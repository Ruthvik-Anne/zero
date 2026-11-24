//! Client protocol skeleton (FND-10): length-prefixed frames, a version, and a
//! JSON projection shared by the Rust and TypeScript readers.
//!
//! Wire form: `u32` big-endian length, then UTF-8 JSON of [`Frame`]. The JSON
//! projection is the same object that appears in `protocol/golden/*.json`.

use crate::error::{ErrorCode, Result, ZeroError};
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameKind {
    Hello,
    Attach,
    Snapshot,
    Event,
    Command,
    Result,
    Approval,
    Action,
    Error,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Frame {
    pub v: u16,
    pub kind: FrameKind,
    pub correlation: String,
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default)]
    pub generation: Option<u64>,
    #[serde(default)]
    pub sequence: Option<u64>,
    pub payload: serde_json::Value,
}

impl Frame {
    pub fn new(kind: FrameKind, correlation: impl Into<String>, payload: serde_json::Value) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            kind,
            correlation: correlation.into(),
            session: None,
            generation: None,
            sequence: None,
            payload,
        }
    }

    pub fn with_session(mut self, session: impl Into<String>) -> Self {
        self.session = Some(session.into());
        self
    }

    pub fn with_cursor(mut self, generation: u64, sequence: u64) -> Self {
        self.generation = Some(generation);
        self.sequence = Some(sequence);
        self
    }

    /// Length-prefixed binary encoding.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let json = serde_json::to_vec(self)?;
        if json.len() > MAX_FRAME_BYTES {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!("frame is {} bytes, limit is {MAX_FRAME_BYTES}", json.len()),
            ));
        }
        let mut out = Vec::with_capacity(4 + json.len());
        out.extend_from_slice(&(json.len() as u32).to_be_bytes());
        out.extend_from_slice(&json);
        Ok(out)
    }

    /// Decode one frame from the front of `buf`; returns the frame and bytes read.
    pub fn decode(buf: &[u8]) -> Result<(Frame, usize)> {
        if buf.len() < 4 {
            return Err(ZeroError::new(ErrorCode::Serialization, "frame shorter than length prefix"));
        }
        let len = u32::from_be_bytes(buf[..4].try_into().expect("4 bytes")) as usize;
        if len > MAX_FRAME_BYTES {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!("declared frame length {len} exceeds {MAX_FRAME_BYTES}"),
            ));
        }
        if buf.len() < 4 + len {
            return Err(ZeroError::new(ErrorCode::Serialization, "truncated frame body"));
        }
        let frame: Frame = serde_json::from_slice(&buf[4..4 + len])?;
        if frame.v != PROTOCOL_VERSION {
            return Err(ZeroError::new(
                ErrorCode::SchemaVersion,
                format!("frame protocol version {} is not {PROTOCOL_VERSION}", frame.v),
            ));
        }
        Ok((frame, 4 + len))
    }
}

/// Decode every frame in a buffer.
pub fn decode_all(buf: &[u8]) -> Result<Vec<Frame>> {
    let mut frames = Vec::new();
    let mut offset = 0;
    while offset < buf.len() {
        let (frame, used) = Frame::decode(&buf[offset..])?;
        frames.push(frame);
        offset += used;
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trip_all_frame_kinds() {
        for kind in [
            FrameKind::Hello,
            FrameKind::Attach,
            FrameKind::Snapshot,
            FrameKind::Event,
            FrameKind::Command,
            FrameKind::Result,
            FrameKind::Approval,
            FrameKind::Action,
            FrameKind::Error,
        ] {
            let frame = Frame::new(kind, "corr-1", json!({"hello":"world"}))
                .with_session("s-1")
                .with_cursor(3, 9);
            let bytes = frame.encode().unwrap();
            let (decoded, used) = Frame::decode(&bytes).unwrap();
            assert_eq!(decoded, frame);
            assert_eq!(used, bytes.len());
        }
    }

    #[test]
    fn truncated_and_oversized_frames_are_rejected() {
        let frame = Frame::new(FrameKind::Event, "c", json!({}));
        let bytes = frame.encode().unwrap();
        assert!(Frame::decode(&bytes[..2]).is_err());
        assert!(Frame::decode(&bytes[..bytes.len() - 1]).is_err());

        let mut huge = Vec::new();
        huge.extend_from_slice(&(MAX_FRAME_BYTES as u32 + 1).to_be_bytes());
        let err = Frame::decode(&huge).unwrap_err();
        assert_eq!(err.code(), ErrorCode::LimitExceeded);
    }

    #[test]
    fn unknown_protocol_version_is_refused() {
        let mut frame = Frame::new(FrameKind::Hello, "c", json!({}));
        frame.v = 99;
        let bytes = frame.encode().unwrap();
        let err = Frame::decode(&bytes).unwrap_err();
        assert_eq!(err.code(), ErrorCode::SchemaVersion);
    }

    #[test]
    fn golden_fixtures_decode_identically() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/golden");
        let mut seen = 0;
        for entry in std::fs::read_dir(&root).expect("protocol/golden must exist") {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("bin") {
                continue;
            }
            let bytes = std::fs::read(&path).unwrap();
            let frames = decode_all(&bytes).unwrap();
            let json_path = path.with_extension("json");
            let expected: Vec<serde_json::Value> =
                serde_json::from_str(&std::fs::read_to_string(&json_path).unwrap()).unwrap();
            assert_eq!(frames.len(), expected.len(), "{}", path.display());
            for (frame, want) in frames.iter().zip(expected) {
                assert_eq!(serde_json::to_value(frame).unwrap(), want, "{}", path.display());
            }
            seen += 1;
        }
        assert!(seen >= 2, "expected golden fixture files");
    }
}
