//! Reliable session stream over datagrams (T-MESH-07, MESH-01, MESH-04,
//! MESH-05).
//!
//! The overlay carries datagrams, not an IP stack. This slice is the small
//! reliable layer the mesh needs above that carrier: a source byte stream is
//! fragmented, each fragment carries a sequence number and a blake3 hash, a
//! bounded window controls how many fragments may be in flight, acks drive
//! retransmission, and the receiver reassembles duplicates and out-of-order
//! arrivals back into the exact original bytes. See
//! `docs/decisions/0002-mesh-transport.md` for why datagram streams were chosen
//! over a userspace TCP/IP stack.
//!
//! The only transport seam is [`DatagramIo`]:
//!
//! ```text
//! send(peer, bytes)          enqueue one datagram for a peer
//! recv() -> Option<(peer, bytes)>   the next inbound datagram, or None
//! ```
//!
//! A WireGuard-style userspace overlay supplies that trait with its real
//! encrypted datagram carrier. This module opens no socket and reads no clock;
//! [`SimulatedNet`] is an in-memory loss/reorder/duplicate harness for tests and
//! for the prototype in [`move_stream`].
//!
//! [`SessionStream`] is the sender side. It is built from the source bytes once,
//! encodes one data frame per fragment, and exposes [`SessionStream::poll`]
//! (which frames may be sent or retransmitted at a round) and
//! [`SessionStream::on_ack`]. [`Reassembler`] is the receiver side. It validates
//! each frame, suppresses duplicates, buffers a bounded amount of out-of-order
//! data, and returns the ack to send. [`move_stream`] wires the two ends
//! together over one [`DatagramIo`] and writes the reassembled stream to a sink.
//!
//! The prototype is deliberately single-process: `move_stream` runs both ends,
//! so the harness can prove the Done criterion — a representative session JSONL
//! stream moves byte-identically under loss, reordering, and duplication —
//! without a network. A production receiver would be the remote endpoint, and a
//! corrupt datagram would normally be dropped and the fragment waited for
//! again rather than failing the stream; that hardening is noted in the ADR.
//!
//! Wire format per datagram:
//!
//! ```text
//! magic "ZMST" (4) | version (1) | kind (1) | stream id (8) |
//! fragment index (4) | total fragments (4) | payload length (2) |
//! payload | blake3 body hash truncated to 16 bytes
//! ```
//!
//! An ack carries the same header with kind `1` and no payload. Integers are
//! big-endian. Every fragment is hashed, so a flipped byte is rejected before it
//! can enter the reassembly buffer.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

/// Wire protocol version carried by every frame.
pub const PROTOCOL_VERSION: u8 = 1;

/// Frame magic, the first four bytes of every datagram.
pub const FRAME_MAGIC: [u8; 4] = *b"ZMST";

/// Bytes of each frame's blake3 body hash that travel on the wire.
pub const HASH_BYTES: usize = 16;

/// Fixed header length: magic, version, kind, stream id, index, total, length.
pub const FRAME_HEADER_BYTES: usize = 4 + 1 + 1 + 8 + 4 + 4 + 2;

/// Default payload bytes per fragment: a conservative overlay datagram size.
pub const DEFAULT_FRAGMENT_BYTES: usize = 512;

/// Largest accepted fragment payload, in bytes.
pub const MAX_FRAGMENT_BYTES: usize = 1200;

/// Default number of unacknowledged fragments allowed in flight.
pub const DEFAULT_WINDOW: usize = 8;

/// Largest accepted send window, in fragments.
pub const MAX_WINDOW: usize = 128;

/// Default out-of-order reassembly slots.
pub const DEFAULT_BUFFERED: usize = 32;

/// Largest accepted out-of-order reassembly buffer, in fragments.
pub const MAX_BUFFERED: usize = 256;

/// Default largest stream this layer will move, in bytes: 4 MiB.
pub const DEFAULT_STREAM_BYTES: usize = 4 * 1024 * 1024;

/// Largest stream this layer will move, in bytes: 8 MiB.
pub const MAX_STREAM_BYTES: usize = 8 * 1024 * 1024;

/// Default largest fragment count for one stream.
pub const DEFAULT_FRAGMENTS: usize = 16_384;

/// Largest fragment count for one stream.
pub const MAX_FRAGMENTS: usize = 16_384;

/// Default retransmissions allowed per fragment.
pub const DEFAULT_RETRANSMITS: u8 = 8;

/// Largest retransmissions allowed per fragment.
pub const MAX_RETRANSMITS: u8 = 16;

/// Default round budget for one transfer.
pub const DEFAULT_ROUNDS: u32 = 10_000;

/// Largest round budget for one transfer.
pub const MAX_ROUNDS: u32 = 50_000;

/// Longest accepted peer id, in bytes.
pub const MAX_PEER_BYTES: usize = 256;

/// Domain separator for the deterministic stream id.
const STREAM_ID_DOMAIN: &[u8] = b"zero.mesh.transport.stream.v1\0";

/// Frame kind for a data fragment.
const KIND_DATA: u8 = 0;

/// Frame kind for an acknowledgement.
const KIND_ACK: u8 = 1;

/// A transport-layer failure.
///
/// These are transport errors, not [`zero_types::ZeroError`]s: a corrupt or
/// oversized datagram, a stream that made no progress inside its budget, and a
/// local read or write failure are all reported here.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StreamError {
    /// A frame failed its structure or hash check, or disagreed with the
    /// stream's established id or fragment count.
    #[error("corrupt stream frame: {0}")]
    Corrupt(String),
    /// A fragment, buffer, stream, or configuration value is above its bound.
    #[error("stream limit exceeded: {0}")]
    Oversized(String),
    /// The stream made no progress inside its retransmission or round budget.
    #[error("stream timed out: {0}")]
    Timeout(String),
    /// A caller-supplied configuration or local input is unusable.
    #[error("invalid stream input: {0}")]
    Invalid(String),
    /// The local reader or writer failed.
    #[error("stream io failed: {0}")]
    Io(String),
}

/// The identity of the peer on the other side of a datagram link.
///
/// It is an opaque label (a device id or an overlay address label), not a
/// network address: the [`DatagramIo`] implementation decides how to route it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PeerId(String);

impl PeerId {
    /// Build a peer id. It must be non-empty and at most [`MAX_PEER_BYTES`].
    pub fn new(value: impl Into<String>) -> Result<Self, StreamError> {
        let value = value.into();
        if value.is_empty() {
            return Err(StreamError::Invalid("a peer id must not be empty".into()));
        }
        if value.len() > MAX_PEER_BYTES {
            return Err(StreamError::Oversized(format!(
                "peer id is {} bytes; the limit is {MAX_PEER_BYTES}",
                value.len()
            )));
        }
        Ok(Self(value))
    }

    /// The label as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for PeerId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// The datagram carrier seam.
///
/// The mesh supplies this trait with a userspace encrypted overlay (the
/// WireGuard-style carrier in MESH-01); the prototype supplies [`SimulatedNet`].
/// The trait deliberately carries bytes and an opaque peer id only: no socket,
/// address, clock, or crypto type leaks into the stream layer.
pub trait DatagramIo {
    /// Send one datagram to `peer`.
    fn send(&mut self, peer: &PeerId, bytes: &[u8]) -> Result<(), StreamError>;

    /// Receive the next datagram, or `None` when the carrier has nothing ready.
    fn recv(&mut self) -> Option<(PeerId, Vec<u8>)>;
}

/// Bounds for one session stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamConfig {
    /// Payload bytes per fragment, at most [`MAX_FRAGMENT_BYTES`].
    pub fragment_bytes: usize,
    /// Unacknowledged fragments allowed in flight, at most [`MAX_WINDOW`].
    pub window: usize,
    /// Out-of-order reassembly slots, at most [`MAX_BUFFERED`].
    pub max_buffered: usize,
    /// Largest source stream, in bytes, at most [`MAX_STREAM_BYTES`].
    pub max_stream_bytes: usize,
    /// Largest fragment count, at most [`MAX_FRAGMENTS`].
    pub max_fragments: usize,
    /// Retransmissions allowed per fragment, at most [`MAX_RETRANSMITS`].
    pub max_retransmits: u8,
    /// Total poll rounds before the transfer times out, at most [`MAX_ROUNDS`].
    pub max_rounds: u32,
    /// Rounds a fragment waits for an ack before it is resent.
    pub retransmit_after_rounds: u32,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            fragment_bytes: DEFAULT_FRAGMENT_BYTES,
            window: DEFAULT_WINDOW,
            max_buffered: DEFAULT_BUFFERED,
            max_stream_bytes: DEFAULT_STREAM_BYTES,
            max_fragments: DEFAULT_FRAGMENTS,
            max_retransmits: DEFAULT_RETRANSMITS,
            max_rounds: DEFAULT_ROUNDS,
            retransmit_after_rounds: 2,
        }
    }
}

impl StreamConfig {
    /// Refuse a configuration the sender or receiver cannot honour.
    ///
    /// A zero or nonsensical value is [`StreamError::Invalid`]; a value above a
    /// ceiling is [`StreamError::Oversized`]. A retransmit wait longer than the
    /// whole round budget is invalid, because no retransmission could happen.
    pub fn validate(&self) -> Result<(), StreamError> {
        bounded("fragment_bytes", self.fragment_bytes, 1, MAX_FRAGMENT_BYTES)?;
        bounded("window", self.window, 1, MAX_WINDOW)?;
        bounded("max_buffered", self.max_buffered, 1, MAX_BUFFERED)?;
        bounded(
            "max_stream_bytes",
            self.max_stream_bytes,
            1,
            MAX_STREAM_BYTES,
        )?;
        bounded("max_fragments", self.max_fragments, 1, MAX_FRAGMENTS)?;
        bounded(
            "max_retransmits",
            usize::from(self.max_retransmits),
            1,
            usize::from(MAX_RETRANSMITS),
        )?;
        bounded(
            "max_rounds",
            self.max_rounds as usize,
            1,
            MAX_ROUNDS as usize,
        )?;
        bounded(
            "retransmit_after_rounds",
            self.retransmit_after_rounds as usize,
            1,
            self.max_rounds as usize,
        )?;
        Ok(())
    }
}

fn bounded(name: &str, value: usize, min: usize, max: usize) -> Result<(), StreamError> {
    if value < min {
        return Err(StreamError::Invalid(format!(
            "{name} is {value}; it must be at least {min}"
        )));
    }
    if value > max {
        return Err(StreamError::Oversized(format!(
            "{name} is {value}; the limit is {max}"
        )));
    }
    Ok(())
}

/// What one transfer moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferStats {
    /// Reassembled stream length in bytes; equals the source length.
    pub bytes: usize,
    /// Number of fragments the source was split into.
    pub fragments: usize,
    /// Retransmissions the sender performed.
    pub retransmits: u32,
    /// Unique fragments the receiver accepted out of order.
    pub reordered: u32,
}

/// The sender half of one session stream.
///
/// The source is fragmented and encoded once. [`Self::poll`] returns the frames
/// that may be sent in a round: first sends fill the window in fragment order,
/// and any unacknowledged fragment whose retransmit wait has elapsed is resent
/// while it has retransmissions left. [`Self::on_ack`] retires a fragment and
/// frees its window slot.
#[derive(Debug, Clone)]
pub struct SessionStream {
    stream_id: u64,
    total: u32,
    bytes: usize,
    config: StreamConfig,
    frames: Vec<Vec<u8>>,
    state: Vec<FragmentState>,
    acked_count: usize,
    in_flight_count: usize,
    retransmits: u32,
}

#[derive(Debug, Clone, Copy)]
struct FragmentState {
    acked: bool,
    in_flight: bool,
    attempts: u8,
    due_round: u32,
}

impl SessionStream {
    /// Fragment `source` into an encoded stream identified by `stream_id`.
    ///
    /// The whole source is bounded by [`StreamConfig::max_stream_bytes`], and
    /// the resulting fragment count by [`StreamConfig::max_fragments`]. An empty
    /// source is a complete stream with zero fragments.
    pub fn new(stream_id: u64, source: &[u8], config: &StreamConfig) -> Result<Self, StreamError> {
        config.validate()?;
        if source.len() > config.max_stream_bytes {
            return Err(StreamError::Oversized(format!(
                "source is {} bytes; this stream moves at most {}",
                source.len(),
                config.max_stream_bytes
            )));
        }

        let fragment_count = source.len().div_ceil(config.fragment_bytes);
        if fragment_count > config.max_fragments {
            return Err(StreamError::Oversized(format!(
                "source needs {fragment_count} fragments; the limit is {}",
                config.max_fragments
            )));
        }
        let total = u32::try_from(fragment_count).map_err(|_| {
            StreamError::Oversized("fragment count does not fit the wire header".to_string())
        })?;

        let frames = source
            .chunks(config.fragment_bytes)
            .enumerate()
            .map(|(index, payload)| encode_data(stream_id, index as u32, total, payload))
            .collect::<Vec<_>>();

        Ok(Self {
            stream_id,
            total,
            bytes: source.len(),
            config: *config,
            state: vec![
                FragmentState {
                    acked: false,
                    in_flight: false,
                    attempts: 0,
                    due_round: 0,
                };
                frames.len()
            ],
            frames,
            acked_count: 0,
            in_flight_count: 0,
            retransmits: 0,
        })
    }

    /// The stream id carried by every frame.
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// Fragment count for this stream.
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// Source length in bytes.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Fragments acknowledged so far.
    pub fn acked_fragments(&self) -> usize {
        self.acked_count
    }

    /// Fragments currently in flight.
    pub fn in_flight(&self) -> usize {
        self.in_flight_count
    }

    /// Retransmissions performed so far.
    pub fn retransmits(&self) -> u32 {
        self.retransmits
    }

    /// True when every fragment has been acknowledged.
    pub fn is_complete(&self) -> bool {
        self.acked_count == self.total as usize
    }

    /// True when every outstanding fragment has spent its retransmission
    /// budget and its last wait has elapsed, so no further progress is possible.
    pub fn is_stalled(&self, round: u32) -> bool {
        !self.is_complete()
            && self.state.iter().all(|state| {
                state.acked
                    || (state.attempts >= self.config.max_retransmits && state.due_round <= round)
            })
    }

    /// The frames to send or resend in `round`.
    ///
    /// New fragments are sent only while fewer than [`StreamConfig::window`]
    /// fragments are in flight. A retransmission does not consume another slot.
    pub fn poll(&mut self, round: u32) -> Vec<Vec<u8>> {
        let after = self.config.retransmit_after_rounds;
        let max_attempts = self.config.max_retransmits;
        let window = self.config.window;
        let mut out = Vec::new();

        for (index, state) in self.state.iter_mut().enumerate() {
            if state.acked {
                continue;
            }
            if state.in_flight {
                if state.due_round <= round && state.attempts < max_attempts {
                    state.attempts += 1;
                    state.due_round = round.saturating_add(after);
                    self.retransmits += 1;
                    out.push(self.frames[index].clone());
                }
            } else if self.in_flight_count < window {
                state.in_flight = true;
                state.due_round = round.saturating_add(after);
                self.in_flight_count += 1;
                out.push(self.frames[index].clone());
            }
        }

        out
    }

    /// Retire fragment `index` after an ack.
    ///
    /// Returns `true` when the ack moved a fragment from unacknowledged to
    /// acknowledged. A duplicate ack, or an index outside the stream, is
    /// `false` and changes nothing.
    pub fn on_ack(&mut self, index: u32) -> bool {
        let Some(state) = self.state.get_mut(index as usize) else {
            return false;
        };
        if state.acked {
            return false;
        }
        state.acked = true;
        if state.in_flight {
            state.in_flight = false;
            self.in_flight_count -= 1;
        }
        self.acked_count += 1;
        true
    }
}

/// The receiver half of one session stream.
///
/// Every accepted fragment yields the ack datagram to return. A duplicate is
/// acked again without being appended; an out-of-order fragment is buffered
/// within [`StreamConfig::max_buffered`] slots and drained as soon as the gap
/// closes.
#[derive(Debug, Clone)]
pub struct Reassembler {
    stream_id: u64,
    total: u32,
    config: StreamConfig,
    next: u32,
    out: Vec<u8>,
    pending: BTreeMap<u32, Vec<u8>>,
    buffered_bytes: usize,
    received: u32,
    reordered: u32,
    duplicates: u32,
}

impl Reassembler {
    /// Prepare to reassemble a stream of `total` fragments.
    ///
    /// The count is bounded by [`StreamConfig::max_fragments`]. A zero count is
    /// an empty stream and is complete immediately.
    pub fn new(stream_id: u64, total: u32, config: &StreamConfig) -> Result<Self, StreamError> {
        config.validate()?;
        if total as usize > config.max_fragments {
            return Err(StreamError::Oversized(format!(
                "stream declares {total} fragments; the limit is {}",
                config.max_fragments
            )));
        }
        Ok(Self {
            stream_id,
            total,
            config: *config,
            next: 0,
            out: Vec::new(),
            pending: BTreeMap::new(),
            buffered_bytes: 0,
            received: 0,
            reordered: 0,
            duplicates: 0,
        })
    }

    /// The stream id this receiver accepts.
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// The declared fragment count.
    pub fn total_fragments(&self) -> u32 {
        self.total
    }

    /// The next fragment index the contiguous prefix expects.
    pub fn next_expected(&self) -> u32 {
        self.next
    }

    /// Unique fragments accepted so far.
    pub fn received_fragments(&self) -> u32 {
        self.received
    }

    /// Unique fragments accepted ahead of the contiguous prefix.
    pub fn reordered(&self) -> u32 {
        self.reordered
    }

    /// Duplicate fragments suppressed.
    pub fn duplicates(&self) -> u32 {
        self.duplicates
    }

    /// Out-of-order fragments currently buffered.
    pub fn buffered(&self) -> usize {
        self.pending.len()
    }

    /// True when the contiguous prefix covers the whole declared stream.
    pub fn is_complete(&self) -> bool {
        self.next == self.total
    }

    /// Decode one inbound datagram and accept it when it is a data frame.
    ///
    /// Returns `Some(ack)` for a data frame and `None` for an ack frame. A
    /// corrupt or oversized datagram is [`StreamError::Corrupt`] or
    /// [`StreamError::Oversized`].
    pub fn accept_datagram(&mut self, bytes: &[u8]) -> Result<Option<Vec<u8>>, StreamError> {
        let frame = decode_frame(bytes, self.config.fragment_bytes)?;
        match &frame {
            Frame::Data { .. } => Ok(Some(self.accept(&frame)?)),
            Frame::Ack { .. } => Ok(None),
        }
    }

    /// Consume the stream once every fragment has arrived.
    ///
    /// An incomplete stream is [`StreamError::Corrupt`]: the caller must not
    /// treat a missing fragment as the end of the stream.
    pub fn finish(self) -> Result<Vec<u8>, StreamError> {
        if !self.is_complete() {
            return Err(StreamError::Corrupt(format!(
                "stream reassembled {} of {} fragments",
                self.next, self.total
            )));
        }
        Ok(self.out)
    }

    fn accept(&mut self, frame: &Frame) -> Result<Vec<u8>, StreamError> {
        let Frame::Data {
            stream_id,
            index,
            total,
            payload,
        } = frame
        else {
            return Err(StreamError::Corrupt(
                "an acknowledgement was offered to the reassembler".into(),
            ));
        };

        if *stream_id != self.stream_id {
            return Err(StreamError::Corrupt(format!(
                "frame is for stream {:016x}; this receiver holds {:016x}",
                stream_id, self.stream_id
            )));
        }
        if *total != self.total {
            return Err(StreamError::Corrupt(format!(
                "frame declares {total} fragments; this stream has {}",
                self.total
            )));
        }
        if *index >= self.total {
            return Err(StreamError::Corrupt(format!(
                "fragment index {index} is outside a {}-fragment stream",
                self.total
            )));
        }
        if payload.is_empty() {
            return Err(StreamError::Corrupt(format!(
                "fragment {index} carries no payload"
            )));
        }
        if payload.len() > self.config.fragment_bytes {
            return Err(StreamError::Oversized(format!(
                "fragment {index} is {} bytes; the configured fragment size is {}",
                payload.len(),
                self.config.fragment_bytes
            )));
        }

        let ack = encode_ack(self.stream_id, *index, self.total);

        if *index < self.next || self.pending.contains_key(index) {
            self.duplicates += 1;
            return Ok(ack);
        }

        if *index != self.next {
            if self.pending.len() >= self.config.max_buffered {
                return Err(StreamError::Oversized(format!(
                    "reassembly buffer already holds {} fragments; the limit is {}",
                    self.pending.len(),
                    self.config.max_buffered
                )));
            }
            if self.out.len() + self.buffered_bytes + payload.len() > self.config.max_stream_bytes {
                return Err(StreamError::Oversized(format!(
                    "reassembly would exceed the {} byte stream limit",
                    self.config.max_stream_bytes
                )));
            }
            self.pending.insert(*index, payload.clone());
            self.buffered_bytes += payload.len();
            self.reordered += 1;
            return Ok(ack);
        }

        if self.out.len() + self.buffered_bytes + payload.len() > self.config.max_stream_bytes {
            return Err(StreamError::Oversized(format!(
                "reassembly would exceed the {} byte stream limit",
                self.config.max_stream_bytes
            )));
        }
        self.out.extend_from_slice(payload);
        self.next += 1;
        self.received += 1;

        loop {
            let next = self.next;
            let Some(payload) = self.pending.remove(&next) else {
                break;
            };
            self.buffered_bytes -= payload.len();
            self.out.extend_from_slice(&payload);
            self.next += 1;
            self.received += 1;
        }

        Ok(ack)
    }
}

/// Move a byte stream across the overlay and write it to `dest`.
///
/// The source is read once, bounded by [`StreamConfig::max_stream_bytes`],
/// fragmented, and sent through `io` to `peer`. The frames the receiver
/// acknowledges are retired; unacknowledged frames are retransmitted after
/// [`StreamConfig::retransmit_after_rounds`] until
/// [`StreamConfig::max_retransmits`] is spent. The reassembled bytes are checked
/// against the source before anything is written, so `dest` either receives the
/// exact original stream or nothing.
///
/// This is the T-MESH-07 prototype: both endpoints run in this call and the
/// [`DatagramIo`] is the simulated overlay between them. A real carrier runs
/// [`SessionStream`] and [`Reassembler`] on the two hosts instead.
pub fn move_stream(
    source: &mut dyn Read,
    dest: &mut dyn Write,
    io: &mut dyn DatagramIo,
    peer: &PeerId,
    config: &StreamConfig,
) -> Result<TransferStats, StreamError> {
    config.validate()?;

    let mut data = Vec::new();
    let limit = config.max_stream_bytes as u64 + 1;
    source
        .take(limit)
        .read_to_end(&mut data)
        .map_err(|error| StreamError::Io(format!("cannot read the source stream: {error}")))?;
    if data.len() > config.max_stream_bytes {
        return Err(StreamError::Oversized(format!(
            "source is longer than the {} byte stream limit",
            config.max_stream_bytes
        )));
    }

    let stream_id = stream_id_for(&data);
    let mut sender = SessionStream::new(stream_id, &data, config)?;
    let mut receiver = Reassembler::new(stream_id, sender.frame_count() as u32, config)?;
    let mut round = 0u32;

    loop {
        for datagram in sender.poll(round) {
            io.send(peer, &datagram)?;
        }

        while let Some((_from, datagram)) = io.recv() {
            let frame = decode_frame(&datagram, config.fragment_bytes)?;
            match &frame {
                Frame::Data { .. } => {
                    let ack = receiver.accept(&frame)?;
                    io.send(peer, &ack)?;
                }
                Frame::Ack { stream_id, index } => {
                    if *stream_id == sender.stream_id() {
                        sender.on_ack(*index);
                    }
                }
            }
        }

        if sender.is_complete() {
            let reordered = receiver.reordered();
            let reassembled = receiver.finish()?;
            if reassembled != data {
                return Err(StreamError::Corrupt(
                    "reassembled stream differs from the source stream".into(),
                ));
            }
            dest.write_all(&reassembled).map_err(|error| {
                StreamError::Io(format!("cannot write the reassembled stream: {error}"))
            })?;
            dest.flush().map_err(|error| {
                StreamError::Io(format!("cannot flush the reassembled stream: {error}"))
            })?;
            return Ok(TransferStats {
                bytes: reassembled.len(),
                fragments: sender.frame_count(),
                retransmits: sender.retransmits(),
                reordered,
            });
        }

        if sender.is_stalled(round) || round >= config.max_rounds {
            return Err(StreamError::Timeout(format!(
                "stream {stream_id:016x} stalled after {round} round(s) with {} of {} fragments acknowledged",
                sender.acked_fragments(),
                sender.frame_count()
            )));
        }
        round += 1;
    }
}

/// A deterministic in-memory [`DatagramIo`] for tests and the prototype.
///
/// Every `send` is scheduled for a later `recv` (the harness is a loopback bus
/// standing in for the whole overlay path). Three knobs make the carrier behave
/// badly without a random source:
///
/// - [`Self::with_loss_every`] drops every *n*th datagram;
/// - [`Self::with_reorder_every`] holds every *n*th datagram for a number of
///   receive ticks, so later datagrams overtake it;
/// - [`Self::with_duplicate_every`] delivers every *n*th datagram twice.
///
/// The patterns are deterministic, so a test either always passes or always
/// fails; counters expose what the harness did.
#[derive(Debug, Clone, Default)]
pub struct SimulatedNet {
    queue: Vec<Scheduled>,
    clock: u64,
    sends: u64,
    delivered: u64,
    dropped: u64,
    held: u64,
    duplicated: u64,
    drop_every: u32,
    reorder_every: u32,
    reorder_delay: u64,
    duplicate_every: u32,
}

#[derive(Debug, Clone)]
struct Scheduled {
    deliver_at: u64,
    peer: PeerId,
    bytes: Vec<u8>,
}

impl SimulatedNet {
    /// A carrier that delivers everything in order.
    pub fn lossless() -> Self {
        Self::default()
    }

    /// Drop every `every`th datagram. `0` disables loss.
    pub fn with_loss_every(mut self, every: u32) -> Self {
        self.drop_every = every;
        self
    }

    /// Hold every `every`th datagram for `delay` receive ticks. `0` disables
    /// reordering.
    pub fn with_reorder_every(mut self, every: u32, delay: u64) -> Self {
        self.reorder_every = every;
        self.reorder_delay = delay;
        self
    }

    /// Deliver every `every`th datagram twice. `0` disables duplication.
    pub fn with_duplicate_every(mut self, every: u32) -> Self {
        self.duplicate_every = every;
        self
    }

    /// Datagrams offered to the carrier.
    pub fn sends(&self) -> u64 {
        self.sends
    }

    /// Datagrams delivered to `recv`.
    pub fn delivered(&self) -> u64 {
        self.delivered
    }

    /// Datagrams dropped by the loss pattern.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Datagrams delayed by the reorder pattern.
    pub fn held(&self) -> u64 {
        self.held
    }

    /// Extra copies delivered by the duplication pattern.
    pub fn duplicated(&self) -> u64 {
        self.duplicated
    }

    /// Datagrams still scheduled.
    pub fn queued(&self) -> usize {
        self.queue.len()
    }
}

impl DatagramIo for SimulatedNet {
    fn send(&mut self, peer: &PeerId, bytes: &[u8]) -> Result<(), StreamError> {
        self.sends += 1;

        if self.drop_every != 0 && self.sends.is_multiple_of(u64::from(self.drop_every)) {
            self.dropped += 1;
            return Ok(());
        }

        let mut deliver_at = self.clock;
        if self.reorder_every != 0 && self.sends.is_multiple_of(u64::from(self.reorder_every)) {
            deliver_at = deliver_at.saturating_add(self.reorder_delay);
            self.held += 1;
        }

        self.queue.push(Scheduled {
            deliver_at,
            peer: peer.clone(),
            bytes: bytes.to_vec(),
        });

        if self.duplicate_every != 0 && self.sends.is_multiple_of(u64::from(self.duplicate_every)) {
            self.queue.push(Scheduled {
                deliver_at: deliver_at.saturating_add(1),
                peer: peer.clone(),
                bytes: bytes.to_vec(),
            });
            self.duplicated += 1;
        }

        Ok(())
    }

    fn recv(&mut self) -> Option<(PeerId, Vec<u8>)> {
        self.clock = self.clock.saturating_add(1);
        // Deliver the earliest eligible datagram, not merely the first one in
        // insertion order: a held datagram must let later ones overtake it.
        let position = self
            .queue
            .iter()
            .enumerate()
            .filter(|(_, scheduled)| scheduled.deliver_at <= self.clock)
            .min_by_key(|(_, scheduled)| scheduled.deliver_at)
            .map(|(position, _)| position)?;
        let scheduled = self.queue.remove(position);
        self.delivered += 1;
        Some((scheduled.peer, scheduled.bytes))
    }
}

/// The wire frame. It is private: callers use [`SessionStream`],
/// [`Reassembler`], and [`move_stream`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Frame {
    Data {
        stream_id: u64,
        index: u32,
        total: u32,
        payload: Vec<u8>,
    },
    Ack {
        stream_id: u64,
        index: u32,
    },
}

fn encode_data(stream_id: u64, index: u32, total: u32, payload: &[u8]) -> Vec<u8> {
    encode_frame(KIND_DATA, stream_id, index, total, payload)
}

fn encode_ack(stream_id: u64, index: u32, total: u32) -> Vec<u8> {
    encode_frame(KIND_ACK, stream_id, index, total, &[])
}

fn encode_frame(kind: u8, stream_id: u64, index: u32, total: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len() + HASH_BYTES);
    out.extend_from_slice(&FRAME_MAGIC);
    out.push(PROTOCOL_VERSION);
    out.push(kind);
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    let hash = blake3::hash(&out);
    out.extend_from_slice(&hash.as_bytes()[..HASH_BYTES]);
    out
}

fn decode_frame(bytes: &[u8], max_payload: usize) -> Result<Frame, StreamError> {
    if bytes.len() < FRAME_HEADER_BYTES + HASH_BYTES {
        return Err(corrupt("frame is shorter than its header and hash"));
    }
    if bytes[..4] != FRAME_MAGIC {
        return Err(corrupt("frame magic is wrong"));
    }
    if bytes[4] != PROTOCOL_VERSION {
        return Err(corrupt(format!(
            "frame version {} is not {PROTOCOL_VERSION}",
            bytes[4]
        )));
    }
    let kind = bytes[5];
    let stream_id = u64::from_be_bytes(
        bytes[6..14]
            .try_into()
            .expect("the frame header holds a stream id"),
    );
    let index = u32::from_be_bytes(
        bytes[14..18]
            .try_into()
            .expect("the frame header holds a fragment index"),
    );
    let total = u32::from_be_bytes(
        bytes[18..22]
            .try_into()
            .expect("the frame header holds a fragment count"),
    );
    let payload_len = usize::from(u16::from_be_bytes([bytes[22], bytes[23]]));

    if payload_len > max_payload || payload_len > MAX_FRAGMENT_BYTES {
        return Err(StreamError::Oversized(format!(
            "frame declares a {payload_len} byte payload; the limit is {}",
            max_payload.min(MAX_FRAGMENT_BYTES)
        )));
    }
    let expected_len = FRAME_HEADER_BYTES + payload_len + HASH_BYTES;
    if bytes.len() != expected_len {
        return Err(corrupt(format!(
            "frame is {} bytes but its header describes {expected_len}",
            bytes.len()
        )));
    }

    let (body, provided) = bytes.split_at(expected_len - HASH_BYTES);
    let hash = blake3::hash(body);
    if provided != &hash.as_bytes()[..HASH_BYTES] {
        return Err(corrupt("frame hash does not match its body"));
    }

    if total == 0 || index >= total {
        return Err(corrupt(format!(
            "fragment index {index} is outside a {total}-fragment stream"
        )));
    }

    match kind {
        KIND_DATA => {
            if payload_len == 0 {
                return Err(corrupt("a data frame carries no payload"));
            }
            Ok(Frame::Data {
                stream_id,
                index,
                total,
                payload: bytes[FRAME_HEADER_BYTES..FRAME_HEADER_BYTES + payload_len].to_vec(),
            })
        }
        KIND_ACK => {
            if payload_len != 0 {
                return Err(corrupt("an ack frame carries a payload"));
            }
            Ok(Frame::Ack { stream_id, index })
        }
        other => Err(corrupt(format!("unknown frame kind {other}"))),
    }
}

/// Derive the deterministic stream id for a source stream.
fn stream_id_for(data: &[u8]) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(STREAM_ID_DOMAIN);
    hasher.update(data);
    let hash = hasher.finalize();
    let mut id = [0u8; 8];
    id.copy_from_slice(&hash.as_bytes()[..8]);
    u64::from_be_bytes(id)
}

fn corrupt(message: impl Into<String>) -> StreamError {
    StreamError::Corrupt(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn peer() -> PeerId {
        PeerId::new("peer-a").expect("peer id")
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|index| (index % 251) as u8).collect()
    }

    fn session_jsonl(events: usize) -> Vec<u8> {
        let mut out = String::new();
        for seq in 0..events {
            let role = if seq % 2 == 0 { "user" } else { "assistant" };
            out.push_str(&format!(
                "{{\"seq\":{seq},\"kind\":\"event\",\"role\":\"{role}\",\"text\":\"turn {seq}: a representative session line with enough text to span several fragments\"}}\n"
            ));
        }
        out.into_bytes()
    }

    fn receive(
        data: &[u8],
        io: &mut dyn DatagramIo,
        config: &StreamConfig,
    ) -> Result<(Vec<u8>, TransferStats), StreamError> {
        let mut source = Cursor::new(data.to_vec());
        let mut dest = Vec::new();
        let stats = move_stream(&mut source, &mut dest, io, &peer(), config)?;
        Ok((dest, stats))
    }

    #[test]
    fn data_and_ack_frames_round_trip() {
        let data = Frame::Data {
            stream_id: 9,
            index: 1,
            total: 3,
            payload: b"slice".to_vec(),
        };
        let encoded = encode_data(9, 1, 3, b"slice");
        assert_eq!(decode_frame(&encoded, MAX_FRAGMENT_BYTES), Ok(data));

        let ack = encode_ack(9, 1, 3);
        assert_eq!(
            decode_frame(&ack, MAX_FRAGMENT_BYTES),
            Ok(Frame::Ack {
                stream_id: 9,
                index: 1
            })
        );
    }

    #[test]
    fn corrupt_frames_are_rejected() {
        let encoded = encode_data(4, 0, 2, b"payload");

        let mut flipped = encoded.clone();
        let last_payload = flipped.len() - HASH_BYTES - 1;
        flipped[last_payload] ^= 0xff;
        assert!(matches!(
            decode_frame(&flipped, MAX_FRAGMENT_BYTES),
            Err(StreamError::Corrupt(_))
        ));

        let mut magic = encoded.clone();
        magic[0] ^= 0xff;
        assert!(matches!(
            decode_frame(&magic, MAX_FRAGMENT_BYTES),
            Err(StreamError::Corrupt(_))
        ));

        let mut kind = encoded.clone();
        kind[5] = 9;
        assert!(matches!(
            decode_frame(&kind, MAX_FRAGMENT_BYTES),
            Err(StreamError::Corrupt(_))
        ));

        let mut truncated = encoded.clone();
        truncated.pop();
        assert!(matches!(
            decode_frame(&truncated, MAX_FRAGMENT_BYTES),
            Err(StreamError::Corrupt(_))
        ));

        assert!(matches!(
            decode_frame(&encoded, 2),
            Err(StreamError::Oversized(_))
        ));

        let mut index_outside = encode_data(4, 2, 2, b"payload");
        // Recompute the hash so the only fault is the out-of-range index.
        let body_len = index_outside.len() - HASH_BYTES;
        let hash = blake3::hash(&index_outside[..body_len]);
        index_outside.truncate(body_len);
        index_outside.extend_from_slice(&hash.as_bytes()[..HASH_BYTES]);
        assert!(matches!(
            decode_frame(&index_outside, MAX_FRAGMENT_BYTES),
            Err(StreamError::Corrupt(_))
        ));
    }

    #[test]
    fn fragmentation_and_reassembly_are_exact_without_loss() {
        let data = pattern(2048);
        let mut io = SimulatedNet::lossless();
        let (moved, stats) =
            receive(&data, &mut io, &StreamConfig::default()).expect("a clean carrier moves data");

        assert_eq!(moved, data);
        assert_eq!(stats.bytes, data.len());
        assert_eq!(stats.fragments, data.len().div_ceil(DEFAULT_FRAGMENT_BYTES));
        assert_eq!(stats.retransmits, 0);
        assert_eq!(stats.reordered, 0);
        assert_eq!(io.dropped(), 0);
        assert_eq!(io.held(), 0);
    }

    #[test]
    fn loss_is_repaired_by_retransmission() {
        let data = pattern(3000);
        let mut io = SimulatedNet::lossless().with_loss_every(3);
        let (moved, stats) =
            receive(&data, &mut io, &StreamConfig::default()).expect("retransmission repairs loss");

        assert_eq!(moved, data);
        assert!(stats.retransmits > 0, "{stats:?}");
        assert!(io.dropped() > 0);
    }

    #[test]
    fn reordered_fragments_are_buffered_and_ordered() {
        let data = pattern(2500);
        let mut io = SimulatedNet::lossless().with_reorder_every(2, 2);
        let (moved, stats) =
            receive(&data, &mut io, &StreamConfig::default()).expect("reordering is buffered");

        assert_eq!(moved, data);
        assert!(stats.reordered > 0, "{stats:?}");
        assert!(io.held() > 0);
    }

    #[test]
    fn duplicate_fragments_are_suppressed() {
        let config = StreamConfig {
            fragment_bytes: 4,
            ..StreamConfig::default()
        };
        let source = b"abcdefgh";
        let mut sender = SessionStream::new(5, source, &config).expect("stream");
        let frames = sender.poll(0);
        assert_eq!(frames.len(), 2);

        let mut receiver = Reassembler::new(5, 2, &config).expect("reassembler");
        let first = receiver
            .accept_datagram(&frames[0])
            .expect("first fragment")
            .expect("a data frame yields an ack");
        assert!(!first.is_empty());
        assert_eq!(receiver.received_fragments(), 1);

        let duplicate = receiver
            .accept_datagram(&frames[0])
            .expect("duplicate is acked")
            .expect("a data frame yields an ack");
        assert_eq!(duplicate, first, "the duplicate is acked again");
        assert_eq!(receiver.received_fragments(), 1, "not appended twice");
        assert_eq!(receiver.duplicates(), 1);

        receiver.accept_datagram(&frames[1]).expect("second");
        assert_eq!(receiver.finish().expect("complete"), source);

        // The whole prototype also survives a carrier that duplicates datagrams.
        let data = pattern(1800);
        let mut io = SimulatedNet::lossless().with_duplicate_every(2);
        let (moved, _) =
            receive(&data, &mut io, &StreamConfig::default()).expect("duplicates are harmless");
        assert_eq!(moved, data);
        assert!(io.duplicated() > 0);
    }

    /// A carrier that flips one byte of the first data datagram it carries.
    struct CorruptingIo {
        inner: SimulatedNet,
        corrupted: bool,
    }

    impl DatagramIo for CorruptingIo {
        fn send(&mut self, peer: &PeerId, bytes: &[u8]) -> Result<(), StreamError> {
            if !self.corrupted && bytes[5] == KIND_DATA {
                self.corrupted = true;
                let mut flipped = bytes.to_vec();
                let at = flipped.len() - HASH_BYTES - 1;
                flipped[at] ^= 0xff;
                return self.inner.send(peer, &flipped);
            }
            self.inner.send(peer, bytes)
        }

        fn recv(&mut self) -> Option<(PeerId, Vec<u8>)> {
            self.inner.recv()
        }
    }

    #[test]
    fn a_corrupt_datagram_fails_the_stream() {
        let data = pattern(1500);
        let mut io = CorruptingIo {
            inner: SimulatedNet::lossless(),
            corrupted: false,
        };
        let mut source = Cursor::new(data);
        let mut dest = Vec::new();
        let error = move_stream(
            &mut source,
            &mut dest,
            &mut io,
            &peer(),
            &StreamConfig::default(),
        )
        .expect_err("a corrupt fragment is rejected");
        assert!(matches!(error, StreamError::Corrupt(_)), "{error:?}");
        assert!(dest.is_empty(), "nothing is written for a failed stream");
    }

    #[test]
    fn oversized_streams_fragments_and_configs_are_rejected() {
        let defaults = StreamConfig::default();

        assert!(matches!(
            StreamConfig {
                fragment_bytes: 0,
                ..defaults
            }
            .validate(),
            Err(StreamError::Invalid(_))
        ));
        assert!(matches!(
            StreamConfig {
                fragment_bytes: MAX_FRAGMENT_BYTES + 1,
                ..defaults
            }
            .validate(),
            Err(StreamError::Oversized(_))
        ));
        assert!(matches!(
            StreamConfig {
                window: 0,
                ..defaults
            }
            .validate(),
            Err(StreamError::Invalid(_))
        ));
        assert!(matches!(
            StreamConfig {
                max_buffered: 0,
                ..defaults
            }
            .validate(),
            Err(StreamError::Invalid(_))
        ));
        assert!(matches!(
            StreamConfig {
                max_retransmits: 0,
                ..defaults
            }
            .validate(),
            Err(StreamError::Invalid(_))
        ));
        assert!(matches!(
            StreamConfig {
                max_rounds: 0,
                ..defaults
            }
            .validate(),
            Err(StreamError::Invalid(_))
        ));

        let too_many_bytes = StreamConfig {
            max_stream_bytes: 8,
            ..defaults
        };
        assert!(matches!(
            SessionStream::new(1, &[0u8; 9], &too_many_bytes),
            Err(StreamError::Oversized(_))
        ));
        assert!(matches!(
            receive(&[0u8; 9], &mut SimulatedNet::lossless(), &too_many_bytes),
            Err(StreamError::Oversized(_))
        ));

        let too_many_fragments = StreamConfig {
            fragment_bytes: 4,
            max_fragments: 1,
            ..defaults
        };
        assert!(matches!(
            SessionStream::new(1, b"12345", &too_many_fragments),
            Err(StreamError::Oversized(_))
        ));
        assert!(matches!(
            Reassembler::new(1, 2, &too_many_fragments),
            Err(StreamError::Oversized(_))
        ));
    }

    #[test]
    fn the_reassembly_buffer_is_bounded() {
        let config = StreamConfig {
            fragment_bytes: 4,
            max_buffered: 1,
            ..StreamConfig::default()
        };
        let mut receiver = Reassembler::new(1, 3, &config).expect("reassembler");

        receiver
            .accept_datagram(&encode_data(1, 1, 3, b"bbbb"))
            .expect("one fragment may wait");
        assert_eq!(receiver.buffered(), 1);

        let error = receiver
            .accept_datagram(&encode_data(1, 2, 3, b"cccc"))
            .expect_err("the second out-of-order fragment exceeds the buffer");
        assert!(matches!(error, StreamError::Oversized(_)), "{error:?}");
        assert_eq!(receiver.buffered(), 1);
    }

    #[test]
    fn a_stalled_stream_times_out() {
        let config = StreamConfig {
            max_retransmits: 1,
            max_rounds: 1_000,
            retransmit_after_rounds: 1,
            ..StreamConfig::default()
        };
        let mut io = SimulatedNet::lossless().with_loss_every(1);
        let mut source = Cursor::new(pattern(600));
        let mut dest = Vec::new();

        let error = move_stream(&mut source, &mut dest, &mut io, &peer(), &config)
            .expect_err("no datagram is ever delivered");
        assert!(matches!(error, StreamError::Timeout(_)), "{error:?}");
        assert!(dest.is_empty());
        assert!(io.dropped() > 0);
    }

    #[test]
    fn the_send_window_is_bounded() {
        let config = StreamConfig {
            fragment_bytes: 4,
            window: 3,
            ..StreamConfig::default()
        };
        let mut sender = SessionStream::new(7, b"0123456789abcdef", &config).expect("stream");
        assert_eq!(sender.frame_count(), 4);

        let first = sender.poll(0);
        assert_eq!(first.len(), 3, "only the window may be in flight");
        assert_eq!(sender.in_flight(), 3);
        assert!(sender.poll(0).is_empty(), "nothing is due again yet");

        assert!(sender.on_ack(0));
        assert!(!sender.on_ack(0), "a duplicate ack changes nothing");
        let next = sender.poll(0);
        assert_eq!(next.len(), 1, "an ack frees exactly one slot");
        assert_eq!(sender.in_flight(), 3);

        assert!(sender.on_ack(1));
        assert!(sender.on_ack(2));
        assert!(sender.on_ack(3));
        assert!(sender.is_complete());
        assert!(sender.poll(1).is_empty());
    }

    #[test]
    fn a_session_jsonl_stream_moves_byte_identically() {
        // The Done criterion: a representative session stream crosses a carrier
        // that loses, reorders, and duplicates datagrams, and the receiver
        // writes exactly the source bytes.
        let data = session_jsonl(160);
        assert!(data.len() > 16_000);
        let mut io = SimulatedNet::lossless()
            .with_loss_every(5)
            .with_reorder_every(4, 2)
            .with_duplicate_every(7);
        let (moved, stats) =
            receive(&data, &mut io, &StreamConfig::default()).expect("the session stream crosses");

        assert_eq!(moved, data, "the reassembled stream is byte-identical");
        assert_eq!(stats.bytes, data.len());
        assert_eq!(stats.fragments, data.len().div_ceil(DEFAULT_FRAGMENT_BYTES));
        assert!(stats.fragments > 20);
        assert!(stats.retransmits > 0, "{stats:?}");
        assert!(stats.reordered > 0, "{stats:?}");
        assert!(io.dropped() > 0 && io.held() > 0 && io.duplicated() > 0);

        // The bytes are not just equal but still a valid JSONL session log.
        let text = std::str::from_utf8(&moved).expect("utf-8 session text");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 160);
        for line in lines {
            serde_json::from_str::<serde_json::Value>(line).expect("each line is valid JSON");
        }
    }

    #[test]
    fn an_empty_stream_moves_nothing() {
        let mut source = Cursor::new(Vec::new());
        let mut dest = Vec::new();
        let stats = move_stream(
            &mut source,
            &mut dest,
            &mut SimulatedNet::lossless(),
            &peer(),
            &StreamConfig::default(),
        )
        .expect("an empty stream is complete");

        assert_eq!(
            stats,
            TransferStats {
                bytes: 0,
                fragments: 0,
                retransmits: 0,
                reordered: 0,
            }
        );
        assert!(dest.is_empty());
    }

    #[test]
    fn peer_ids_configs_and_stats_survive_serde() {
        let peer = peer();
        let json = serde_json::to_string(&peer).expect("peer serialises");
        assert_eq!(json, "\"peer-a\"");
        assert_eq!(
            serde_json::from_str::<PeerId>(&json).expect("peer parses"),
            peer
        );

        let config = StreamConfig::default();
        let json = serde_json::to_string(&config).expect("config serialises");
        assert_eq!(
            serde_json::from_str::<StreamConfig>(&json).expect("config parses"),
            config
        );

        let stats = TransferStats {
            bytes: 42,
            fragments: 2,
            retransmits: 1,
            reordered: 3,
        };
        let json = serde_json::to_string(&stats).expect("stats serialise");
        assert_eq!(
            serde_json::from_str::<TransferStats>(&json).expect("stats parse"),
            stats
        );
    }

    #[test]
    fn peer_ids_are_bounded() {
        assert!(matches!(PeerId::new(""), Err(StreamError::Invalid(_))));
        assert!(matches!(
            PeerId::new("a".repeat(MAX_PEER_BYTES + 1)),
            Err(StreamError::Oversized(_))
        ));
        assert_eq!(peer().as_str(), "peer-a");
    }

    #[test]
    fn the_module_opens_no_socket_and_reads_no_clock() {
        let source = include_str!("transport.rs");
        // Assembled at compile time so this test's own literals are not what it
        // finds in the source.
        let forbidden = [
            concat!("Udp", "Socket"),
            concat!("Tcp", "Stream"),
            concat!("Tcp", "Listener"),
            concat!("std::", "net"),
            concat!("std::", "time"),
            concat!("to_socket", "_addrs"),
        ];
        for needle in forbidden {
            assert!(
                !source.contains(needle),
                "transport must stay carrier-agnostic but names `{needle}`"
            );
        }
    }
}
