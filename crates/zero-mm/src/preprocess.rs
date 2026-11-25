//! T-MM-02 preprocessing: originals retained, deterministic plans, injectable
//! processor seams.
//!
//! Every attachment is first stored byte-for-byte in an [`OriginalStore`],
//! addressed by its BLAKE3 hash. Nothing in this module rewrites that file:
//! downscaling, tiling, OCR, transcription, and frame sampling all consume a
//! copy of the bytes and produce separate [`Derived`] values. [`OriginalRef`]
//! plus [`OriginalStore::read_full`] is therefore the full-resolution re-read
//! path that T-MM-02 requires.
//!
//! Work is planned before anything is executed:
//!
//! - [`plan_image`] bounds the longest edge, tiles the downscaled image with a
//!   configured overlap, and bounds the tile count ([`MAX_TILES`]).
//! - [`plan_audio`] picks a resample rate that never upsamples and splits the
//!   clip into bounded chunks ([`MAX_AUDIO_CHUNKS`]).
//! - [`plan_video`] samples at a target frame rate and caps the frame count
//!   ([`MAX_VIDEO_FRAMES`]).
//!
//! Real codecs are deliberately out of scope: [`ImageProcessor`],
//! [`OcrEngine`], [`Transcriber`], and [`FrameSampler`] are traits a caller
//! injects through [`Processors`]. A missing seam produces no derived item
//! rather than an implicit dependency, and no network access is possible here
//! (a URL attachment is rejected as unsupported). OCR and transcription output
//! is untrusted data: [`DerivedMeta::untrusted_text`] is always `true` for it,
//! and it must never be treated as instructions (MM-02, MM-03, MM-04).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zero_store::{BlobId, BlobStore};
use zero_types::{ErrorCode, Result, ZeroError};

use crate::input::{decode_base64, Attachment, Modality, Source};

/// Largest allowed downscale target, in pixels for the longest edge.
pub const MAX_IMAGE_EDGE: u32 = 8_192;
/// Maximum tiles produced by one image plan.
pub const MAX_TILES: usize = 64;
/// Maximum chunks produced by one audio plan.
pub const MAX_AUDIO_CHUNKS: usize = 4_096;
/// Maximum frames produced by one video plan.
pub const MAX_VIDEO_FRAMES: u32 = 64;
/// Largest accepted source sample rate, in hertz.
pub const MAX_SAMPLE_RATE_HZ: u32 = 384_000;
/// Largest accepted source frame rate, in frames per second.
pub const MAX_SOURCE_FPS: u32 = 240;
/// Maximum characters kept from one OCR region.
pub const MAX_OCR_CHARS: usize = 65_536;
/// Maximum characters kept from one transcript.
pub const MAX_TRANSCRIPT_CHARS: usize = 524_288;
/// Maximum bytes in one derived item.
pub const MAX_DERIVED_ITEM_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum bytes across every derived item of one preprocessing run.
pub const MAX_DERIVED_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Originals
// ---------------------------------------------------------------------------

/// A content-addressed reference to the untouched original bytes.
///
/// `hash` is the lowercase hex BLAKE3 digest, `bytes` is the exact length, and
/// `mime` is the essence recorded at store time. Reading through
/// [`OriginalStore::read_full`] verifies both the hash and the length, so a
/// caller can always return to full resolution even after a downscale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginalRef {
    pub hash: String,
    pub bytes: u64,
    pub mime: String,
}

/// A filesystem store for originals, laid out as `<root>/<2 hex>/<62 hex>`.
///
/// The store wraps [`zero_store::BlobStore`], so the BLAKE3 digest, the
/// idempotent write, and the verified read are shared with the rest of the
/// workspace. `put` is idempotent for identical content, and `read_full` never
/// mutates or downscales what it reads.
#[derive(Debug, Clone)]
pub struct OriginalStore {
    root: PathBuf,
    blobs: BlobStore,
}

impl OriginalStore {
    /// Create or open a store rooted at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let blobs = BlobStore::open(&root)?;
        Ok(Self { root, blobs })
    }

    /// The store root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Store bytes under the byte cap of their modality.
    ///
    /// The cap is [`Modality::byte_cap`], the same per-modality limit the input
    /// layer enforces.
    pub fn put(&self, kind: Modality, mime: &str, bytes: &[u8]) -> Result<OriginalRef> {
        self.put_with_cap(mime, bytes, kind.byte_cap())
    }

    /// Store bytes under an explicit cap.
    pub fn put_with_cap(&self, mime: &str, bytes: &[u8], cap: u64) -> Result<OriginalRef> {
        let mime = validate_mime(mime)?;
        if bytes.len() as u64 > cap {
            return Err(limit(format!(
                "original is {} bytes; the cap is {cap}",
                bytes.len()
            )));
        }
        let id = self.blobs.put(bytes)?;
        Ok(OriginalRef {
            hash: id.to_hex(),
            bytes: bytes.len() as u64,
            mime: mime.to_string(),
        })
    }

    /// Whether the referenced content is present.
    pub fn has(&self, original: &OriginalRef) -> bool {
        BlobId::parse(&original.hash)
            .map(|id| self.blobs.has(id))
            .unwrap_or(false)
    }

    /// Read the original at full resolution and verify its hash and length.
    ///
    /// A missing blob is [`ErrorCode::NotFound`]. A blob whose bytes no longer
    /// match the reference is [`ErrorCode::Corrupt`]; the caller must not
    /// silently fall back to a downscaled copy.
    pub fn read_full(&self, original: &OriginalRef) -> Result<Vec<u8>> {
        let id = BlobId::parse(&original.hash).map_err(|_| {
            invalid("original hash must be 64 hexadecimal characters (a BLAKE3 digest)")
        })?;
        let bytes = self.blobs.get(id).map_err(|error| {
            if error.code() == ErrorCode::NotFound {
                ZeroError::new(
                    ErrorCode::NotFound,
                    format!("original `{}` is missing", original.hash),
                )
            } else {
                error
            }
        })?;
        if bytes.len() as u64 != original.bytes {
            return Err(ZeroError::new(
                ErrorCode::Corrupt,
                format!(
                    "original `{}` is {} bytes but the reference says {}",
                    original.hash,
                    bytes.len(),
                    original.bytes
                ),
            ));
        }
        Ok(bytes)
    }

    /// [`preprocess`](crate::preprocess) against this store.
    ///
    /// This is the three-argument call form: `store.preprocess(&attachment,
    /// &plan, &processors)`.
    pub fn preprocess(
        &self,
        attachment: &Attachment,
        plan: &PreprocessPlan,
        processors: &Processors<'_>,
    ) -> Result<Preprocessed> {
        preprocess(self, attachment, plan, processors)
    }
}

// ---------------------------------------------------------------------------
// Image plans
// ---------------------------------------------------------------------------

/// A bounded downscale-and-tile plan for one image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImagePlan {
    /// Longest edge of the downscaled image. The image is never upscaled.
    pub max_edge: u32,
    /// Edge of one square-ish tile in the downscaled image.
    pub tile_edge: u32,
    /// Overlap between adjacent tiles, in pixels. Must be smaller than
    /// `tile_edge`.
    pub overlap: u32,
    /// Whether the plan includes OCR regions.
    pub ocr: bool,
}

impl Default for ImagePlan {
    fn default() -> Self {
        Self {
            max_edge: 1_568,
            tile_edge: 512,
            overlap: 64,
            ocr: true,
        }
    }
}

/// One tile of a downscaled image, in downscaled pixel coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tile {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

/// The resolved image plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageWork {
    /// Downscaled size. Equal to the source size when it already fits.
    pub downscaled: (u32, u32),
    /// Tiles in row-major order. Every tile is inside `downscaled`.
    pub tiles: Vec<Tile>,
    /// Regions to OCR. Equal to `tiles` when `ocr` is set, otherwise empty.
    pub ocr_regions: Vec<Tile>,
}

/// Plan an image downscale and its tiles.
///
/// The downscaled image preserves aspect ratio, never upscales, and never has a
/// zero dimension. Tiles cover the whole downscaled image; adjacent tiles in
/// one axis overlap by at least `overlap`, and the final tile is shifted left
/// or up so it ends exactly on the edge instead of running past it. The plan is
/// deterministic and is rejected with [`ErrorCode::LimitExceeded`] when it
/// would exceed [`MAX_TILES`].
pub fn plan_image(width: u32, height: u32, plan: ImagePlan) -> Result<ImageWork> {
    if width == 0 || height == 0 {
        return Err(invalid("image dimensions must be positive"));
    }
    if plan.max_edge == 0 {
        return Err(invalid("image max_edge must be positive"));
    }
    if plan.max_edge > MAX_IMAGE_EDGE {
        return Err(limit(format!(
            "image max_edge {} exceeds the documented maximum of {MAX_IMAGE_EDGE}",
            plan.max_edge
        )));
    }
    if plan.tile_edge == 0 || plan.tile_edge > plan.max_edge {
        return Err(invalid(
            "image tile_edge must be positive and no larger than max_edge",
        ));
    }
    if plan.overlap >= plan.tile_edge {
        return Err(invalid("image overlap must be smaller than tile_edge"));
    }

    let (downscaled_w, downscaled_h) = downscaled_size(width, height, plan.max_edge);
    let xs = axis_tiles(downscaled_w, plan.tile_edge, plan.overlap);
    let ys = axis_tiles(downscaled_h, plan.tile_edge, plan.overlap);
    let count = xs.len() * ys.len();
    if count > MAX_TILES {
        return Err(limit(format!(
            "image plan needs {count} tiles; the cap is {MAX_TILES}"
        )));
    }

    let mut tiles = Vec::with_capacity(count);
    for &(y, h) in &ys {
        for &(x, w) in &xs {
            tiles.push(Tile { x, y, w, h });
        }
    }
    let ocr_regions = if plan.ocr { tiles.clone() } else { Vec::new() };
    Ok(ImageWork {
        downscaled: (downscaled_w, downscaled_h),
        tiles,
        ocr_regions,
    })
}

/// Scale the longest edge down to `max_edge` with integer rounding. No upscale.
fn downscaled_size(width: u32, height: u32, max_edge: u32) -> (u32, u32) {
    let longest = width.max(height);
    if longest <= max_edge {
        return (width, height);
    }
    let scale = |edge: u32| -> u32 {
        let scaled =
            (u64::from(edge) * u64::from(max_edge) + u64::from(longest) / 2) / u64::from(longest);
        scaled.max(1) as u32
    };
    (scale(width), scale(height))
}

/// One axis of the tile grid: `(start, length)` pairs, in order.
fn axis_tiles(length: u32, tile_edge: u32, overlap: u32) -> Vec<(u32, u32)> {
    if length <= tile_edge {
        return vec![(0, length)];
    }
    let step = tile_edge - overlap;
    let last = length - tile_edge;
    let mut spans = Vec::new();
    let mut start = 0;
    while start < last {
        spans.push((start, tile_edge));
        start += step;
    }
    if spans.last().map(|(start, _)| *start) != Some(last) {
        spans.push((last, tile_edge));
    }
    spans
}

// ---------------------------------------------------------------------------
// Audio plans
// ---------------------------------------------------------------------------

/// A bounded resample-and-chunk plan for one audio clip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudioPlan {
    /// Requested sample rate. The effective rate never upsamples.
    pub target_rate_hz: u32,
    /// Chunk length in milliseconds.
    pub chunk_ms: u32,
}

impl Default for AudioPlan {
    fn default() -> Self {
        Self {
            target_rate_hz: 16_000,
            chunk_ms: 30_000,
        }
    }
}

/// One planned audio chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudioChunk {
    pub index: u32,
    pub start_ms: u64,
    pub end_ms: u64,
}

/// The resolved audio plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudioWork {
    /// `min(source rate, target rate)`; resampling never invents detail.
    pub resampled_rate: u32,
    /// Chunks in time order. A zero-length clip has no chunks.
    pub chunks: Vec<AudioChunk>,
}

/// Plan audio resampling and chunk boundaries.
///
/// Chunks are contiguous, the last chunk is shortened to the clip length, and
/// the count is bounded by [`MAX_AUDIO_CHUNKS`]. A zero-length clip is valid
/// and produces no chunks.
pub fn plan_audio(duration_ms: u64, rate_hz: u32, plan: AudioPlan) -> Result<AudioWork> {
    if rate_hz == 0 {
        return Err(invalid("audio source rate must be positive"));
    }
    if plan.target_rate_hz == 0 {
        return Err(invalid("audio target_rate_hz must be positive"));
    }
    if rate_hz > MAX_SAMPLE_RATE_HZ || plan.target_rate_hz > MAX_SAMPLE_RATE_HZ {
        return Err(limit(format!(
            "audio sample rate exceeds the documented maximum of {MAX_SAMPLE_RATE_HZ} Hz"
        )));
    }
    if plan.chunk_ms == 0 {
        return Err(invalid("audio chunk_ms must be positive"));
    }

    let chunk_ms = u64::from(plan.chunk_ms);
    let count = if duration_ms == 0 {
        0
    } else {
        duration_ms.div_ceil(chunk_ms)
    };
    if count > MAX_AUDIO_CHUNKS as u64 {
        return Err(limit(format!(
            "audio plan needs {count} chunks; the cap is {MAX_AUDIO_CHUNKS}"
        )));
    }

    let mut chunks = Vec::with_capacity(count as usize);
    let mut start_ms = 0;
    while start_ms < duration_ms {
        let end_ms = start_ms.saturating_add(chunk_ms).min(duration_ms);
        chunks.push(AudioChunk {
            index: chunks.len() as u32,
            start_ms,
            end_ms,
        });
        start_ms = end_ms;
    }

    Ok(AudioWork {
        resampled_rate: rate_hz.min(plan.target_rate_hz),
        chunks,
    })
}

// ---------------------------------------------------------------------------
// Video plans
// ---------------------------------------------------------------------------

/// A bounded frame-sampling plan for one video.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoPlan {
    /// Target samples per second. Clamped to the source frame rate.
    pub fps_sample: u32,
    /// Hard cap on sampled frames.
    pub max_frames: u32,
}

impl Default for VideoPlan {
    fn default() -> Self {
        Self {
            fps_sample: 1,
            max_frames: 24,
        }
    }
}

/// The resolved video plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoWork {
    /// Frame timestamps in milliseconds, strictly increasing.
    pub frame_times: Vec<u64>,
    /// Number of timestamps. Equal to `frame_times.len()`.
    pub sampled: u32,
}

/// Plan video frame timestamps.
///
/// Sampling is at `min(fps_sample, fps)` so the plan never asks for frames the
/// source does not have. When the requested count exceeds `max_frames`, the
/// plan keeps `max_frames` timestamps spread evenly across the clip instead of
/// dropping the tail. `max_frames` is bounded by [`MAX_VIDEO_FRAMES`].
pub fn plan_video(duration_ms: u64, fps: u32, plan: VideoPlan) -> Result<VideoWork> {
    if fps == 0 {
        return Err(invalid("video frame rate must be positive"));
    }
    if fps > MAX_SOURCE_FPS {
        return Err(limit(format!(
            "video frame rate {fps} exceeds the documented maximum of {MAX_SOURCE_FPS}"
        )));
    }
    if plan.fps_sample == 0 {
        return Err(invalid("video fps_sample must be positive"));
    }
    if plan.max_frames == 0 {
        return Err(invalid("video max_frames must be positive"));
    }
    if plan.max_frames > MAX_VIDEO_FRAMES {
        return Err(limit(format!(
            "video max_frames {} exceeds the documented maximum of {MAX_VIDEO_FRAMES}",
            plan.max_frames
        )));
    }

    let effective_fps = plan.fps_sample.min(fps);
    let frame_times = if duration_ms == 0 {
        Vec::new()
    } else {
        let requested = (u128::from(duration_ms) * u128::from(effective_fps)).div_ceil(1_000);
        let max_frames = u128::from(plan.max_frames);
        if requested <= max_frames {
            (0..requested)
                .map(|index| (index * 1_000 / u128::from(effective_fps)) as u64)
                .collect()
        } else {
            (0..max_frames)
                .map(|index| (index * u128::from(duration_ms) / max_frames) as u64)
                .collect()
        }
    };

    Ok(VideoWork {
        sampled: frame_times.len() as u32,
        frame_times,
    })
}

// ---------------------------------------------------------------------------
// Processor seams
// ---------------------------------------------------------------------------

/// Downscale and crop an image.
///
/// `downscale` receives the untouched original bytes and the planned target
/// size. `crop` receives the downscaled bytes and one [`Tile`] in the
/// downscaled coordinate space; it must not read the original out of band.
pub trait ImageProcessor {
    fn downscale(&self, original: &[u8], target: (u32, u32)) -> Result<Vec<u8>>;
    fn crop(&self, image: &[u8], tile: Tile) -> Result<Vec<u8>>;
}

/// Recognise text in one image. Output is untrusted data.
pub trait OcrEngine {
    fn ocr(&self, image: &[u8]) -> Result<String>;
}

/// Transcribe one audio clip. Output is untrusted data.
pub trait Transcriber {
    fn transcribe(&self, audio: &[u8]) -> Result<String>;
}

/// Extract frames at the planned timestamps.
pub trait FrameSampler {
    fn sample(&self, video: &[u8], times_ms: &[u64]) -> Result<Vec<Vec<u8>>>;
}

/// The injected seams for one preprocessing run.
///
/// Every seam is optional. A missing seam means the corresponding derived
/// output is not produced; it never triggers an implicit codec or download.
#[derive(Clone, Copy, Default)]
pub struct Processors<'a> {
    pub image: Option<&'a dyn ImageProcessor>,
    pub ocr: Option<&'a dyn OcrEngine>,
    pub transcriber: Option<&'a dyn Transcriber>,
    pub frames: Option<&'a dyn FrameSampler>,
}

impl<'a> Processors<'a> {
    /// No seams: originals are stored and plans resolved, but nothing runs.
    pub fn none() -> Self {
        Self::default()
    }

    pub fn with_image(mut self, image: &'a dyn ImageProcessor) -> Self {
        self.image = Some(image);
        self
    }

    pub fn with_ocr(mut self, ocr: &'a dyn OcrEngine) -> Self {
        self.ocr = Some(ocr);
        self
    }

    pub fn with_transcriber(mut self, transcriber: &'a dyn Transcriber) -> Self {
        self.transcriber = Some(transcriber);
        self
    }

    pub fn with_frames(mut self, frames: &'a dyn FrameSampler) -> Self {
        self.frames = Some(frames);
        self
    }
}

// ---------------------------------------------------------------------------
// Derived outputs and accounting
// ---------------------------------------------------------------------------

/// What one derived value is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedKind {
    Downscaled,
    Tile,
    OcrText,
    Transcript,
    Frame,
}

impl DerivedKind {
    /// Stable lowercase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            DerivedKind::Downscaled => "downscaled",
            DerivedKind::Tile => "tile",
            DerivedKind::OcrText => "ocr_text",
            DerivedKind::Transcript => "transcript",
            DerivedKind::Frame => "frame",
        }
    }
}

/// The payload of one derived value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DerivedPayload {
    Bytes { bytes: Vec<u8> },
    Text { text: String },
}

impl DerivedPayload {
    /// Length in bytes as stored.
    pub fn byte_len(&self) -> u64 {
        match self {
            DerivedPayload::Bytes { bytes } => bytes.len() as u64,
            DerivedPayload::Text { text } => text.len() as u64,
        }
    }

    /// Character count for text payloads, `0` for bytes.
    pub fn char_len(&self) -> u64 {
        match self {
            DerivedPayload::Bytes { .. } => 0,
            DerivedPayload::Text { text } => text.chars().count() as u64,
        }
    }
}

/// Metadata recorded next to one derived value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedMeta {
    /// Position within its kind, in production order.
    pub index: u32,
    pub width: Option<u32>,
    pub height: Option<u32>,
    /// The source tile, for a tile, crop, or per-tile OCR item.
    pub tile: Option<Tile>,
    /// The source timestamp, for a video frame.
    pub frame_ms: Option<u64>,
    /// Payload bytes.
    pub bytes: u64,
    /// Payload characters (`0` for binary payloads).
    pub chars: u64,
    /// `true` for OCR and transcript text. Such text is data, never instructions.
    pub untrusted_text: bool,
}

/// One value derived from an original, always separate from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Derived {
    pub kind: DerivedKind,
    pub bytes_or_text: DerivedPayload,
    pub meta: DerivedMeta,
}

impl Derived {
    /// The text payload, when this item is OCR or transcript text.
    pub fn text(&self) -> Option<&str> {
        match &self.bytes_or_text {
            DerivedPayload::Text { text } => Some(text.as_str()),
            DerivedPayload::Bytes { .. } => None,
        }
    }

    /// Whether this item carries untrusted text.
    pub fn is_untrusted_text(&self) -> bool {
        self.meta.untrusted_text
    }

    fn new_bytes(kind: DerivedKind, bytes: Vec<u8>, mut meta: DerivedMeta) -> Self {
        meta.bytes = bytes.len() as u64;
        meta.chars = 0;
        meta.untrusted_text = false;
        Self {
            kind,
            bytes_or_text: DerivedPayload::Bytes { bytes },
            meta,
        }
    }

    fn new_text(
        kind: DerivedKind,
        text: String,
        cap_chars: usize,
        mut meta: DerivedMeta,
    ) -> Result<Self> {
        let chars = text.chars().count();
        if chars > cap_chars {
            return Err(limit(format!(
                "{} text is {chars} characters; the cap is {cap_chars}",
                kind.as_str()
            )));
        }
        meta.bytes = text.len() as u64;
        meta.chars = chars as u64;
        meta.untrusted_text = true;
        Ok(Self {
            kind,
            bytes_or_text: DerivedPayload::Text { text },
            meta,
        })
    }
}

/// Per-run accounting. Every value comes from work that actually ran or was
/// planned; nothing is guessed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreprocessAccounting {
    pub original_bytes: u64,
    pub derived_items: u32,
    pub derived_bytes: u64,
    pub text_chars: u64,
    pub tiles: u32,
    pub ocr_chars: u64,
    pub transcript_chars: u64,
    pub frames: u32,
}

/// The plan that was applied, for inspection and test evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AppliedWork {
    /// Text and document attachments are stored only in this slice.
    Skipped,
    Image(ImageWork),
    Audio(AudioWork),
    Video(VideoWork),
}

/// One attachment's source geometry, measured by the caller's decoder.
///
/// This module never parses image, audio, or video headers, so the caller must
/// supply the dimensions, duration, rate, and frame rate it already knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceGeometry {
    Image { width: u32, height: u32 },
    Audio { duration_ms: u64, rate_hz: u32 },
    Video { duration_ms: u64, fps: u32 },
}

/// The whole plan for one preprocessing run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PreprocessPlan {
    pub image: ImagePlan,
    pub audio: AudioPlan,
    pub video: VideoPlan,
    /// Required for image, audio, and video attachments. Ignored for text and
    /// documents.
    pub geometry: Option<SourceGeometry>,
}

impl PreprocessPlan {
    pub fn for_image(width: u32, height: u32) -> Self {
        Self {
            geometry: Some(SourceGeometry::Image { width, height }),
            ..Self::default()
        }
    }

    pub fn for_audio(duration_ms: u64, rate_hz: u32) -> Self {
        Self {
            geometry: Some(SourceGeometry::Audio {
                duration_ms,
                rate_hz,
            }),
            ..Self::default()
        }
    }

    pub fn for_video(duration_ms: u64, fps: u32) -> Self {
        Self {
            geometry: Some(SourceGeometry::Video { duration_ms, fps }),
            ..Self::default()
        }
    }
}

/// The complete result of one preprocessing run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preprocessed {
    /// The untouched bytes, addressable for a full-resolution re-read.
    pub original: OriginalRef,
    /// The resolved plan.
    pub work: AppliedWork,
    /// Derived values, in deterministic production order.
    pub derived: Vec<Derived>,
    pub accounting: PreprocessAccounting,
}

/// Store the original, resolve the plan, and run the injected seams.
///
/// The original is written first and is never replaced by a derived value.
/// `preprocess` keeps no external state: the caller passes the same store it
/// uses for [`OriginalStore::read_full`]. A URL source is rejected with
/// [`ErrorCode::Unsupported`] rather than fetched.
///
/// Image order is one `Downscaled` item, then for each tile a `Tile` item and,
/// when OCR is enabled and an engine is present, one `OcrText` item. Without an
/// image seam, a present OCR engine runs once over the original bytes. Audio
/// produces one `Transcript` item from the whole original; the chunk plan is
/// metadata, not a byte slice of a compressed container. Video produces one
/// `Frame` item per timestamp.
pub fn preprocess(
    store: &OriginalStore,
    attachment: &Attachment,
    plan: &PreprocessPlan,
    processors: &Processors<'_>,
) -> Result<Preprocessed> {
    validate_mime(&attachment.mime)?;
    let original_bytes = attachment_bytes(attachment)?;
    let cap = attachment.kind.byte_cap();
    if original_bytes.len() as u64 > cap {
        return Err(limit(format!(
            "attachment `{}` is {} bytes; the {} cap is {cap}",
            attachment.id,
            original_bytes.len(),
            attachment.kind.as_str()
        )));
    }
    let original = store.put(attachment.kind, &attachment.mime, &original_bytes)?;

    let mut sink = DerivedSink::default();
    let (work, tiles, frames) = match attachment.kind {
        Modality::Image => image_work(&original_bytes, plan, processors, &mut sink)?,
        Modality::Audio => audio_work(&original_bytes, plan, processors, &mut sink)?,
        Modality::Video => video_work(&original_bytes, plan, processors, &mut sink)?,
        Modality::Text | Modality::Document => (AppliedWork::Skipped, 0, 0),
    };

    let accounting = PreprocessAccounting {
        original_bytes: original.bytes,
        derived_items: sink.items.len() as u32,
        derived_bytes: sink.bytes,
        text_chars: sink.text_chars,
        tiles,
        ocr_chars: sink.ocr_chars,
        transcript_chars: sink.transcript_chars,
        frames,
    };
    Ok(Preprocessed {
        original,
        work,
        derived: sink.items,
        accounting,
    })
}

fn image_work(
    bytes: &[u8],
    plan: &PreprocessPlan,
    processors: &Processors<'_>,
    sink: &mut DerivedSink,
) -> Result<(AppliedWork, u32, u32)> {
    let (width, height) = match plan.geometry {
        Some(SourceGeometry::Image { width, height }) => (width, height),
        Some(_) => return Err(invalid("image preprocessing received non-image geometry")),
        None => {
            return Err(invalid(
                "image preprocessing needs width and height in the plan",
            ))
        }
    };
    let work = plan_image(width, height, plan.image.clone())?;
    let tile_count = work.tiles.len() as u32;

    if let Some(image) = processors.image {
        let downscaled = image.downscale(bytes, work.downscaled)?;
        let meta = DerivedMeta {
            width: Some(work.downscaled.0),
            height: Some(work.downscaled.1),
            ..DerivedMeta::default()
        };
        sink.push(Derived::new_bytes(
            DerivedKind::Downscaled,
            downscaled.clone(),
            meta,
        ))?;

        for (index, tile) in work.tiles.iter().enumerate() {
            let cropped = image.crop(&downscaled, *tile)?;
            let meta = DerivedMeta {
                index: index as u32,
                tile: Some(*tile),
                ..DerivedMeta::default()
            };
            sink.push(Derived::new_bytes(DerivedKind::Tile, cropped.clone(), meta))?;
            if plan.image.ocr {
                if let Some(ocr) = processors.ocr {
                    let text = ocr.ocr(&cropped)?;
                    let meta = DerivedMeta {
                        index: index as u32,
                        tile: Some(*tile),
                        ..DerivedMeta::default()
                    };
                    sink.push(Derived::new_text(
                        DerivedKind::OcrText,
                        text,
                        MAX_OCR_CHARS,
                        meta,
                    )?)?;
                }
            }
        }
    } else if plan.image.ocr {
        if let Some(ocr) = processors.ocr {
            let text = ocr.ocr(bytes)?;
            let meta = DerivedMeta {
                untrusted_text: true,
                ..DerivedMeta::default()
            };
            sink.push(Derived::new_text(
                DerivedKind::OcrText,
                text,
                MAX_OCR_CHARS,
                meta,
            )?)?;
        }
    }

    Ok((AppliedWork::Image(work), tile_count, 0))
}

fn audio_work(
    bytes: &[u8],
    plan: &PreprocessPlan,
    processors: &Processors<'_>,
    sink: &mut DerivedSink,
) -> Result<(AppliedWork, u32, u32)> {
    let (duration_ms, rate_hz) = match plan.geometry {
        Some(SourceGeometry::Audio {
            duration_ms,
            rate_hz,
        }) => (duration_ms, rate_hz),
        Some(_) => return Err(invalid("audio preprocessing received non-audio geometry")),
        None => {
            return Err(invalid(
                "audio preprocessing needs duration and sample rate in the plan",
            ))
        }
    };
    let work = plan_audio(duration_ms, rate_hz, plan.audio.clone())?;

    if let Some(transcriber) = processors.transcriber {
        let text = transcriber.transcribe(bytes)?;
        let meta = DerivedMeta {
            untrusted_text: true,
            ..DerivedMeta::default()
        };
        sink.push(Derived::new_text(
            DerivedKind::Transcript,
            text,
            MAX_TRANSCRIPT_CHARS,
            meta,
        )?)?;
    }

    Ok((AppliedWork::Audio(work), 0, 0))
}

fn video_work(
    bytes: &[u8],
    plan: &PreprocessPlan,
    processors: &Processors<'_>,
    sink: &mut DerivedSink,
) -> Result<(AppliedWork, u32, u32)> {
    let (duration_ms, fps) = match plan.geometry {
        Some(SourceGeometry::Video { duration_ms, fps }) => (duration_ms, fps),
        Some(_) => return Err(invalid("video preprocessing received non-video geometry")),
        None => {
            return Err(invalid(
                "video preprocessing needs duration and frame rate in the plan",
            ))
        }
    };
    let work = plan_video(duration_ms, fps, plan.video.clone())?;
    let sampled = work.sampled;

    if let Some(frames) = processors.frames {
        let extracted = frames.sample(bytes, &work.frame_times)?;
        if extracted.len() != work.frame_times.len() {
            return Err(invalid(format!(
                "frame sampler returned {} frames for {} timestamps",
                extracted.len(),
                work.frame_times.len()
            )));
        }
        for (index, (frame, at_ms)) in extracted
            .into_iter()
            .zip(work.frame_times.iter())
            .enumerate()
        {
            let meta = DerivedMeta {
                index: index as u32,
                frame_ms: Some(*at_ms),
                ..DerivedMeta::default()
            };
            sink.push(Derived::new_bytes(DerivedKind::Frame, frame, meta))?;
        }
    }

    Ok((AppliedWork::Video(work), 0, sampled))
}

#[derive(Default)]
struct DerivedSink {
    items: Vec<Derived>,
    bytes: u64,
    text_chars: u64,
    ocr_chars: u64,
    transcript_chars: u64,
}

impl DerivedSink {
    fn push(&mut self, derived: Derived) -> Result<()> {
        let item_bytes = derived.meta.bytes;
        if item_bytes > MAX_DERIVED_ITEM_BYTES {
            return Err(limit(format!(
                "derived {} item is {item_bytes} bytes; the cap is {MAX_DERIVED_ITEM_BYTES}",
                derived.kind.as_str()
            )));
        }
        let total = self.bytes.saturating_add(item_bytes);
        if total > MAX_DERIVED_TOTAL_BYTES {
            return Err(limit(format!(
                "derived output is {total} bytes; the cap is {MAX_DERIVED_TOTAL_BYTES}"
            )));
        }
        self.bytes = total;
        self.text_chars += derived.meta.chars;
        match derived.kind {
            DerivedKind::OcrText => self.ocr_chars += derived.meta.chars,
            DerivedKind::Transcript => self.transcript_chars += derived.meta.chars,
            DerivedKind::Downscaled | DerivedKind::Tile | DerivedKind::Frame => {}
        }
        self.items.push(derived);
        Ok(())
    }
}

fn attachment_bytes(attachment: &Attachment) -> Result<Vec<u8>> {
    match &attachment.source {
        Source::Inline { bytes_b64 } => decode_base64(bytes_b64),
        Source::Path { path } => {
            let metadata = fs::metadata(path)?;
            if metadata.len() > attachment.kind.byte_cap() {
                return Err(limit(format!(
                    "attachment `{}` is {} bytes; the {} cap is {}",
                    attachment.id,
                    metadata.len(),
                    attachment.kind.as_str(),
                    attachment.kind.byte_cap()
                )));
            }
            Ok(fs::read(path)?)
        }
        Source::Url { url } => Err(ZeroError::new(
            ErrorCode::Unsupported,
            format!(
                "preprocessing does not fetch `{url}`; attach the bytes inline or as a local path"
            ),
        )),
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn validate_mime(mime: &str) -> Result<&str> {
    if mime.chars().any(char::is_control) {
        return Err(invalid(format!(
            "mime `{mime}` contains a control character"
        )));
    }
    let essence = mime.split(';').next().unwrap_or("").trim();
    let Some((category, subtype)) = essence.split_once('/') else {
        return Err(invalid(format!("mime `{mime}` is missing `type/subtype`")));
    };
    if category.is_empty() || subtype.is_empty() || subtype.contains('/') {
        return Err(invalid(format!("mime `{mime}` is malformed")));
    }
    Ok(essence)
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn limit(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    struct Fixture {
        temp: TempDir,
        originals: OriginalStore,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().expect("tempdir");
            let originals =
                OriginalStore::open(temp.path().join("originals")).expect("original store");
            Self { temp, originals }
        }

        fn attachment(&self, name: &str, kind: Modality, mime: &str, bytes: &[u8]) -> Attachment {
            let path = self.temp.path().join(name);
            fs::write(&path, bytes).expect("write fixture");
            Attachment {
                id: format!("att-{name}"),
                kind,
                source: Source::Path { path },
                mime: mime.to_string(),
                bytes: bytes.len() as u64,
                name: None,
            }
        }
    }

    struct FakeImage;

    impl ImageProcessor for FakeImage {
        fn downscale(&self, original: &[u8], target: (u32, u32)) -> Result<Vec<u8>> {
            Ok(format!("down:{}x{}:{}", target.0, target.1, original.len()).into_bytes())
        }

        fn crop(&self, image: &[u8], tile: Tile) -> Result<Vec<u8>> {
            Ok(format!(
                "crop:{},{},{},{}:{}",
                tile.x,
                tile.y,
                tile.w,
                tile.h,
                image.len()
            )
            .into_bytes())
        }
    }

    struct FakeOcr;

    impl OcrEngine for FakeOcr {
        fn ocr(&self, image: &[u8]) -> Result<String> {
            Ok(format!("ocr:{}", image.len()))
        }
    }

    struct VerboseOcr;

    impl OcrEngine for VerboseOcr {
        fn ocr(&self, _image: &[u8]) -> Result<String> {
            Ok("x".repeat(MAX_OCR_CHARS + 1))
        }
    }

    struct FakeTranscriber;

    impl Transcriber for FakeTranscriber {
        fn transcribe(&self, audio: &[u8]) -> Result<String> {
            Ok(format!("transcript:{}", audio.len()))
        }
    }

    struct FakeFrames;

    impl FrameSampler for FakeFrames {
        fn sample(&self, video: &[u8], times_ms: &[u64]) -> Result<Vec<Vec<u8>>> {
            Ok(times_ms
                .iter()
                .map(|at_ms| format!("frame:{at_ms}:{}", video.len()).into_bytes())
                .collect())
        }
    }

    struct ShortFrames;

    impl FrameSampler for ShortFrames {
        fn sample(&self, _video: &[u8], _times_ms: &[u64]) -> Result<Vec<Vec<u8>>> {
            Ok(vec![b"one".to_vec()])
        }
    }

    fn payload_len(payload: &DerivedPayload) -> u64 {
        payload.byte_len()
    }

    #[test]
    fn original_store_round_trips_and_re_reads_at_full_resolution() {
        let fixture = Fixture::new();
        let store = &fixture.originals;
        let bytes = b"full resolution original".to_vec();

        let original = store
            .put(Modality::Image, "image/png", &bytes)
            .expect("store original");
        assert_eq!(original.hash.len(), 64);
        assert!(original.hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(original.bytes, bytes.len() as u64);
        assert_eq!(original.mime, "image/png");
        assert!(store.has(&original));
        assert_eq!(store.read_full(&original).expect("re-read"), bytes);

        let again = store
            .put(Modality::Image, "image/png", &bytes)
            .expect("idempotent store");
        assert_eq!(
            again, original,
            "identical content reuses the same reference"
        );

        let missing = OriginalRef {
            hash: "0".repeat(64),
            bytes: 1,
            mime: "image/png".to_string(),
        };
        assert_eq!(
            store
                .read_full(&missing)
                .expect_err("missing original")
                .code(),
            ErrorCode::NotFound
        );

        let path = store
            .root
            .join(&original.hash[..2])
            .join(&original.hash[2..]);
        fs::write(&path, b"tampered").expect("tamper with the blob");
        assert_eq!(
            store
                .read_full(&original)
                .expect_err("corrupt original")
                .code(),
            ErrorCode::Corrupt
        );
    }

    #[test]
    fn image_plan_is_deterministic_and_bounded() {
        let plan = ImagePlan {
            max_edge: 1_024,
            tile_edge: 256,
            overlap: 32,
            ocr: true,
        };
        let first = plan_image(4_000, 2_000, plan.clone()).expect("plan");
        let second = plan_image(4_000, 2_000, plan.clone()).expect("plan");
        assert_eq!(first, second, "the same input yields the same plan");
        assert_eq!(first.downscaled, (1_024, 512));
        assert!(first.tiles.len() <= MAX_TILES);
        assert_eq!(first.ocr_regions, first.tiles);

        let small = plan_image(
            100,
            50,
            ImagePlan {
                max_edge: 1_024,
                tile_edge: 512,
                overlap: 64,
                ocr: false,
            },
        )
        .expect("small image");
        assert_eq!(small.downscaled, (100, 50), "no upscale");
        assert_eq!(
            small.tiles,
            vec![Tile {
                x: 0,
                y: 0,
                w: 100,
                h: 50
            }]
        );
        assert!(small.ocr_regions.is_empty(), "ocr is off in this plan");

        let too_many = ImagePlan {
            max_edge: MAX_IMAGE_EDGE,
            tile_edge: 8,
            overlap: 0,
            ocr: false,
        };
        assert_eq!(
            plan_image(MAX_IMAGE_EDGE, MAX_IMAGE_EDGE, too_many)
                .expect_err("tile cap")
                .code(),
            ErrorCode::LimitExceeded
        );

        assert!(
            plan_image(0, 10, ImagePlan::default()).is_err(),
            "zero width is rejected"
        );
        for (label, plan) in [
            (
                "zero max edge",
                ImagePlan {
                    max_edge: 0,
                    ..ImagePlan::default()
                },
            ),
            (
                "oversize max edge",
                ImagePlan {
                    max_edge: MAX_IMAGE_EDGE + 1,
                    ..ImagePlan::default()
                },
            ),
            (
                "zero tile edge",
                ImagePlan {
                    tile_edge: 0,
                    ..ImagePlan::default()
                },
            ),
            (
                "tile larger than max edge",
                ImagePlan {
                    tile_edge: 2_000,
                    ..ImagePlan::default()
                },
            ),
            (
                "overlap equals tile edge",
                ImagePlan {
                    overlap: 512,
                    ..ImagePlan::default()
                },
            ),
        ] {
            let result = plan_image(1_000, 1_000, plan);
            assert!(result.is_err(), "{label} must be rejected");
        }
    }

    #[test]
    fn image_tiles_cover_the_image_and_keep_the_overlap() {
        let work = plan_image(
            1_000,
            700,
            ImagePlan {
                max_edge: 1_000,
                tile_edge: 300,
                overlap: 50,
                ocr: false,
            },
        )
        .expect("plan");
        assert_eq!(work.downscaled, (1_000, 700));

        for tile in &work.tiles {
            assert_eq!((tile.w, tile.h), (300, 300), "full-size tiles");
            assert!(tile.x + tile.w <= 1_000);
            assert!(tile.y + tile.h <= 700);
        }

        let mut xs: Vec<u32> = work.tiles.iter().map(|tile| tile.x).collect();
        xs.sort_unstable();
        xs.dedup();
        let mut ys: Vec<u32> = work.tiles.iter().map(|tile| tile.y).collect();
        ys.sort_unstable();
        ys.dedup();

        for pair in xs.windows(2) {
            let overlap = 300 - (pair[1] - pair[0]);
            assert!(overlap >= 50, "horizontal overlap is at least 50");
        }
        for pair in ys.windows(2) {
            let overlap = 300 - (pair[1] - pair[0]);
            assert!(overlap >= 50, "vertical overlap is at least 50");
        }
        assert_eq!(xs.first(), Some(&0));
        assert_eq!(xs.last(), Some(&(1_000 - 300)));
        assert_eq!(ys.first(), Some(&0));
        assert_eq!(ys.last(), Some(&(700 - 300)));

        let mut covered_x = vec![false; 1_000];
        for tile in &work.tiles {
            for slot in covered_x
                .iter_mut()
                .take((tile.x + tile.w) as usize)
                .skip(tile.x as usize)
            {
                *slot = true;
            }
        }
        assert!(
            covered_x.iter().all(|slot| *slot),
            "every column is covered"
        );

        let mut covered_y = vec![false; 700];
        for tile in &work.tiles {
            for slot in covered_y
                .iter_mut()
                .take((tile.y + tile.h) as usize)
                .skip(tile.y as usize)
            {
                *slot = true;
            }
        }
        assert!(covered_y.iter().all(|slot| *slot), "every row is covered");
    }

    #[test]
    fn audio_chunk_count_and_rate_are_bounded() {
        let plan = AudioPlan {
            target_rate_hz: 16_000,
            chunk_ms: 30_000,
        };
        let work = plan_audio(65_000, 48_000, plan.clone()).expect("plan");
        assert_eq!(work.resampled_rate, 16_000);
        assert_eq!(work.chunks.len(), 3);
        assert_eq!(
            work.chunks
                .iter()
                .map(|chunk| (chunk.index, chunk.start_ms, chunk.end_ms))
                .collect::<Vec<_>>(),
            vec![(0, 0, 30_000), (1, 30_000, 60_000), (2, 60_000, 65_000)]
        );

        let low_rate = plan_audio(65_000, 8_000, plan.clone()).expect("plan");
        assert_eq!(low_rate.resampled_rate, 8_000, "never upsample");

        let empty = plan_audio(0, 48_000, plan.clone()).expect("empty clip");
        assert_eq!(empty.resampled_rate, 16_000);
        assert!(empty.chunks.is_empty());

        let too_many = AudioPlan {
            target_rate_hz: 16_000,
            chunk_ms: 1,
        };
        assert_eq!(
            plan_audio(MAX_AUDIO_CHUNKS as u64 + 1, 48_000, too_many)
                .expect_err("chunk cap")
                .code(),
            ErrorCode::LimitExceeded
        );

        for plan in [
            AudioPlan {
                target_rate_hz: 0,
                chunk_ms: 30_000,
            },
            AudioPlan {
                target_rate_hz: 16_000,
                chunk_ms: 0,
            },
            AudioPlan {
                target_rate_hz: MAX_SAMPLE_RATE_HZ + 1,
                chunk_ms: 30_000,
            },
        ] {
            assert!(plan_audio(1_000, 48_000, plan).is_err());
        }
        assert!(plan_audio(1_000, 0, AudioPlan::default()).is_err());
    }

    #[test]
    fn video_sampling_is_bounded_and_ordered() {
        let work = plan_video(
            10_000,
            30,
            VideoPlan {
                fps_sample: 2,
                max_frames: 10,
            },
        )
        .expect("plan");
        assert_eq!(work.sampled, 10);
        assert_eq!(work.frame_times.len(), 10);
        assert_eq!(work.frame_times[0], 0);
        assert!(work.frame_times.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(*work.frame_times.last().expect("frames") < 10_000);

        let exact = plan_video(
            2_000,
            30,
            VideoPlan {
                fps_sample: 10,
                max_frames: 24,
            },
        )
        .expect("plan");
        assert_eq!(exact.sampled, 20);
        assert_eq!(&exact.frame_times[..3], &[0, 100, 200]);

        let clamped = plan_video(
            1_000,
            5,
            VideoPlan {
                fps_sample: 30,
                max_frames: 24,
            },
        )
        .expect("plan");
        assert_eq!(clamped.sampled, 5, "sampling never exceeds the source fps");
        assert_eq!(clamped.frame_times, vec![0, 200, 400, 600, 800]);

        let empty = plan_video(0, 30, VideoPlan::default()).expect("empty video");
        assert_eq!(empty.sampled, 0);
        assert!(empty.frame_times.is_empty());

        for plan in [
            VideoPlan {
                fps_sample: 0,
                max_frames: 24,
            },
            VideoPlan {
                fps_sample: 1,
                max_frames: 0,
            },
            VideoPlan {
                fps_sample: 1,
                max_frames: MAX_VIDEO_FRAMES + 1,
            },
        ] {
            assert!(plan_video(1_000, 30, plan).is_err());
        }
        assert!(plan_video(1_000, 0, VideoPlan::default()).is_err());
        assert!(plan_video(1_000, MAX_SOURCE_FPS + 1, VideoPlan::default()).is_err());
    }

    #[test]
    fn image_preprocessing_runs_every_seam_and_keeps_the_original() {
        let fixture = Fixture::new();
        let bytes = b"image-original";
        let attachment = fixture.attachment("shot.png", Modality::Image, "image/png", bytes);
        let mut plan = PreprocessPlan::for_image(4_000, 2_000);
        plan.image = ImagePlan {
            max_edge: 256,
            tile_edge: 128,
            overlap: 16,
            ocr: true,
        };
        let processors = Processors::none().with_image(&FakeImage).with_ocr(&FakeOcr);

        let result = preprocess(&fixture.originals, &attachment, &plan, &processors)
            .expect("preprocess image");

        assert_eq!(result.original.bytes, bytes.len() as u64);
        assert_eq!(
            fixture
                .originals
                .read_full(&result.original)
                .expect("full re-read"),
            bytes,
            "the original is unchanged after preprocessing"
        );

        let (downscaled, tiles) = match &result.work {
            AppliedWork::Image(work) => (work.downscaled, work.tiles.clone()),
            other => panic!("expected image work, got {other:?}"),
        };
        assert_eq!(downscaled, (256, 128));
        assert_eq!(result.derived.len(), 1 + tiles.len() * 2);
        assert_eq!(result.accounting.tiles, tiles.len() as u32);

        assert_eq!(result.derived[0].kind, DerivedKind::Downscaled);
        assert_eq!(result.derived[0].meta.width, Some(256));
        assert_eq!(result.derived[0].meta.height, Some(128));
        assert!(!result.derived[0].is_untrusted_text());

        for (index, tile) in tiles.iter().enumerate() {
            let tile_item = &result.derived[1 + index * 2];
            assert_eq!(tile_item.kind, DerivedKind::Tile);
            assert_eq!(tile_item.meta.tile, Some(*tile));
            assert_eq!(tile_item.meta.index, index as u32);

            let text_item = &result.derived[2 + index * 2];
            assert_eq!(text_item.kind, DerivedKind::OcrText);
            assert!(text_item.is_untrusted_text());
            assert_eq!(text_item.meta.tile, Some(*tile));
            assert!(text_item.text().expect("ocr text").starts_with("ocr:"));
        }

        assert_eq!(
            result.accounting.ocr_chars,
            result
                .derived
                .iter()
                .filter(|item| item.kind == DerivedKind::OcrText)
                .map(|item| item.meta.chars)
                .sum::<u64>()
        );
        for item in &result.derived {
            assert_eq!(item.meta.bytes, payload_len(&item.bytes_or_text));
            assert_eq!(item.meta.chars, item.bytes_or_text.char_len());
        }

        let json = serde_json::to_string(&result).expect("serialize result");
        assert_eq!(
            serde_json::from_str::<Preprocessed>(&json).expect("deserialize result"),
            result
        );

        let only_ocr = Processors::none().with_ocr(&FakeOcr);
        let fallback = preprocess(&fixture.originals, &attachment, &plan, &only_ocr)
            .expect("ocr without an image seam");
        assert_eq!(fallback.derived.len(), 1);
        assert_eq!(fallback.derived[0].kind, DerivedKind::OcrText);
        assert!(fallback.derived[0].is_untrusted_text());
    }

    #[test]
    fn audio_and_video_preprocessing_record_their_plans() {
        let fixture = Fixture::new();
        let audio = fixture.attachment("clip.wav", Modality::Audio, "audio/wav", b"audio-bytes");
        let audio_plan = PreprocessPlan::for_audio(65_000, 48_000);
        let audio_result = preprocess(
            &fixture.originals,
            &audio,
            &audio_plan,
            &Processors::none().with_transcriber(&FakeTranscriber),
        )
        .expect("preprocess audio");
        match &audio_result.work {
            AppliedWork::Audio(work) => {
                assert_eq!(work.resampled_rate, 16_000);
                assert_eq!(work.chunks.len(), 3);
            }
            other => panic!("expected audio work, got {other:?}"),
        }
        assert_eq!(audio_result.derived.len(), 1);
        assert_eq!(audio_result.derived[0].kind, DerivedKind::Transcript);
        assert!(audio_result.derived[0].is_untrusted_text());
        assert_eq!(
            audio_result.accounting.transcript_chars,
            audio_result.derived[0].meta.chars
        );
        assert_eq!(
            fixture
                .originals
                .read_full(&audio_result.original)
                .expect("audio re-read"),
            b"audio-bytes"
        );

        let video = fixture.attachment("clip.mp4", Modality::Video, "video/mp4", b"video-bytes");
        let mut video_plan = PreprocessPlan::for_video(2_000, 30);
        video_plan.video = VideoPlan {
            fps_sample: 10,
            max_frames: 24,
        };
        let video_result = preprocess(
            &fixture.originals,
            &video,
            &video_plan,
            &Processors::none().with_frames(&FakeFrames),
        )
        .expect("preprocess video");
        match &video_result.work {
            AppliedWork::Video(work) => assert_eq!(work.sampled, 20),
            other => panic!("expected video work, got {other:?}"),
        }
        assert_eq!(video_result.derived.len(), 20);
        assert_eq!(video_result.accounting.frames, 20);
        for (index, item) in video_result.derived.iter().enumerate() {
            assert_eq!(item.kind, DerivedKind::Frame);
            assert_eq!(item.meta.index, index as u32);
            assert_eq!(item.meta.frame_ms, Some(index as u64 * 100));
        }
        assert_eq!(
            fixture
                .originals
                .read_full(&video_result.original)
                .expect("video re-read"),
            b"video-bytes"
        );
    }

    #[test]
    fn text_and_documents_are_stored_without_derived_work() {
        let fixture = Fixture::new();
        let text = fixture.attachment("note.txt", Modality::Text, "text/plain", b"hello");
        let result = preprocess(
            &fixture.originals,
            &text,
            &PreprocessPlan::default(),
            &Processors::none(),
        )
        .expect("preprocess text");
        assert_eq!(result.work, AppliedWork::Skipped);
        assert!(result.derived.is_empty());
        assert_eq!(result.accounting.original_bytes, 5);
        assert_eq!(
            fixture
                .originals
                .read_full(&result.original)
                .expect("text re-read"),
            b"hello"
        );

        let document =
            fixture.attachment("doc.pdf", Modality::Document, "application/pdf", b"%PDF");
        let result = preprocess(
            &fixture.originals,
            &document,
            &PreprocessPlan::default(),
            &Processors::none(),
        )
        .expect("preprocess document");
        assert_eq!(result.work, AppliedWork::Skipped);
        assert!(result.derived.is_empty());
    }

    #[test]
    fn geometry_and_processor_failures_are_rejected() {
        let fixture = Fixture::new();
        let image = fixture.attachment("shot.png", Modality::Image, "image/png", b"image");

        let err = preprocess(
            &fixture.originals,
            &image,
            &PreprocessPlan::default(),
            &Processors::none(),
        )
        .expect_err("image needs geometry");
        assert_eq!(err.code(), ErrorCode::InvalidInput);

        let wrong = PreprocessPlan::for_audio(1_000, 48_000);
        let err = preprocess(&fixture.originals, &image, &wrong, &Processors::none())
            .expect_err("non-image geometry");
        assert_eq!(err.code(), ErrorCode::InvalidInput);

        let text = fixture.attachment("note.txt", Modality::Text, "text/plain", b"hello");
        let skipped = preprocess(
            &fixture.originals,
            &text,
            &PreprocessPlan::for_image(10, 10),
            &Processors::none(),
        )
        .expect("text is stored only");
        assert_eq!(skipped.work, AppliedWork::Skipped);
        assert!(skipped.derived.is_empty());

        let video = fixture.attachment("clip.mp4", Modality::Video, "video/mp4", b"video");
        let mut plan = PreprocessPlan::for_video(2_000, 30);
        plan.video = VideoPlan {
            fps_sample: 10,
            max_frames: 24,
        };
        let err = preprocess(
            &fixture.originals,
            &video,
            &plan,
            &Processors::none().with_frames(&ShortFrames),
        )
        .expect_err("frame count mismatch");
        assert_eq!(err.code(), ErrorCode::InvalidInput);
    }

    #[test]
    fn path_url_and_size_caps_are_enforced() {
        let fixture = Fixture::new();

        let err = fixture
            .originals
            .put_with_cap("image/png", b"12345", 4)
            .expect_err("store cap");
        assert_eq!(err.code(), ErrorCode::LimitExceeded);

        let url = Attachment {
            id: "att-url".to_string(),
            kind: Modality::Image,
            source: Source::Url {
                url: "https://example.com/shot.png".to_string(),
            },
            mime: "image/png".to_string(),
            bytes: 0,
            name: None,
        };
        let err = preprocess(
            &fixture.originals,
            &url,
            &PreprocessPlan::for_image(10, 10),
            &Processors::none(),
        )
        .expect_err("urls are never fetched");
        assert_eq!(err.code(), ErrorCode::Unsupported);

        let missing = Attachment {
            id: "att-missing".to_string(),
            kind: Modality::Image,
            source: Source::Path {
                path: fixture.temp.path().join("missing.png"),
            },
            mime: "image/png".to_string(),
            bytes: 10,
            name: None,
        };
        let err = preprocess(
            &fixture.originals,
            &missing,
            &PreprocessPlan::for_image(10, 10),
            &Processors::none(),
        )
        .expect_err("missing path");
        assert_eq!(err.code(), ErrorCode::NotFound);

        let image = fixture.attachment("shot.png", Modality::Image, "image/png", b"image");
        let err = preprocess(
            &fixture.originals,
            &image,
            &PreprocessPlan::for_image(10, 10),
            &Processors::none()
                .with_image(&FakeImage)
                .with_ocr(&VerboseOcr),
        )
        .expect_err("ocr text cap");
        assert_eq!(err.code(), ErrorCode::LimitExceeded);
    }

    #[test]
    fn plans_and_work_round_trip_through_serde() {
        let plan = PreprocessPlan {
            image: ImagePlan {
                max_edge: 512,
                tile_edge: 128,
                overlap: 16,
                ocr: true,
            },
            audio: AudioPlan::default(),
            video: VideoPlan::default(),
            geometry: Some(SourceGeometry::Image {
                width: 1_024,
                height: 512,
            }),
        };
        let json = serde_json::to_string(&plan).expect("serialize plan");
        assert_eq!(
            serde_json::from_str::<PreprocessPlan>(&json).expect("deserialize plan"),
            plan
        );

        let work = plan_image(1_024, 512, plan.image).expect("plan");
        let json = serde_json::to_string(&work).expect("serialize work");
        assert_eq!(
            serde_json::from_str::<ImageWork>(&json).expect("deserialize work"),
            work
        );

        let audio = plan_audio(65_000, 48_000, AudioPlan::default()).expect("audio");
        let json = serde_json::to_string(&audio).expect("serialize audio");
        assert_eq!(
            serde_json::from_str::<AudioWork>(&json).expect("deserialize audio"),
            audio
        );

        let video = plan_video(2_000, 30, VideoPlan::default()).expect("video");
        let json = serde_json::to_string(&video).expect("serialize video");
        assert_eq!(
            serde_json::from_str::<VideoWork>(&json).expect("deserialize video"),
            video
        );
    }

    #[test]
    fn no_network_code_path_exists() {
        let source = include_str!("preprocess.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("preprocess.rs has a production half");
        for needle in [
            "std::net",
            "TcpStream",
            "UdpSocket",
            "reqwest",
            "hyper",
            "ureq",
            "isahc",
            "curl",
            "Command::new",
            "fn fetch",
            "fn download",
        ] {
            assert!(
                !production.contains(needle),
                "`{needle}` must not appear in the preprocess module; it never fetches or runs a process"
            );
        }
    }
}
