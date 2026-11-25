//! Per-device append-only usage ledger and union merge (USG-01, USG-02, USG-08).
//!
//! Each device writes usage events to its own JSONL file and never rewrites
//! them. Syncing devices unions the files by event id: identical records are
//! duplicates, differing records with the same id are reported as conflicts
//! and the first one wins. Attribution rolls child and subagent usage into the
//! parent's totals. There is intentionally no update or delete API; compaction
//! is a later task.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use zero_types::error::{ErrorCode, Result, ZeroError};

/// Subagent share is expressed in basis points, so 10 000 is "all of it".
pub const MAX_SHARE_BPS: u32 = 10_000;

const CSV_HEADER: &str = "id,device,session,model,provider,tool,input_tokens,\
output_tokens,cache_read_tokens,cache_write_tokens,cost_micros,wall_ms,retries,\
parent_id,subagent_share_bps,at_ms";

/// One unit of billed work.
///
/// The id is derived from `(device, session, at_ms, model, parent, nonce)` so
/// two devices that observe the same work derive the same id and merge into
/// one record. Counts are unsigned, so a negative value cannot be represented.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageEvent {
    pub id: String,
    pub device: String,
    pub session: String,
    pub model: String,
    pub provider: String,
    pub tool: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub cost_micros: u64,
    pub wall_ms: u64,
    pub retries: u32,
    pub parent_id: Option<String>,
    pub subagent_share_bps: u32,
    pub at_ms: i64,
}

impl UsageEvent {
    /// Create an event with a content-derived id and zeroed counters.
    ///
    /// `parent_id` is part of the id, so a child must pass it here rather than
    /// mutating the field afterwards.
    pub fn new(
        device: impl Into<String>,
        session: impl Into<String>,
        model: impl Into<String>,
        provider: impl Into<String>,
        at_ms: i64,
        parent_id: Option<&str>,
        nonce: &str,
    ) -> Self {
        let device = device.into();
        let session = session.into();
        let model = model.into();
        let provider = provider.into();
        let id = event_id(&device, &session, at_ms, &model, parent_id, nonce);
        Self {
            id,
            device,
            session,
            model,
            provider,
            tool: None,
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            cost_micros: 0,
            wall_ms: 0,
            retries: 0,
            parent_id: parent_id.map(str::to_owned),
            subagent_share_bps: 0,
            at_ms,
        }
    }

    pub fn with_tool(mut self, tool: impl Into<String>) -> Self {
        self.tool = Some(tool.into());
        self
    }

    pub fn with_usage(mut self, input: u64, output: u64, cache_read: u64, cache_write: u64) -> Self {
        self.input_tokens = input;
        self.output_tokens = output;
        self.cache_read_tokens = cache_read;
        self.cache_write_tokens = cache_write;
        self
    }

    pub fn with_cost(mut self, cost_micros: u64) -> Self {
        self.cost_micros = cost_micros;
        self
    }

    pub fn with_wall_ms(mut self, wall_ms: u64) -> Self {
        self.wall_ms = wall_ms;
        self
    }

    pub fn with_retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    pub fn with_subagent_share(mut self, bps: u32) -> Self {
        self.subagent_share_bps = bps;
        self
    }

    /// Structural validation. Parent existence cannot be checked here because
    /// a single event file may not contain the parent yet; see [`merge`] and
    /// [`attribute`].
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(ZeroError::new(ErrorCode::InvalidInput, "usage event id must not be empty"));
        }
        for (field, value) in [
            ("device", self.device.as_str()),
            ("session", self.session.as_str()),
            ("model", self.model.as_str()),
            ("provider", self.provider.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!("usage event `{}`: {field} must not be empty", self.id),
                ));
            }
        }
        if self.subagent_share_bps > MAX_SHARE_BPS {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                format!(
                    "usage event `{}`: subagent_share_bps {} exceeds {MAX_SHARE_BPS}",
                    self.id, self.subagent_share_bps
                ),
            ));
        }
        if let Some(parent) = &self.parent_id {
            if parent.trim().is_empty() {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!("usage event `{}`: parent_id must not be empty when set", self.id),
                ));
            }
            if *parent == self.id {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!("usage event `{}` cannot be its own parent", self.id),
                ));
            }
        }
        Ok(())
    }
}

/// Derive the stable id for one observed unit of work.
///
/// Components are length-prefixed before hashing so distinct tuples cannot
/// collide by concatenation.
pub fn event_id(
    device: &str,
    session: &str,
    at_ms: i64,
    model: &str,
    parent_id: Option<&str>,
    nonce: &str,
) -> String {
    let at = at_ms.to_string();
    let parts = [device, session, at.as_str(), model, parent_id.unwrap_or("-"), nonce];
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    format!("ue_{}", hasher.finalize().to_hex())
}

/// One ledger file for one device.
///
/// The file is opened in append mode and every record is one JSON object plus
/// a newline. Appends within a process are serialized by a global lock so two
/// handles cannot interleave a half line; across processes the append-mode
/// single write is the guarantee. There is no API that rewrites a record.
#[derive(Debug)]
pub struct UsageLedger {
    path: PathBuf,
    file: File,
}

/// Result of reading a ledger: valid events plus the count of lines skipped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadReport {
    pub events: Vec<UsageEvent>,
    /// Complete lines that were not valid usage events or failed validation.
    pub malformed: usize,
    /// True when the last line had no terminating newline and was skipped.
    pub torn_tail: bool,
}

impl UsageLedger {
    /// Open a ledger, creating it and its parent directory when missing.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with(path.as_ref(), false)
    }

    /// Create a new ledger. Fails with `already_exists` when the path exists.
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with(path.as_ref(), true)
    }

    fn open_with(path: &Path, create_new: bool) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut options = OpenOptions::new();
        options.append(true).read(true);
        if create_new {
            options.create_new(true);
        } else {
            options.create(true);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        restrict_permissions(path)?;
        Ok(Self { path: path.to_path_buf(), file })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one event. The whole line is written and flushed before return.
    ///
    /// Validation is structural only; an unresolvable parent is reported at
    /// merge or attribution time.
    pub fn append(&self, event: &UsageEvent) -> Result<()> {
        event.validate()?;
        let mut line = serde_json::to_vec(event)?;
        line.push(b'\n');
        let _guard = APPEND_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut file = &self.file;
        file.write_all(&line)?;
        file.flush()?;
        file.sync_data()?;
        Ok(())
    }

    /// Read valid events, counting malformed complete lines instead of failing.
    ///
    /// A file that is not JSONL at all (invalid UTF-8, a JSON array, or text
    /// lines) returns `zero.fnd.corrupt`.
    pub fn scan(&self) -> Result<ReadReport> {
        read_report(&self.path)
    }

    /// Convenience form of [`Self::scan`] that returns only valid events.
    pub fn read_all(&self) -> Result<Vec<UsageEvent>> {
        Ok(self.scan()?.events)
    }
}

static APPEND_LOCK: Mutex<()> = Mutex::new(());

fn restrict_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Read a ledger file. A missing file is an empty report, not an error.
pub fn read_report(path: impl AsRef<Path>) -> Result<ReadReport> {
    let path = path.as_ref();
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ReadReport::default())
        }
        Err(error) => return Err(error.into()),
    };
    parse_report(path, &bytes)
}

fn parse_report(path: &Path, bytes: &[u8]) -> Result<ReadReport> {
    if bytes.is_empty() {
        return Ok(ReadReport::default());
    }
    let text = std::str::from_utf8(bytes).map_err(|error| {
        ZeroError::new(
            ErrorCode::Corrupt,
            format!("{}: usage ledger is not UTF-8 JSONL: {error}", path.display()),
        )
    })?;
    if text.trim_start().starts_with('[') {
        return Err(ZeroError::new(
            ErrorCode::Corrupt,
            format!("{}: usage ledger is a JSON array, not JSONL", path.display()),
        ));
    }

    let mut report = ReadReport::default();
    let complete = if text.ends_with('\n') {
        text
    } else {
        report.torn_tail = true;
        match text.rfind('\n') {
            Some(index) => &text[..=index],
            None => "",
        }
    };

    let mut non_empty = 0usize;
    let mut object_like = 0usize;
    for line in complete.split('\n') {
        if line.trim().is_empty() {
            continue;
        }
        non_empty += 1;
        if line.trim_start().starts_with('{') {
            object_like += 1;
        }
        match serde_json::from_str::<UsageEvent>(line) {
            Ok(event) if event.validate().is_ok() => report.events.push(event),
            Ok(_) | Err(_) => report.malformed += 1,
        }
    }

    // Individual bad lines are skipped, but a file whose lines are not even
    // object-shaped (pretty-printed JSON, CSV, log text) is not a ledger.
    if report.events.is_empty() && report.malformed > 0 && object_like < non_empty {
        return Err(ZeroError::new(
            ErrorCode::Corrupt,
            format!("{}: not a JSONL usage ledger", path.display()),
        ));
    }
    Ok(report)
}

/// A same-id record whose payload differs from the one already kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeConflict {
    pub id: String,
    pub kept: UsageEvent,
    pub rejected: UsageEvent,
}

/// Union of two ledger slices.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeResult {
    /// Deduplicated union, sorted by `(at_ms, device, id)`.
    pub events: Vec<UsageEvent>,
    /// Same id and byte-identical payload.
    pub duplicates: usize,
    /// Same id with a different payload; the first occurrence is kept.
    pub conflicts: Vec<MergeConflict>,
    /// Parent ids referenced by the union but absent from it.
    pub unresolved_parents: Vec<String>,
}

/// Union two device ledgers by id.
///
/// The result is sorted by `(at_ms, device, id)` so identical inputs produce
/// identical output. Conflicts are recorded, never silently overwritten.
pub fn merge(a: &[UsageEvent], b: &[UsageEvent]) -> MergeResult {
    let mut result = MergeResult::default();
    let mut positions: HashMap<&str, usize> = HashMap::new();
    for event in a.iter().chain(b.iter()) {
        match positions.get(event.id.as_str()) {
            Some(&position) => {
                let kept = &result.events[position];
                if kept == event {
                    result.duplicates += 1;
                } else {
                    result.conflicts.push(MergeConflict {
                        id: event.id.clone(),
                        kept: kept.clone(),
                        rejected: event.clone(),
                    });
                }
            }
            None => {
                positions.insert(event.id.as_str(), result.events.len());
                result.events.push(event.clone());
            }
        }
    }
    result.events.sort_by_key(|event| (event.at_ms, event.device.clone(), event.id.clone()));
    result.unresolved_parents = unresolved_parents(&result.events);
    result
}

/// Parent ids referenced by `events` that are not present in `events`.
pub fn unresolved_parents(events: &[UsageEvent]) -> Vec<String> {
    let ids: HashSet<&str> = events.iter().map(|event| event.id.as_str()).collect();
    let mut missing = BTreeSet::new();
    for event in events {
        if let Some(parent) = &event.parent_id {
            if !ids.contains(parent.as_str()) {
                missing.insert(parent.clone());
            }
        }
    }
    missing.into_iter().collect()
}

/// Fail when any child references a parent outside `events`.
///
/// [`merge`] reports the same condition in `unresolved_parents` instead of
/// failing, because a sync may deliver a child device's file before the
/// parent's. Call this when a complete set is required.
pub fn validate_parents(events: &[UsageEvent]) -> Result<()> {
    let missing = unresolved_parents(events);
    if missing.is_empty() {
        return Ok(());
    }
    Err(ZeroError::new(
        ErrorCode::NotFound,
        format!("usage events reference missing parents: {}", missing.join(", ")),
    ))
}

/// Report from [`merge_files`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeReport {
    pub events: usize,
    pub duplicates: usize,
    pub conflicts: Vec<MergeConflict>,
    pub malformed: usize,
    pub unresolved_parents: Vec<String>,
    pub bytes_written: u64,
}

/// Merge ledger files into `out`, replacing it atomically.
///
/// Running the same inputs twice writes byte-identical output. Missing input
/// files are treated as empty. The output is mode 0600 on Unix.
pub fn merge_files<P: AsRef<Path>>(paths: &[P], out: impl AsRef<Path>) -> Result<MergeReport> {
    let mut report = MergeReport::default();
    let mut accumulated: Vec<UsageEvent> = Vec::new();
    for path in paths {
        let read = read_report(path)?;
        report.malformed += read.malformed;
        let merged = merge(&accumulated, &read.events);
        report.duplicates += merged.duplicates;
        report.conflicts.extend(merged.conflicts);
        accumulated = merged.events;
    }

    let mut bytes = Vec::new();
    for event in &accumulated {
        serde_json::to_writer(&mut bytes, event)?;
        bytes.push(b'\n');
    }
    write_atomic(out.as_ref(), &bytes)?;

    report.events = accumulated.len();
    report.unresolved_parents = unresolved_parents(&accumulated);
    report.bytes_written = bytes.len() as u64;
    Ok(report)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "usage.jsonl".to_owned());
    let temporary = parent.join(format!(".{name}.tmp-{}-{counter}", std::process::id()));

    let mut file = OpenOptions::new().write(true).create_new(true).open(&temporary)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.into());
    }
    Ok(())
}

/// Summed usage. Additions saturate rather than wrap.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub cost_micros: u64,
    pub wall_ms: u64,
    pub retries: u64,
    pub events: u64,
}

impl Totals {
    pub fn of(event: &UsageEvent) -> Self {
        let mut totals = Self::default();
        totals.add_event(event);
        totals
    }

    pub fn add_event(&mut self, event: &UsageEvent) {
        self.input = self.input.saturating_add(event.input_tokens);
        self.output = self.output.saturating_add(event.output_tokens);
        self.cache_read = self.cache_read.saturating_add(event.cache_read_tokens);
        self.cache_write = self.cache_write.saturating_add(event.cache_write_tokens);
        self.cost_micros = self.cost_micros.saturating_add(event.cost_micros);
        self.wall_ms = self.wall_ms.saturating_add(event.wall_ms);
        self.retries = self.retries.saturating_add(u64::from(event.retries));
        self.events = self.events.saturating_add(1);
    }

    pub fn add(&mut self, other: &Self) {
        self.input = self.input.saturating_add(other.input);
        self.output = self.output.saturating_add(other.output);
        self.cache_read = self.cache_read.saturating_add(other.cache_read);
        self.cache_write = self.cache_write.saturating_add(other.cache_write);
        self.cost_micros = self.cost_micros.saturating_add(other.cost_micros);
        self.wall_ms = self.wall_ms.saturating_add(other.wall_ms);
        self.retries = self.retries.saturating_add(other.retries);
        self.events = self.events.saturating_add(other.events);
    }

    fn subtract(&mut self, other: &Self) {
        self.input = self.input.saturating_sub(other.input);
        self.output = self.output.saturating_sub(other.output);
        self.cache_read = self.cache_read.saturating_sub(other.cache_read);
        self.cache_write = self.cache_write.saturating_sub(other.cache_write);
        self.cost_micros = self.cost_micros.saturating_sub(other.cost_micros);
        self.wall_ms = self.wall_ms.saturating_sub(other.wall_ms);
        self.retries = self.retries.saturating_sub(other.retries);
        self.events = self.events.saturating_sub(other.events);
    }
}

/// Totals over every event, including children. For a tree view use
/// [`attribute`] so descendants are not counted twice.
pub fn totals(events: &[UsageEvent]) -> Totals {
    let mut totals = Totals::default();
    for event in events {
        totals.add_event(event);
    }
    totals
}

/// Totals grouped by a caller-chosen key, for example `|e| e.session.clone()`.
pub fn totals_by<K, F>(events: &[UsageEvent], key: F) -> BTreeMap<K, Totals>
where
    K: Ord,
    F: Fn(&UsageEvent) -> K,
{
    let mut grouped: BTreeMap<K, Totals> = BTreeMap::new();
    for event in events {
        grouped.entry(key(event)).or_default().add_event(event);
    }
    grouped
}

/// `part * 10 000 / whole`, clamped to `0..=10 000`.
///
/// When `whole` is zero but `part` is not, the share is treated as fully
/// attributed (`10 000`) because there is no parent cost to divide by.
pub fn share_bps(part: u64, whole: u64) -> u32 {
    if part == 0 {
        return 0;
    }
    if whole == 0 {
        return MAX_SHARE_BPS;
    }
    let scaled = u128::from(part) * u128::from(MAX_SHARE_BPS) / u128::from(whole);
    scaled.min(u128::from(MAX_SHARE_BPS)) as u32
}

/// An event with its own usage separated from its descendants' usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributedEvent {
    pub event: UsageEvent,
    /// Usage recorded on this event itself.
    pub own: Totals,
    /// Usage of every descendant, rolled up.
    pub subagent: Totals,
    /// `own + subagent`, so a root's total covers its whole subtree.
    pub total: Totals,
    /// `subagent.cost * 10 000 / own.cost`, clamped to `0..=10 000`.
    pub subagent_share_bps: u32,
    /// Direct children, in input order.
    pub children: Vec<String>,
}

/// Roll child and subagent usage into each parent.
///
/// Every event in `events` is returned. An id referenced as a parent must be
/// present (otherwise `zero.fnd.not_found`) and cycles are rejected
/// (`zero.fnd.corrupt`). Duplicate ids are rejected because attribution over
/// an unmerged ledger is ambiguous.
pub fn attribute(events: &[UsageEvent]) -> Result<Vec<AttributedEvent>> {
    let mut index: HashMap<&str, usize> = HashMap::new();
    for (position, event) in events.iter().enumerate() {
        event.validate()?;
        if index.insert(event.id.as_str(), position).is_some() {
            return Err(ZeroError::new(
                ErrorCode::Corrupt,
                format!("duplicate usage event id `{}`; merge before attributing", event.id),
            ));
        }
    }

    let mut children: Vec<Vec<usize>> = vec![Vec::new(); events.len()];
    for (position, event) in events.iter().enumerate() {
        let Some(parent) = &event.parent_id else {
            continue;
        };
        let Some(&parent_position) = index.get(parent.as_str()) else {
            return Err(ZeroError::new(
                ErrorCode::NotFound,
                format!("usage event `{}` references missing parent `{parent}`", event.id),
            ));
        };
        if parent_position == position {
            return Err(ZeroError::new(
                ErrorCode::Corrupt,
                format!("usage event `{}` is its own parent", event.id),
            ));
        }
        children[parent_position].push(position);
    }

    let mut state = vec![0u8; events.len()];
    let mut memo: Vec<Option<Totals>> = vec![None; events.len()];
    for position in 0..events.len() {
        subtree_totals(position, events, &children, &mut state, &mut memo)?;
    }

    let mut attributed = Vec::with_capacity(events.len());
    for (position, event) in events.iter().enumerate() {
        let own = Totals::of(event);
        let total = memo[position].unwrap_or(own);
        let mut subagent = total;
        subagent.subtract(&own);
        attributed.push(AttributedEvent {
            event: event.clone(),
            own,
            subagent,
            total,
            subagent_share_bps: share_bps(subagent.cost_micros, own.cost_micros),
            children: children[position].iter().map(|&child| events[child].id.clone()).collect(),
        });
    }
    Ok(attributed)
}

fn subtree_totals(
    position: usize,
    events: &[UsageEvent],
    children: &[Vec<usize>],
    state: &mut [u8],
    memo: &mut [Option<Totals>],
) -> Result<Totals> {
    if let Some(total) = memo[position] {
        return Ok(total);
    }
    if state[position] == 1 {
        return Err(ZeroError::new(
            ErrorCode::Corrupt,
            format!("usage attribution cycle at event `{}`", events[position].id),
        ));
    }
    state[position] = 1;
    let mut total = Totals::of(&events[position]);
    for &child in &children[position] {
        let child_total = subtree_totals(child, events, children, state, memo)?;
        total.add(&child_total);
    }
    state[position] = 2;
    memo[position] = Some(total);
    Ok(total)
}

/// JSON array of events. No file is written and no telemetry is emitted.
pub fn export_json(events: &[UsageEvent]) -> Result<String> {
    Ok(serde_json::to_string_pretty(events)?)
}

/// CSV with a fixed header. Empty optional fields are empty cells.
pub fn export_csv(events: &[UsageEvent]) -> String {
    let mut out = String::with_capacity(CSV_HEADER.len() + 1 + events.len() * 160);
    out.push_str(CSV_HEADER);
    out.push('\n');
    for event in events {
        let fields = [
            event.id.clone(),
            event.device.clone(),
            event.session.clone(),
            event.model.clone(),
            event.provider.clone(),
            event.tool.clone().unwrap_or_default(),
            event.input_tokens.to_string(),
            event.output_tokens.to_string(),
            event.cache_read_tokens.to_string(),
            event.cache_write_tokens.to_string(),
            event.cost_micros.to_string(),
            event.wall_ms.to_string(),
            event.retries.to_string(),
            event.parent_id.clone().unwrap_or_default(),
            event.subagent_share_bps.to_string(),
            event.at_ms.to_string(),
        ];
        out.push_str(&fields.iter().map(|field| csv_field(field)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

fn csv_field(value: &str) -> String {
    if value.chars().any(|c| matches!(c, ',' | '"' | '\n' | '\r')) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(device: &str, session: &str, at_ms: i64, nonce: &str) -> UsageEvent {
        UsageEvent::new(device, session, "gpt-5", "openai", at_ms, None, nonce)
            .with_usage(10, 5, 2, 1)
            .with_cost(100)
            .with_wall_ms(50)
            .with_retries(1)
    }

    #[test]
    fn append_and_read_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("usage.jsonl");
        let ledger = UsageLedger::open(&path).unwrap();
        let events = vec![
            event("dev-a", "s1", 1, "n1"),
            event("dev-a", "s1", 2, "n2"),
            event("dev-a", "s2", 3, "n3").with_tool("shell"),
        ];
        for event in &events {
            ledger.append(event).unwrap();
        }
        let report = ledger.scan().unwrap();
        assert_eq!(report.events, events);
        assert_eq!(report.malformed, 0);
        assert!(!report.torn_tail);
        assert_eq!(UsageLedger::open(&path).unwrap().read_all().unwrap(), events);
    }

    #[test]
    fn malformed_line_is_counted_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("usage.jsonl");
        let first = event("dev-a", "s1", 1, "n1");
        let second = event("dev-a", "s1", 2, "n2");
        let body = format!(
            "{}\nnot json\n{}\n",
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
        std::fs::write(&path, body).unwrap();

        let report = UsageLedger::open(&path).unwrap().scan().unwrap();
        assert_eq!(report.events, vec![first, second]);
        assert_eq!(report.malformed, 1);
    }

    #[test]
    fn a_file_that_is_not_jsonl_is_a_typed_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("usage.jsonl");
        std::fs::write(&path, b"[\n{\"id\":\"x\"}\n]\n").unwrap();
        let error = UsageLedger::open(&path).unwrap().read_all().unwrap_err();
        assert_eq!(error.code(), ErrorCode::Corrupt);

        std::fs::write(&path, b"device,model\ndev-a,gpt\n").unwrap();
        let error = UsageLedger::open(&path).unwrap().read_all().unwrap_err();
        assert_eq!(error.code(), ErrorCode::Corrupt);
    }

    #[test]
    fn duplicate_id_and_payload_is_counted_once() {
        let one = event("dev-a", "s1", 1, "n1");
        let merged = merge(std::slice::from_ref(&one), std::slice::from_ref(&one));
        assert_eq!(merged.events, vec![one]);
        assert_eq!(merged.duplicates, 1);
        assert!(merged.conflicts.is_empty());
    }

    #[test]
    fn conflicting_payload_is_recorded_and_the_first_wins() {
        let kept = event("dev-a", "s1", 1, "n1");
        let mut changed = kept.clone();
        changed.cost_micros += 1;
        let merged = merge(std::slice::from_ref(&kept), std::slice::from_ref(&changed));
        assert_eq!(merged.events.len(), 1);
        assert_eq!(merged.events[0], kept);
        assert_eq!(merged.duplicates, 0);
        assert_eq!(merged.conflicts.len(), 1);
        assert_eq!(merged.conflicts[0].id, kept.id);
        assert_eq!(merged.conflicts[0].kept, kept);
        assert_eq!(merged.conflicts[0].rejected, changed);
    }

    #[test]
    fn two_devices_union_without_conflict_and_totals_match() {
        let a1 = event("dev-a", "s1", 3, "a1");
        let a2 = event("dev-b", "s1", 1, "b1");
        let b1 = event("dev-b", "s1", 2, "b2");
        let merged = merge(&[a1.clone(), a2.clone()], std::slice::from_ref(&b1));
        assert_eq!(merged.events.len(), 3);
        assert_eq!(merged.duplicates, 0);
        assert!(merged.conflicts.is_empty(), "union must not conflict");
        assert_eq!(
            merged.events.iter().map(|event| event.at_ms).collect::<Vec<_>>(),
            vec![1, 2, 3],
            "sorted by (at_ms, device, id)"
        );
        assert_eq!(totals(&merged.events), totals(&[a1, a2, b1]));
    }

    #[test]
    fn remerging_files_is_idempotent_and_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let a_path = dir.path().join("a.jsonl");
        let b_path = dir.path().join("b.jsonl");
        let out = dir.path().join("out.jsonl");
        let a = UsageLedger::open(&a_path).unwrap();
        a.append(&event("dev-a", "s1", 1, "a1")).unwrap();
        a.append(&event("dev-a", "s1", 2, "a2")).unwrap();
        let b = UsageLedger::open(&b_path).unwrap();
        b.append(&event("dev-b", "s1", 1, "b1")).unwrap();

        let inputs = [a_path.as_path(), b_path.as_path()];
        let first = merge_files(&inputs, &out).unwrap();
        let first_bytes = std::fs::read(&out).unwrap();
        let second = merge_files(&inputs, &out).unwrap();
        let second_bytes = std::fs::read(&out).unwrap();

        assert_eq!(first.events, 3);
        assert_eq!(first.duplicates, 0);
        assert!(first.conflicts.is_empty());
        assert_eq!(first_bytes, second_bytes);
        assert_eq!(first.events, second.events);
        assert_eq!(first.bytes_written, second.bytes_written);
        assert_eq!(std::fs::read_to_string(&out).unwrap().lines().count(), 3);
    }

    #[test]
    fn unresolved_parents_are_reported_but_not_fatal_to_merge() {
        let child = UsageEvent::new("dev-a", "s1", "gpt-5", "openai", 1, Some("missing"), "c1");
        let merged = merge(&[], std::slice::from_ref(&child));
        assert_eq!(merged.events.len(), 1);
        assert_eq!(merged.unresolved_parents, vec!["missing".to_string()]);
        assert_eq!(validate_parents(&merged.events).unwrap_err().code(), ErrorCode::NotFound);
    }

    #[test]
    fn orphan_parent_is_a_typed_error_during_attribution() {
        let child = UsageEvent::new("dev-a", "s1", "gpt-5", "openai", 1, Some("missing"), "c1");
        let error = attribute(&[child]).unwrap_err();
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert!(error.message().contains("missing"));
    }

    #[test]
    fn attribution_rolls_children_into_the_parent_share() {
        let parent = UsageEvent::new("dev-a", "s1", "gpt-5", "openai", 1, None, "p")
            .with_usage(100, 50, 10, 5)
            .with_cost(1_000);
        let first_child = UsageEvent::new("dev-a", "s1", "gpt-5", "openai", 2, Some(&parent.id), "c1")
            .with_usage(10, 5, 0, 0)
            .with_cost(200);
        let second_child = UsageEvent::new("dev-a", "s1", "gpt-5", "openai", 3, Some(&parent.id), "c2")
            .with_usage(20, 5, 0, 0)
            .with_cost(300);
        let grandchild =
            UsageEvent::new("dev-a", "s1", "gpt-5", "openai", 4, Some(&first_child.id), "g1")
                .with_usage(1, 1, 0, 0)
                .with_cost(100);

        let attributed = attribute(&[parent.clone(), first_child, second_child, grandchild]).unwrap();
        let root = &attributed[0];
        assert_eq!(root.event.id, parent.id);
        assert_eq!(root.own.input, 100);
        assert_eq!(root.own.events, 1);
        assert_eq!(root.subagent.input, 31);
        assert_eq!(root.subagent.cost_micros, 600);
        assert_eq!(root.subagent.events, 3);
        assert_eq!(root.total.input, 131);
        assert_eq!(root.total.events, 4);
        assert_eq!(root.subagent_share_bps, 6_000);
        assert_eq!(root.children.len(), 2);

        // A nested child still sees its own subtree.
        assert_eq!(attributed[1].subagent.cost_micros, 100);
        assert_eq!(attributed[1].total.cost_micros, 300);
        assert_eq!(attributed[3].subagent_share_bps, 0);
    }

    #[test]
    fn attribution_rejects_cycles_and_duplicate_ids() {
        let mut a = UsageEvent::new("dev-a", "s1", "gpt-5", "openai", 1, None, "a");
        let mut b = UsageEvent::new("dev-a", "s1", "gpt-5", "openai", 2, None, "b");
        a.parent_id = Some(b.id.clone());
        b.parent_id = Some(a.id.clone());
        let error = attribute(&[a.clone(), b.clone()]).unwrap_err();
        assert_eq!(error.code(), ErrorCode::Corrupt);

        let error = attribute(&[a.clone(), a]).unwrap_err();
        assert_eq!(error.code(), ErrorCode::Corrupt);
    }

    #[test]
    fn totals_and_totals_by_group() {
        let a = event("dev-a", "s1", 1, "a1");
        let b = event("dev-b", "s1", 2, "b1");
        let c = event("dev-a", "s2", 3, "a2");
        let all = [a, b.clone(), c];
        let summed = totals(&all);
        assert_eq!(summed.input, 30);
        assert_eq!(summed.output, 15);
        assert_eq!(summed.cache_read, 6);
        assert_eq!(summed.cache_write, 3);
        assert_eq!(summed.cost_micros, 300);
        assert_eq!(summed.wall_ms, 150);
        assert_eq!(summed.retries, 3);
        assert_eq!(summed.events, 3);

        let by_session = totals_by(&all, |event| event.session.clone());
        assert_eq!(by_session["s1"].input, 20);
        assert_eq!(by_session["s2"].input, 10);
        let by_device = totals_by(&all, |event| event.device.clone());
        assert_eq!(by_device["dev-a"].events, 2);
        assert_eq!(by_device["dev-b"].events, 1);
    }

    #[test]
    fn export_shapes_are_stable() {
        let one = event("dev-a", "s1", 1, "n1").with_tool("shell");
        let two = event("dev-b", "s2", 2, "n2");
        let json = export_json(&[one.clone(), two.clone()]).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.as_array().unwrap().len(), 2);
        assert_eq!(parsed[0]["id"], one.id);
        assert_eq!(parsed[0]["tool"], "shell");

        let csv = export_csv(&[one, two]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], CSV_HEADER);
        assert!(lines[1].contains("dev-a,s1,gpt-5,openai,shell"));
        assert!(csv.ends_with('\n'));
    }

    #[test]
    fn csv_escapes_commas_and_quotes() {
        let quoted = UsageEvent::new("dev,a", "s1", "gpt-5", "openai", 1, None, "n1")
            .with_tool("a\"b");
        let csv = export_csv(&[quoted]);
        assert!(csv.contains("\"dev,a\""));
        assert!(csv.contains("\"a\"\"b\""));
    }

    #[test]
    fn validation_rejects_empty_fields_and_bad_share() {
        let empty = UsageEvent::new("", "s1", "gpt-5", "openai", 1, None, "n");
        assert_eq!(empty.validate().unwrap_err().code(), ErrorCode::InvalidInput);
        let bad_share = event("dev-a", "s1", 1, "n").with_subagent_share(MAX_SHARE_BPS + 1);
        assert_eq!(bad_share.validate().unwrap_err().code(), ErrorCode::InvalidInput);
        let empty_parent = UsageEvent::new("dev-a", "s1", "gpt-5", "openai", 1, Some(""), "n");
        assert_eq!(empty_parent.validate().unwrap_err().code(), ErrorCode::InvalidInput);
    }

    #[test]
    fn create_refuses_to_reuse_an_existing_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("usage.jsonl");
        UsageLedger::create(&path).unwrap();
        let error = UsageLedger::create(&path).unwrap_err();
        assert_eq!(error.code(), ErrorCode::AlreadyExists);
    }

    #[test]
    fn concurrent_appends_from_two_handles_produce_complete_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("usage.jsonl");
        let first = UsageLedger::open(&path).unwrap();
        let second = UsageLedger::open(&path).unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for index in 0..25 {
                    let nonce = format!("first-{index}");
                    first.append(&event("dev-a", "s1", index, &nonce)).unwrap();
                }
            });
            scope.spawn(|| {
                for index in 0..25 {
                    let nonce = format!("second-{index}");
                    second.append(&event("dev-b", "s1", index, &nonce)).unwrap();
                }
            });
        });
        let report = UsageLedger::open(&path).unwrap().scan().unwrap();
        assert_eq!(report.events.len(), 50);
        assert_eq!(report.malformed, 0);
        assert!(!report.torn_tail);
        assert_eq!(totals(&report.events).events, 50);
    }

    #[cfg(unix)]
    #[test]
    fn ledger_file_is_mode_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("usage.jsonl");
        let ledger = UsageLedger::open(&path).unwrap();
        ledger.append(&event("dev-a", "s1", 1, "n1")).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
