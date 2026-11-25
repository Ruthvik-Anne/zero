//! Local-only metrics registry and read-only dashboard (OBS-01, OBS-03, OBS-08).
//!
//! Every number here is produced on the device. Nothing in this module opens a
//! socket, spawns a task, or contacts a collector: a dashboard reads the
//! in-process registry or a JSON snapshot written beside the local store.
//!
//! The registry is deliberately closed. Only the metrics listed in
//! [`METRIC_NAMES`] exist; an unknown name is rejected instead of silently
//! creating an unbounded series. Label sets are validated and capped per metric
//! so a misbehaving caller cannot grow memory without limit.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use zero_types::error::{ErrorCode, Result, ZeroError};

/// Metric names exposed by the registry, in render order.
pub const METRIC_NAMES: [&str; 7] = [
    QUEUE_DEPTH,
    LATENCY_MS,
    RATE_LIMITED_429,
    RETRIES,
    COST_MICROS,
    REQUESTS,
    ERRORS,
];

/// Current queue depth (gauge).
pub const QUEUE_DEPTH: &str = "queue_depth";
/// Request latency in milliseconds (histogram).
pub const LATENCY_MS: &str = "latency_ms";
/// Provider 429 responses observed locally (counter).
pub const RATE_LIMITED_429: &str = "rate_limited_429";
/// Retry attempts (counter).
pub const RETRIES: &str = "retries";
/// Accumulated cost in millionths of a currency unit (counter).
pub const COST_MICROS: &str = "cost_micros";
/// Requests started (counter).
pub const REQUESTS: &str = "requests";
/// Requests that ended in error (counter).
pub const ERRORS: &str = "errors";

/// Fixed histogram upper bounds in milliseconds; the final bucket is `+Inf`.
pub const LATENCY_BUCKETS_MS: [u64; 10] = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];

/// Schema version of the on-disk snapshot file.
pub const SNAPSHOT_SCHEMA_VERSION: u32 = 1;

/// Maximum bytes in a label key.
pub const MAX_LABEL_KEY_LEN: usize = 32;
/// Maximum bytes in a label value (provider and model names are bounded).
pub const MAX_LABEL_VALUE_LEN: usize = 64;
/// Maximum labels attached to one series.
pub const MAX_LABELS_PER_SERIES: usize = 4;
/// Maximum distinct label sets per metric.
pub const MAX_SERIES_PER_METRIC: usize = 64;

const NUM_BUCKETS: usize = LATENCY_BUCKETS_MS.len() + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetricKind {
    Counter,
    Gauge,
    Histogram,
}

struct MetricSpec {
    name: &'static str,
    kind: MetricKind,
    help: &'static str,
}

const METRICS: [MetricSpec; 7] = [
    MetricSpec {
        name: QUEUE_DEPTH,
        kind: MetricKind::Gauge,
        help: "Current local queue depth (OBS-03).",
    },
    MetricSpec {
        name: LATENCY_MS,
        kind: MetricKind::Histogram,
        help: "Local request latency in milliseconds (OBS-03).",
    },
    MetricSpec {
        name: RATE_LIMITED_429,
        kind: MetricKind::Counter,
        help: "Provider 429 responses observed locally (OBS-03).",
    },
    MetricSpec {
        name: RETRIES,
        kind: MetricKind::Counter,
        help: "Retry attempts (OBS-03).",
    },
    MetricSpec {
        name: COST_MICROS,
        kind: MetricKind::Counter,
        help: "Accumulated cost in millionths of a currency unit (OBS-03).",
    },
    MetricSpec {
        name: REQUESTS,
        kind: MetricKind::Counter,
        help: "Requests started (OBS-03).",
    },
    MetricSpec {
        name: ERRORS,
        kind: MetricKind::Counter,
        help: "Requests that ended in error (OBS-03).",
    },
];

fn spec(name: &str) -> Option<&'static MetricSpec> {
    METRICS.iter().find(|m| m.name == name)
}

fn require_kind(name: &str, kind: MetricKind) -> Result<&'static MetricSpec> {
    let spec = spec(name).ok_or_else(|| {
        ZeroError::new(ErrorCode::InvalidInput, format!("unknown metric `{name}`"))
    })?;
    if spec.kind != kind {
        return Err(ZeroError::new(
            ErrorCode::InvalidInput,
            format!("metric `{name}` is not a {kind:?}"),
        ));
    }
    Ok(spec)
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn validate_label_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(invalid("metric label key is empty"));
    }
    if key.len() > MAX_LABEL_KEY_LEN {
        return Err(invalid(format!(
            "metric label key `{key}` exceeds {MAX_LABEL_KEY_LEN} bytes"
        )));
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(invalid(format!(
            "metric label key `{key}` must be ASCII letters, digits, `_`, `-`, or `.`"
        )));
    }
    Ok(())
}

fn validate_label_value(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(invalid("metric label value is empty"));
    }
    if value.len() > MAX_LABEL_VALUE_LEN {
        return Err(invalid(format!(
            "metric label value exceeds {MAX_LABEL_VALUE_LEN} bytes"
        )));
    }
    if value
        .chars()
        .any(|c| c.is_control() || c == '{' || c == '}' || c == '"' || c == '\\')
    {
        return Err(invalid(
            "metric label value contains a control character or a reserved delimiter",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SeriesKey {
    name: String,
    labels: Vec<(String, String)>,
}

impl SeriesKey {
    fn new(name: &str, labels: &[(&str, &str)]) -> Result<Self> {
        if labels.len() > MAX_LABELS_PER_SERIES {
            return Err(invalid(format!(
                "metric `{name}` accepts at most {MAX_LABELS_PER_SERIES} labels"
            )));
        }
        let mut pairs = Vec::with_capacity(labels.len());
        for &(key, value) in labels {
            validate_label_key(key)?;
            validate_label_value(value)?;
            if pairs.iter().any(|(existing, _): &(String, String)| existing == key) {
                return Err(invalid(format!("duplicate metric label key `{key}`")));
            }
            pairs.push((key.to_string(), value.to_string()));
        }
        pairs.sort();
        Ok(Self { name: name.to_string(), labels: pairs })
    }

    /// Canonical series key: `name` or `name{k="v",...}` with sorted labels.
    fn display(&self) -> String {
        if self.labels.is_empty() {
            return self.name.clone();
        }
        let inner = self
            .labels
            .iter()
            .map(|(key, value)| format!("{key}=\"{value}\""))
            .collect::<Vec<_>>()
            .join(",");
        format!("{}{{{inner}}}", self.name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bucket {
    /// Upper bound in milliseconds; `None` is the `+Inf` bucket.
    pub le_ms: Option<u64>,
    pub count: u64,
}

/// A histogram reading with fixed buckets and percentiles derived from them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketSnapshot {
    pub count: u64,
    pub sum_ms: u64,
    pub min_ms: u64,
    pub max_ms: u64,
    pub buckets: Vec<Bucket>,
    pub p50_ms: u64,
    pub p95_ms: u64,
    pub p99_ms: u64,
}

impl Default for BucketSnapshot {
    fn default() -> Self {
        Self::from_parts(&[0; NUM_BUCKETS], 0, 0, 0, 0)
    }
}

impl BucketSnapshot {
    fn from_parts(counts: &[u64; NUM_BUCKETS], count: u64, sum_ms: u64, min_ms: u64, max_ms: u64) -> Self {
        let buckets = LATENCY_BUCKETS_MS
            .iter()
            .copied()
            .map(Some)
            .chain(std::iter::once(None))
            .zip(counts.iter().copied())
            .map(|(le_ms, count)| Bucket { le_ms, count })
            .collect();
        let mut snapshot = Self {
            count,
            sum_ms,
            min_ms: if count == 0 { 0 } else { min_ms },
            max_ms: if count == 0 { 0 } else { max_ms },
            buckets,
            p50_ms: 0,
            p95_ms: 0,
            p99_ms: 0,
        };
        snapshot.p50_ms = snapshot.percentile(50);
        snapshot.p95_ms = snapshot.percentile(95);
        snapshot.p99_ms = snapshot.percentile(99);
        snapshot
    }

    /// Upper bound of the first bucket that reaches the requested percentile.
    /// When the observation lands in `+Inf`, the recorded maximum is reported so
    /// p95 is never understated for slow requests.
    fn percentile(&self, percentile: u64) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let rank = self.count.saturating_mul(percentile).div_ceil(100).max(1);
        let mut cumulative = 0u64;
        for bucket in &self.buckets {
            cumulative = cumulative.saturating_add(bucket.count);
            if cumulative >= rank {
                return match bucket.le_ms {
                    Some(upper) => upper,
                    None => self.max_ms,
                };
            }
        }
        self.max_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Histogram {
    counts: [u64; NUM_BUCKETS],
    count: u64,
    sum_ms: u64,
    min_ms: u64,
    max_ms: u64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            counts: [0; NUM_BUCKETS],
            count: 0,
            sum_ms: 0,
            min_ms: u64::MAX,
            max_ms: 0,
        }
    }
}

impl Histogram {
    fn record(&mut self, ms: u64) {
        let index = LATENCY_BUCKETS_MS
            .iter()
            .position(|&upper| ms <= upper)
            .unwrap_or(LATENCY_BUCKETS_MS.len());
        self.counts[index] = self.counts[index].saturating_add(1);
        self.count = self.count.saturating_add(1);
        self.sum_ms = self.sum_ms.saturating_add(ms);
        self.min_ms = self.min_ms.min(ms);
        self.max_ms = self.max_ms.max(ms);
    }

    fn snapshot(&self) -> BucketSnapshot {
        BucketSnapshot::from_parts(&self.counts, self.count, self.sum_ms, self.min_ms, self.max_ms)
    }
}

/// Aggregated values across every label set of one metric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Totals {
    /// Sum of each counter over all of its label sets.
    pub counters: BTreeMap<String, u64>,
    /// Sum of each gauge over all of its label sets (global queue depth).
    pub gauges: BTreeMap<String, i64>,
    /// Latency histogram merged across all label sets.
    pub latency: BucketSnapshot,
    /// Number of distinct series in the snapshot.
    pub series: usize,
}

impl Totals {
    fn counter(&self, name: &str) -> u64 {
        self.counters.get(name).copied().unwrap_or(0)
    }

    fn gauge(&self, name: &str) -> i64 {
        self.gauges.get(name).copied().unwrap_or(0)
    }

    /// Error rate in basis points, safe when no request was recorded.
    fn error_basis_points(&self) -> u64 {
        self.counter(ERRORS)
            .saturating_mul(10_000)
            .checked_div(self.counter(REQUESTS))
            .unwrap_or(0)
    }
}

/// Point-in-time view of the registry. All maps use `BTreeMap` so the order is
/// deterministic across runs and platforms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MetricsSnapshot {
    pub counters: BTreeMap<String, u64>,
    pub gauges: BTreeMap<String, i64>,
    pub histograms: BTreeMap<String, BucketSnapshot>,
    pub totals: Totals,
}

impl MetricsSnapshot {
    /// Prometheus text exposition, including zero-valued samples for metrics
    /// that have not recorded anything yet.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        for spec in &METRICS {
            let type_name = match spec.kind {
                MetricKind::Counter => "counter",
                MetricKind::Gauge => "gauge",
                MetricKind::Histogram => "histogram",
            };
            out.push_str(&format!(
                "# HELP {} {}\n# TYPE {} {}\n",
                spec.name, spec.help, spec.name, type_name
            ));
            match spec.kind {
                MetricKind::Counter => {
                    let mut wrote = false;
                    for (key, value) in &self.counters {
                        if split_series_key(key).0 == spec.name {
                            out.push_str(&format!("{key} {value}\n"));
                            wrote = true;
                        }
                    }
                    if !wrote {
                        out.push_str(&format!("{} 0\n", spec.name));
                    }
                }
                MetricKind::Gauge => {
                    let mut wrote = false;
                    for (key, value) in &self.gauges {
                        if split_series_key(key).0 == spec.name {
                            out.push_str(&format!("{key} {value}\n"));
                            wrote = true;
                        }
                    }
                    if !wrote {
                        out.push_str(&format!("{} 0\n", spec.name));
                    }
                }
                MetricKind::Histogram => {
                    let mut wrote = false;
                    for (key, histogram) in &self.histograms {
                        if split_series_key(key).0 == spec.name {
                            write_histogram(&mut out, key, histogram);
                            wrote = true;
                        }
                    }
                    if !wrote {
                        write_histogram(&mut out, spec.name, &BucketSnapshot::default());
                    }
                }
            }
        }
        out
    }

    /// Local JSON projection: counters, gauges, histograms, and totals.
    pub fn render_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }
}

fn split_series_key(key: &str) -> (&str, Option<&str>) {
    match key.find('{') {
        Some(open) if key.ends_with('}') => (&key[..open], Some(&key[open + 1..key.len() - 1])),
        _ => (key, None),
    }
}

fn label_block(labels: Option<&str>, extra: Option<(&str, &str)>) -> String {
    let mut parts = Vec::new();
    if let Some((key, value)) = extra {
        parts.push(format!("{key}=\"{value}\""));
    }
    if let Some(labels) = labels {
        if !labels.is_empty() {
            parts.push(labels.to_string());
        }
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("{{{}}}", parts.join(","))
    }
}

fn write_histogram(out: &mut String, series_key: &str, histogram: &BucketSnapshot) {
    let (name, labels) = split_series_key(series_key);
    for bucket in &histogram.buckets {
        let upper = match bucket.le_ms {
            Some(upper) => upper.to_string(),
            None => "+Inf".to_string(),
        };
        out.push_str(&format!(
            "{}_bucket{} {}\n",
            name,
            label_block(labels, Some(("le", &upper))),
            bucket.count
        ));
    }
    out.push_str(&format!(
        "{}_sum{} {}\n",
        name,
        label_block(labels, None),
        histogram.sum_ms
    ));
    out.push_str(&format!(
        "{}_count{} {}\n",
        name,
        label_block(labels, None),
        histogram.count
    ));
}

#[derive(Debug, Default)]
struct Inner {
    counters: BTreeMap<SeriesKey, u64>,
    gauges: BTreeMap<SeriesKey, i64>,
    histograms: BTreeMap<SeriesKey, Histogram>,
}

impl Inner {
    fn series_count(&self, name: &str) -> usize {
        self.counters.keys().filter(|key| key.name == name).count()
            + self.gauges.keys().filter(|key| key.name == name).count()
            + self.histograms.keys().filter(|key| key.name == name).count()
    }

    fn ensure_capacity(&self, key: &SeriesKey) -> Result<()> {
        let exists = self.counters.contains_key(key)
            || self.gauges.contains_key(key)
            || self.histograms.contains_key(key);
        if !exists && self.series_count(&key.name) >= MAX_SERIES_PER_METRIC {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "metric `{}` is capped at {MAX_SERIES_PER_METRIC} label sets",
                    key.name
                ),
            ));
        }
        Ok(())
    }
}

/// Thread-safe, bounded metrics registry.
#[derive(Debug, Default)]
pub struct Metrics {
    inner: Mutex<Inner>,
}

impl Metrics {
    pub fn new() -> Self {
        Self { inner: Mutex::new(Inner::default()) }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Increment a counter without labels.
    pub fn inc(&self, name: &str) -> Result<()> {
        self.inc_labeled(name, &[])
    }

    /// Increment a counter for a bounded label set.
    pub fn inc_labeled(&self, name: &str, labels: &[(&str, &str)]) -> Result<()> {
        let spec = require_kind(name, MetricKind::Counter)?;
        let key = SeriesKey::new(spec.name, labels)?;
        let mut inner = self.lock();
        inner.ensure_capacity(&key)?;
        let value = inner.counters.entry(key).or_insert(0);
        *value = value.saturating_add(1);
        Ok(())
    }

    /// Add `value` to a counter without labels.
    pub fn add(&self, name: &str, value: u64) -> Result<()> {
        self.add_labeled(name, value, &[])
    }

    /// Add `value` to a counter for a bounded label set.
    pub fn add_labeled(&self, name: &str, value: u64, labels: &[(&str, &str)]) -> Result<()> {
        let spec = require_kind(name, MetricKind::Counter)?;
        let key = SeriesKey::new(spec.name, labels)?;
        let mut inner = self.lock();
        inner.ensure_capacity(&key)?;
        let counter = inner.counters.entry(key).or_insert(0);
        *counter = counter.saturating_add(value);
        Ok(())
    }

    /// Set a gauge without labels.
    pub fn gauge_set(&self, name: &str, value: i64) -> Result<()> {
        self.gauge_set_labeled(name, value, &[])
    }

    /// Set a gauge for a bounded label set.
    pub fn gauge_set_labeled(&self, name: &str, value: i64, labels: &[(&str, &str)]) -> Result<()> {
        let spec = require_kind(name, MetricKind::Gauge)?;
        let key = SeriesKey::new(spec.name, labels)?;
        let mut inner = self.lock();
        inner.ensure_capacity(&key)?;
        inner.gauges.insert(key, value);
        Ok(())
    }

    /// Record one latency observation in milliseconds.
    pub fn record_latency(&self, ms: u64) -> Result<()> {
        self.record_latency_labeled(ms, &[])
    }

    /// Record one latency observation for a bounded label set.
    pub fn record_latency_labeled(&self, ms: u64, labels: &[(&str, &str)]) -> Result<()> {
        let spec = require_kind(LATENCY_MS, MetricKind::Histogram)?;
        let key = SeriesKey::new(spec.name, labels)?;
        let mut inner = self.lock();
        inner.ensure_capacity(&key)?;
        inner.histograms.entry(key).or_default().record(ms);
        Ok(())
    }

    /// Clear every series. The registry stays usable.
    pub fn reset(&self) {
        let mut inner = self.lock();
        inner.counters.clear();
        inner.gauges.clear();
        inner.histograms.clear();
    }

    /// Deterministic point-in-time view with totals aggregated over labels.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let inner = self.lock();
        let counters: BTreeMap<String, u64> = inner
            .counters
            .iter()
            .map(|(key, value)| (key.display(), *value))
            .collect();
        let gauges: BTreeMap<String, i64> = inner
            .gauges
            .iter()
            .map(|(key, value)| (key.display(), *value))
            .collect();
        let histograms: BTreeMap<String, BucketSnapshot> = inner
            .histograms
            .iter()
            .map(|(key, histogram)| (key.display(), histogram.snapshot()))
            .collect();

        let mut totals = Totals::default();
        for (key, value) in &inner.counters {
            let total = totals.counters.entry(key.name.clone()).or_insert(0);
            *total = total.saturating_add(*value);
        }
        for (key, value) in &inner.gauges {
            let total = totals.gauges.entry(key.name.clone()).or_insert(0);
            *total = total.saturating_add(*value);
        }
        totals.latency = aggregate_latency(
            inner
                .histograms
                .iter()
                .filter(|(key, _)| key.name == LATENCY_MS)
                .map(|(_, histogram)| histogram.snapshot()),
        );
        totals.series = inner.counters.len() + inner.gauges.len() + inner.histograms.len();

        MetricsSnapshot { counters, gauges, histograms, totals }
    }
}

fn aggregate_latency(items: impl Iterator<Item = BucketSnapshot>) -> BucketSnapshot {
    let mut counts = [0u64; NUM_BUCKETS];
    let mut count = 0u64;
    let mut sum_ms = 0u64;
    let mut min_ms = u64::MAX;
    let mut max_ms = 0u64;
    for item in items {
        for (index, bucket) in item.buckets.iter().enumerate() {
            counts[index] = counts[index].saturating_add(bucket.count);
        }
        count = count.saturating_add(item.count);
        sum_ms = sum_ms.saturating_add(item.sum_ms);
        if item.count > 0 {
            min_ms = min_ms.min(item.min_ms);
            max_ms = max_ms.max(item.max_ms);
        }
    }
    BucketSnapshot::from_parts(&counts, count, sum_ms, min_ms, max_ms)
}

/// A rendered local dashboard. `generated_ms` is caller-supplied wall time; all
/// other numbers come from the snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dashboard {
    pub snapshot: MetricsSnapshot,
    pub generated_ms: u64,
}

impl Dashboard {
    pub fn from_snapshot(snapshot: MetricsSnapshot, now_ms: u64) -> Self {
        Self { snapshot, generated_ms: now_ms }
    }

    /// Text lines for a terminal or a local file.
    pub fn lines(&self) -> Vec<String> {
        let totals = &self.snapshot.totals;
        let queue_depth = totals.gauge(QUEUE_DEPTH);
        let rate_limited = totals.counter(RATE_LIMITED_429);
        let retries = totals.counter(RETRIES);
        let cost_micros = totals.counter(COST_MICROS);
        let requests = totals.counter(REQUESTS);
        let errors = totals.counter(ERRORS);
        let error_basis_points = totals.error_basis_points();
        vec![
            format!("zero metrics generated_ms={}", self.generated_ms),
            format!("queue_depth: {queue_depth}"),
            format!("latency p50: {} ms", totals.latency.p50_ms),
            format!("latency p95: {} ms", totals.latency.p95_ms),
            format!("429s: {rate_limited}"),
            format!("retries: {retries}"),
            format!(
                "cost: {cost_micros} micros (${}.{c:06})",
                cost_micros / 1_000_000,
                c = cost_micros % 1_000_000
            ),
            format!(
                "error_rate: {}.{:02}% ({errors}/{requests} requests)",
                error_basis_points / 100,
                error_basis_points % 100
            ),
        ]
    }

    /// Local JSON projection of the dashboard fields.
    pub fn json(&self) -> String {
        let totals = &self.snapshot.totals;
        let requests = totals.counter(REQUESTS);
        let errors = totals.counter(ERRORS);
        let error_basis_points = totals.error_basis_points();
        let value = serde_json::json!({
            "generated_ms": self.generated_ms,
            "queue_depth": totals.gauge(QUEUE_DEPTH),
            "latency_ms": {
                "p50": totals.latency.p50_ms,
                "p95": totals.latency.p95_ms,
                "p99": totals.latency.p99_ms,
                "count": totals.latency.count,
                "sum": totals.latency.sum_ms,
            },
            "rate_limited_429": totals.counter(RATE_LIMITED_429),
            "retries": totals.counter(RETRIES),
            "cost_micros": totals.counter(COST_MICROS),
            "requests": requests,
            "errors": errors,
            "error_rate_bps": error_basis_points,
        });
        serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Read the in-process registry into a dashboard. No I/O and no network.
pub fn dashboard(metrics: &Metrics, now_ms: u64) -> Dashboard {
    Dashboard::from_snapshot(metrics.snapshot(), now_ms)
}

#[derive(Serialize, Deserialize)]
struct SnapshotFile {
    schema_version: u32,
    snapshot: MetricsSnapshot,
}

static SAVE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Write a snapshot as pretty JSON with an atomic rename, so a crash leaves the
/// previous file intact instead of a half-written one.
pub fn save_snapshot(snapshot: &MetricsSnapshot, path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let file = SnapshotFile {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        snapshot: snapshot.clone(),
    };
    let mut bytes = serde_json::to_vec_pretty(&file)?;
    bytes.push(b'\n');
    let sequence = SAVE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = path.with_extension(format!("tmp-{}-{sequence}", std::process::id()));
    {
        let mut handle = File::create(&temporary)?;
        handle.write_all(&bytes)?;
        handle.sync_all()?;
    }
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.into());
    }
    Ok(())
}

/// Read a snapshot written by [`save_snapshot`]. A schema mismatch is refused
/// rather than guessed at.
pub fn load_snapshot(path: impl AsRef<Path>) -> Result<MetricsSnapshot> {
    let text = std::fs::read_to_string(path.as_ref())?;
    let file: SnapshotFile = serde_json::from_str(&text)?;
    if file.schema_version != SNAPSHOT_SCHEMA_VERSION {
        return Err(ZeroError::new(
            ErrorCode::SchemaVersion,
            format!(
                "metrics snapshot schema {} is not supported (expected {SNAPSHOT_SCHEMA_VERSION})",
                file.schema_version
            ),
        ));
    }
    Ok(file.snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::sync::Arc;

    fn kind_of(name: &str) -> MetricKind {
        spec(name).expect("known metric").kind
    }

    #[test]
    fn counters_and_gauges_accumulate_and_reject_the_wrong_kind() {
        let metrics = Metrics::new();
        metrics.inc(REQUESTS).unwrap();
        metrics.inc(REQUESTS).unwrap();
        metrics.add(COST_MICROS, 1_500_000).unwrap();
        metrics.gauge_set(QUEUE_DEPTH, 7).unwrap();
        metrics.gauge_set(QUEUE_DEPTH, 3).unwrap();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.counters["requests"], 2);
        assert_eq!(snapshot.counters["cost_micros"], 1_500_000);
        assert_eq!(snapshot.gauges["queue_depth"], 3);
        assert_eq!(snapshot.totals.counter(REQUESTS), 2);
        assert_eq!(snapshot.totals.gauge(QUEUE_DEPTH), 3);
        assert_eq!(snapshot.totals.series, 3);

        assert_eq!(metrics.inc(QUEUE_DEPTH).unwrap_err().code(), ErrorCode::InvalidInput);
        assert_eq!(
            metrics.gauge_set(REQUESTS, 1).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            metrics.add(LATENCY_MS, 1).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn histogram_places_observations_and_derives_percentiles() {
        let metrics = Metrics::new();
        for ms in [3, 7, 7, 30, 6000] {
            metrics.record_latency(ms).unwrap();
        }
        assert_eq!(kind_of(LATENCY_MS), MetricKind::Histogram);
        let histogram = &metrics.snapshot().histograms["latency_ms"];
        assert_eq!(histogram.count, 5);
        assert_eq!(histogram.sum_ms, 6047);
        assert_eq!(histogram.min_ms, 3);
        assert_eq!(histogram.max_ms, 6000);
        let counts: Vec<u64> = histogram.buckets.iter().map(|bucket| bucket.count).collect();
        assert_eq!(counts, vec![1, 2, 0, 1, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(histogram.p50_ms, 10);
        assert_eq!(histogram.p95_ms, 6000);
        assert_eq!(histogram.p99_ms, 6000);

        let percentiles = Metrics::new();
        for ms in 1..=100 {
            percentiles.record_latency(ms).unwrap();
        }
        let histogram = &percentiles.snapshot().histograms["latency_ms"];
        assert_eq!(histogram.p50_ms, 50);
        assert_eq!(histogram.p95_ms, 100);
        assert_eq!(histogram.buckets[0].le_ms, Some(5));
        assert_eq!(histogram.buckets[10].le_ms, None);
    }

    #[test]
    fn concurrent_increments_from_threads_sum_correctly() {
        let metrics = Arc::new(Metrics::new());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let metrics = Arc::clone(&metrics);
            handles.push(std::thread::spawn(move || {
                for _ in 0..500 {
                    metrics.inc(REQUESTS).unwrap();
                    metrics.record_latency(7).unwrap();
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.totals.counter(REQUESTS), 4000);
        assert_eq!(snapshot.totals.latency.count, 4000);
        assert_eq!(snapshot.histograms["latency_ms"].buckets[1].count, 4000);
    }

    #[test]
    fn label_sets_are_capped_per_metric() {
        let metrics = Metrics::new();
        for index in 0..MAX_SERIES_PER_METRIC {
            metrics
                .inc_labeled(REQUESTS, &[("model", &format!("m{index}"))])
                .unwrap();
        }
        let overflow = metrics
            .inc_labeled(REQUESTS, &[("model", "overflow")])
            .unwrap_err();
        assert_eq!(overflow.code(), ErrorCode::LimitExceeded);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.counters.len(), MAX_SERIES_PER_METRIC);
        assert_eq!(snapshot.totals.series, MAX_SERIES_PER_METRIC);

        // A label set that already exists is still writable at the cap.
        metrics.inc_labeled(REQUESTS, &[("model", "m0")]).unwrap();
        assert_eq!(metrics.snapshot().counters.len(), MAX_SERIES_PER_METRIC);
    }

    #[test]
    fn invalid_names_and_labels_are_rejected() {
        let metrics = Metrics::new();
        assert_eq!(metrics.inc("not_a_metric").unwrap_err().code(), ErrorCode::InvalidInput);
        assert_eq!(
            metrics
                .inc_labeled(REQUESTS, &[("bad\nkey", "x")])
                .unwrap_err()
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            metrics
                .inc_labeled(REQUESTS, &[("provider", "bad\nvalue")])
                .unwrap_err()
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            metrics
                .inc_labeled(REQUESTS, &[("provider", &"x".repeat(MAX_LABEL_VALUE_LEN + 1))])
                .unwrap_err()
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            metrics
                .inc_labeled(
                    REQUESTS,
                    &[("a", "1"), ("b", "2"), ("c", "3"), ("d", "4"), ("e", "5")]
                )
                .unwrap_err()
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            metrics
                .inc_labeled(REQUESTS, &[("provider", "a"), ("provider", "b")])
                .unwrap_err()
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            metrics
                .inc_labeled(REQUESTS, &[("provider", "a}b")])
                .unwrap_err()
                .code(),
            ErrorCode::InvalidInput
        );
        assert!(metrics.snapshot().counters.is_empty());
    }

    #[test]
    fn snapshot_and_render_order_are_deterministic() {
        let first = Metrics::new();
        first.gauge_set(QUEUE_DEPTH, 5).unwrap();
        first.inc(REQUESTS).unwrap();
        first.inc(REQUESTS).unwrap();
        first.add(COST_MICROS, 10).unwrap();
        first.record_latency(7).unwrap();

        let second = Metrics::new();
        second.record_latency(7).unwrap();
        second.add(COST_MICROS, 10).unwrap();
        second.inc(REQUESTS).unwrap();
        second.inc(REQUESTS).unwrap();
        second.gauge_set(QUEUE_DEPTH, 5).unwrap();

        let first_snapshot = first.snapshot();
        let second_snapshot = second.snapshot();
        assert_eq!(first_snapshot, second_snapshot);
        assert_eq!(
            first_snapshot.render_prometheus(),
            second_snapshot.render_prometheus()
        );
        assert_eq!(first_snapshot.render_json(), second_snapshot.render_json());
    }

    #[test]
    fn dashboard_reads_the_registry_values() {
        let metrics = Metrics::new();
        metrics.gauge_set(QUEUE_DEPTH, 7).unwrap();
        metrics.record_latency(10).unwrap();
        metrics.record_latency(20).unwrap();
        metrics.inc(RATE_LIMITED_429).unwrap();
        metrics.inc(RATE_LIMITED_429).unwrap();
        metrics.add(RETRIES, 3).unwrap();
        metrics.add(COST_MICROS, 1_500_000).unwrap();
        metrics.add(REQUESTS, 40).unwrap();
        metrics.add(ERRORS, 2).unwrap();

        let dashboard = dashboard(&metrics, 42);
        assert_eq!(dashboard.generated_ms, 42);
        let lines = dashboard.lines();
        assert!(lines.contains(&"queue_depth: 7".to_string()), "{lines:?}");
        assert!(lines.contains(&"latency p50: 10 ms".to_string()), "{lines:?}");
        assert!(lines.contains(&"latency p95: 25 ms".to_string()), "{lines:?}");
        assert!(lines.contains(&"429s: 2".to_string()), "{lines:?}");
        assert!(lines.contains(&"retries: 3".to_string()), "{lines:?}");
        assert!(
            lines.contains(&"cost: 1500000 micros ($1.500000)".to_string()),
            "{lines:?}"
        );
        assert!(
            lines.contains(&"error_rate: 5.00% (2/40 requests)".to_string()),
            "{lines:?}"
        );

        let value: Value = serde_json::from_str(&dashboard.json()).unwrap();
        assert_eq!(value["generated_ms"].as_u64(), Some(42));
        assert_eq!(value["queue_depth"].as_i64(), Some(7));
        assert_eq!(value["latency_ms"]["p50"].as_u64(), Some(10));
        assert_eq!(value["latency_ms"]["p95"].as_u64(), Some(25));
        assert_eq!(value["rate_limited_429"].as_u64(), Some(2));
        assert_eq!(value["retries"].as_u64(), Some(3));
        assert_eq!(value["cost_micros"].as_u64(), Some(1_500_000));
        assert_eq!(value["error_rate_bps"].as_u64(), Some(500));
    }

    #[test]
    fn save_and_load_round_trip_keeps_the_dashboard_identical() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("metrics.json");
        let metrics = Metrics::new();
        metrics.gauge_set(QUEUE_DEPTH, 4).unwrap();
        metrics.record_latency(7).unwrap();
        metrics.inc(RATE_LIMITED_429).unwrap();
        metrics.add(COST_MICROS, 123).unwrap();
        metrics.inc_labeled(REQUESTS, &[("provider", "local")]).unwrap();

        let snapshot = metrics.snapshot();
        save_snapshot(&snapshot, &path).unwrap();
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("\"schema_version\": 1"));
        assert_eq!(load_snapshot(&path).unwrap(), snapshot);

        // A second save replaces the file atomically.
        save_snapshot(&MetricsSnapshot::default(), &path).unwrap();
        assert_eq!(load_snapshot(&path).unwrap(), MetricsSnapshot::default());

        let before = Dashboard::from_snapshot(snapshot.clone(), 99);
        let after = Dashboard::from_snapshot(load_snapshot(&path).unwrap(), 99);
        assert_ne!(before, after);
        save_snapshot(&snapshot, &path).unwrap();
        let after = Dashboard::from_snapshot(load_snapshot(&path).unwrap(), 99);
        assert_eq!(before.lines(), after.lines());
        assert_eq!(before.json(), after.json());

        let mut value: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        value["schema_version"] = serde_json::json!(99);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            load_snapshot(&path).unwrap_err().code(),
            ErrorCode::SchemaVersion
        );
    }

    #[test]
    fn an_empty_registry_renders_zeroes_and_a_usable_dashboard() {
        let metrics = Metrics::new();
        let snapshot = metrics.snapshot();
        assert!(snapshot.counters.is_empty());
        assert!(snapshot.gauges.is_empty());
        assert!(snapshot.histograms.is_empty());
        assert_eq!(snapshot.totals, Totals::default());
        assert_eq!(snapshot.totals.latency.p50_ms, 0);
        assert_eq!(snapshot.totals.latency.count, 0);

        let prometheus = snapshot.render_prometheus();
        assert_eq!(prometheus.matches("# TYPE ").count(), METRIC_NAMES.len());
        for name in METRIC_NAMES {
            assert!(prometheus.contains(&format!("# TYPE {name} ")), "{name}");
        }
        assert!(prometheus.contains("queue_depth 0\n"));
        assert!(prometheus.contains("latency_ms_count 0\n"));

        let value: Value = serde_json::from_str(&snapshot.render_json()).unwrap();
        assert_eq!(value["counters"], serde_json::json!({}));
        assert_eq!(value["totals"]["series"].as_u64(), Some(0));

        let dashboard = dashboard(&metrics, 1);
        assert!(dashboard.lines().contains(&"queue_depth: 0".to_string()));
        assert!(dashboard
            .lines()
            .contains(&"latency p95: 0 ms".to_string()));
        assert!(dashboard
            .lines()
            .contains(&"error_rate: 0.00% (0/0 requests)".to_string()));
    }

    #[test]
    fn reset_clears_every_series_and_keeps_the_registry_usable() {
        let metrics = Metrics::new();
        metrics.inc(REQUESTS).unwrap();
        metrics.gauge_set(QUEUE_DEPTH, 2).unwrap();
        metrics.record_latency(5).unwrap();
        metrics.reset();
        assert_eq!(metrics.snapshot(), MetricsSnapshot::default());
        metrics.inc(REQUESTS).unwrap();
        assert_eq!(metrics.snapshot().counters["requests"], 1);
    }

    #[test]
    fn prometheus_and_json_shapes_include_labels_and_buckets() {
        let metrics = Metrics::new();
        metrics
            .inc_labeled(REQUESTS, &[("provider", "p"), ("model", "m1")])
            .unwrap();
        metrics.add_labeled(REQUESTS, 2, &[("provider", "p"), ("model", "m1")])
            .unwrap();
        metrics
            .record_latency_labeled(9, &[("provider", "p")])
            .unwrap();

        let snapshot = metrics.snapshot();
        assert!(snapshot.counters.contains_key("requests{model=\"m1\",provider=\"p\"}"));
        assert!(snapshot.histograms.contains_key("latency_ms{provider=\"p\"}"));

        let prometheus = snapshot.render_prometheus();
        assert!(prometheus.contains("requests{model=\"m1\",provider=\"p\"} 3\n"));
        assert!(prometheus.contains("latency_ms_bucket{le=\"10\",provider=\"p\"} 1\n"));
        assert!(prometheus.contains("latency_ms_bucket{le=\"+Inf\",provider=\"p\"} 0\n"));
        assert!(prometheus.contains("latency_ms_count{provider=\"p\"} 1\n"));
        assert!(prometheus.contains("# TYPE latency_ms histogram\n"));

        let value: Value = serde_json::from_str(&snapshot.render_json()).unwrap();
        assert_eq!(
            value["counters"]["requests{model=\"m1\",provider=\"p\"}"].as_u64(),
            Some(3)
        );
        assert_eq!(
            value["histograms"]["latency_ms{provider=\"p\"}"]["buckets"]
                .as_array()
                .unwrap()
                .len(),
            NUM_BUCKETS
        );
    }

    #[test]
    fn the_module_contains_no_network_code() {
        let source = include_str!("metrics.rs");
        let forbidden = [
            concat!("std::", "net"),
            concat!("Tcp", "Stream"),
            concat!("Udp", "Socket"),
            concat!("Tcp", "Listener"),
            concat!("req", "west"),
            concat!("hyper", "::"),
            concat!("ure", "q"),
            concat!("http", "://"),
            concat!("https", "://"),
        ];
        for token in forbidden {
            assert!(
                !source.contains(token),
                "metrics.rs must stay local-only, found `{token}`"
            );
        }
    }
}
