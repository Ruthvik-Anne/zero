//! Resumable crawl jobs: frontier, robots.txt, sitemaps, limits, retries
//! (WEB-11, WEB-12).
//!
//! A crawl is a [`CrawlJob`]: a durable document holding the frontier queue,
//! the deduplication set, completed and failed pages, the separate
//! robots-blocked list, the limits, and its state. [`CrawlStore`] persists that
//! document with an atomic temp-file-and-rename write, so killing the process
//! and reloading the file resumes exactly where the last step stopped.
//!
//! [`CrawlSession::step`] processes one frontier entry per call:
//!
//! 1. Refuse to fetch once the job is `cancelled`, `completed`, or `failed`.
//! 2. Leave an entry in place until its `next_attempt_ms` backoff has elapsed.
//! 3. Stop before the page or byte limit would be exceeded.
//! 4. Drop a path-denied URL and count it.
//! 5. Fetch `/robots.txt` per origin and skip a disallowed URL into the
//!    separate robots-blocked list.
//! 6. Fetch the page, retry with exponential backoff, and enqueue discovered
//!    links breadth-first up to the depth limit.
//!
//! The module never opens a socket: callers implement [`Fetcher`]. Tests script
//! it, so the whole crawl is deterministic and clock-driven (`now_ms`).
//!
//! Untrusted page bodies are only scanned for links; nothing here executes
//! them. See `docs/web.md` for the store schema and the exact rules.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::resilience::is_bench_refusal;
use crate::search::canonical_url_key;

/// Version written into every store document.
///
/// A document with another version is refused with [`ErrorCode::SchemaVersion`]
/// instead of being guessed at. Bump this on any breaking field change.
pub const CRAWL_SCHEMA_VERSION: u32 = 1;

/// Default page ceiling: small enough for an unattended first crawl.
pub const DEFAULT_MAX_PAGES: usize = 32;
/// Default link depth (seeds are depth 0, their links depth 1, ...).
pub const DEFAULT_MAX_DEPTH: usize = 2;
/// Default byte ceiling for admitted response bodies (4 MiB).
pub const DEFAULT_MAX_BYTES: u64 = 4 * 1024 * 1024;
/// Default retries after the first failed attempt.
pub const DEFAULT_MAX_RETRIES: u32 = 3;
/// Default reportable concurrency. [`CrawlSession::step`] is sequential; the
/// value is carried so a parallel driver knows its budget.
pub const DEFAULT_CONCURRENCY: usize = 2;
/// First retry delay; doubles for every further attempt.
pub const RETRY_BASE_MS: u64 = 1_000;
/// Cap on a retry delay.
pub const RETRY_MAX_MS: u64 = 60_000;
/// Product token sent as the robots.txt user-agent.
pub const CRAWLER_USER_AGENT: &str = "zero-crawler";

/// Longest failure reason kept in the store. Longer messages are truncated on
/// a character boundary, so a hostile server cannot grow the job file without
/// bound.
pub const MAX_REASON_CHARS: usize = 200;

/// Limits for one crawl. All fields are caller-set; the [`Default`] values are
/// conservative for an unattended first run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CrawlLimits {
    /// Maximum admitted pages (completed + failed + robots-blocked).
    pub max_pages: usize,
    /// Maximum link depth; a seed is depth 0.
    pub max_depth: usize,
    /// Maximum cumulative bytes of admitted response bodies.
    pub max_bytes: u64,
    /// Retries after the first attempt.
    pub max_retries: u32,
    /// If non-empty, only paths matching one of these rules are crawled.
    pub allowed_paths: Vec<String>,
    /// Paths matching one of these rules are never crawled. Deny wins over
    /// allow.
    pub denied_paths: Vec<String>,
    /// Reportable concurrency budget. `step` itself is sequential.
    pub concurrency: usize,
}

impl Default for CrawlLimits {
    fn default() -> Self {
        Self {
            max_pages: DEFAULT_MAX_PAGES,
            max_depth: DEFAULT_MAX_DEPTH,
            max_bytes: DEFAULT_MAX_BYTES,
            max_retries: DEFAULT_MAX_RETRIES,
            allowed_paths: Vec::new(),
            denied_paths: Vec::new(),
            concurrency: DEFAULT_CONCURRENCY,
        }
    }
}

impl CrawlLimits {
    /// The conservative defaults, spelled out for callers that prefer a named
    /// constructor.
    pub fn conservative() -> Self {
        Self::default()
    }

    /// Whether a URL path may be crawled under these limits.
    ///
    /// A denied rule always wins. With no allowed rules every non-denied path
    /// is allowed; otherwise at least one allowed rule must match.
    pub fn path_allowed(&self, path: &str) -> bool {
        if self
            .denied_paths
            .iter()
            .any(|rule| path_matches(rule, path))
        {
            return false;
        }
        self.allowed_paths.is_empty()
            || self
                .allowed_paths
                .iter()
                .any(|rule| path_matches(rule, path))
    }
}

/// Job state (WEB-12). `Scraping` means at least one step has started fetching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrawlState {
    Queued,
    Scraping,
    Completed,
    Failed,
    Cancelled,
}

impl CrawlState {
    /// Stable lower-case name used in diagnostics and the job list.
    pub fn as_str(self) -> &'static str {
        match self {
            CrawlState::Queued => "queued",
            CrawlState::Scraping => "scraping",
            CrawlState::Completed => "completed",
            CrawlState::Failed => "failed",
            CrawlState::Cancelled => "cancelled",
        }
    }

    fn is_terminal(self) -> bool {
        matches!(
            self,
            CrawlState::Completed | CrawlState::Failed | CrawlState::Cancelled
        )
    }
}

/// One queued URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierEntry {
    /// Absolute http(s) URL, fragment removed, scheme and host lowercased.
    pub url: String,
    /// 0 for a seed, one more per link hop.
    pub depth: usize,
    /// Tries already made. `0` means the first attempt is still pending.
    pub attempts: u32,
    /// Earliest `now_ms` at which the next attempt may run.
    pub next_attempt_ms: u64,
}

/// One successfully fetched page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrawlResult {
    pub url: String,
    pub status: u16,
    pub bytes: u64,
    pub depth: usize,
    pub fetched_at_ms: u64,
}

/// One page that exhausted its retries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrawlFailure {
    pub url: String,
    /// Total attempts made, including the first one.
    pub attempts: u32,
    /// Bounded reason (`MAX_REASON_CHARS`).
    pub reason: String,
}

/// One page blocked by robots.txt or by a CAPTCHA/login wall.
///
/// Kept apart from [`CrawlFailure`]: a refusal is a policy answer, not a
/// transport or server error, and must not poison the failure list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RobotsBlock {
    pub url: String,
    /// HTTP status when a CAPTCHA/login wall produced the block; `0` when a
    /// robots.txt rule did.
    pub status: u16,
    pub reason: String,
}

/// Counts for progress reporting (WEB-12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrawlProgress {
    pub state: CrawlState,
    /// URLs still waiting on the frontier, including entries in backoff.
    pub queued: usize,
    pub completed: usize,
    pub failed: usize,
    pub robots_blocked: usize,
    /// URLs discarded by a path rule.
    pub skipped: u64,
    /// Cumulative bytes of completed pages.
    pub bytes: u64,
    pub max_pages: usize,
    pub max_depth: usize,
}

/// One page of the completed/failed/robots-blocked lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrawlPage {
    pub offset: usize,
    pub limit: usize,
    pub completed: Vec<CrawlResult>,
    pub failed: Vec<CrawlFailure>,
    pub robots_blocked: Vec<RobotsBlock>,
    pub total_completed: usize,
    pub total_failed: usize,
    pub total_robots_blocked: usize,
}

/// A crawl job. Serialized whole by [`CrawlStore`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrawlJob {
    pub id: String,
    /// Seeds that were accepted at creation (valid URL, allowed path, deduped).
    pub seeds: Vec<String>,
    pub limits: CrawlLimits,
    pub frontier: VecDeque<FrontierEntry>,
    /// Canonical URL keys that have been scheduled at least once. A key is
    /// inserted before a fetch so a link cycle can never enqueue it twice.
    pub seen: BTreeSet<String>,
    pub completed: Vec<CrawlResult>,
    pub failed: Vec<CrawlFailure>,
    pub robots_blocked: Vec<RobotsBlock>,
    /// URLs discarded by an allowed/denied path rule.
    #[serde(default)]
    pub skipped: u64,
    pub state: CrawlState,
    pub created_ms: u64,
    pub updated_ms: u64,
}

impl CrawlJob {
    /// Build a job and schedule its seeds breadth-first at depth 0.
    ///
    /// Seeds that are not http(s), carry userinfo, or are denied by a path rule
    /// are dropped and counted in [`Self::skipped`]. Duplicate seeds collapse
    /// to one canonical key. The state starts as `queued`.
    pub fn new(
        id: impl Into<String>,
        seeds: impl IntoIterator<Item = String>,
        limits: CrawlLimits,
        now_ms: u64,
    ) -> Self {
        let mut job = Self {
            id: id.into(),
            seeds: Vec::new(),
            limits,
            frontier: VecDeque::new(),
            seen: BTreeSet::new(),
            completed: Vec::new(),
            failed: Vec::new(),
            robots_blocked: Vec::new(),
            skipped: 0,
            state: CrawlState::Queued,
            created_ms: now_ms,
            updated_ms: now_ms,
        };
        for seed in seeds {
            job.schedule(&seed, 0, now_ms);
        }
        job.seeds = job.frontier.iter().map(|entry| entry.url.clone()).collect();
        job
    }

    /// Cumulative bytes of admitted pages.
    pub fn bytes_fetched(&self) -> u64 {
        self.completed.iter().map(|result| result.bytes).sum()
    }

    /// Pages that consumed the page budget.
    fn processed(&self) -> usize {
        self.completed.len() + self.failed.len() + self.robots_blocked.len()
    }

    /// Progress counts and the limits they are measured against.
    pub fn progress(&self) -> CrawlProgress {
        CrawlProgress {
            state: self.state,
            queued: self.frontier.len(),
            completed: self.completed.len(),
            failed: self.failed.len(),
            robots_blocked: self.robots_blocked.len(),
            skipped: self.skipped,
            bytes: self.bytes_fetched(),
            max_pages: self.limits.max_pages,
            max_depth: self.limits.max_depth,
        }
    }

    /// A window over the completed, failed, and robots-blocked lists.
    ///
    /// `limit == 0` yields empty windows. `offset` past the end is empty too.
    pub fn page(&self, offset: usize, limit: usize) -> CrawlPage {
        CrawlPage {
            offset,
            limit,
            completed: window(&self.completed, offset, limit),
            failed: window(&self.failed, offset, limit),
            robots_blocked: window(&self.robots_blocked, offset, limit),
            total_completed: self.completed.len(),
            total_failed: self.failed.len(),
            total_robots_blocked: self.robots_blocked.len(),
        }
    }

    /// Move to `cancelled`. Returns `false` when already cancelled.
    pub fn cancel(&mut self, now_ms: u64) -> bool {
        if self.state == CrawlState::Cancelled {
            return false;
        }
        self.state = CrawlState::Cancelled;
        self.updated_ms = now_ms;
        true
    }

    /// `completed` when the frontier drains; `failed` when nothing was ever
    /// admitted and at least one page failed.
    fn settle(&mut self) {
        if !self.frontier.is_empty() {
            return;
        }
        self.state = if self.completed.is_empty() && !self.failed.is_empty() {
            CrawlState::Failed
        } else {
            CrawlState::Completed
        };
    }

    /// Deduplicate, filter, and enqueue one URL. Returns whether it was queued.
    fn schedule(&mut self, url: &str, depth: usize, now_ms: u64) -> bool {
        if depth > self.limits.max_depth {
            return false;
        }
        let Some(normalized) = normalize_http_url(url) else {
            self.skipped += 1;
            return false;
        };
        let path = url_path_for_robots(&normalized);
        if !self.limits.path_allowed(&path) {
            self.skipped += 1;
            return false;
        }
        let key = canonical_url_key(&normalized);
        if key.is_empty() || !self.seen.insert(key) {
            return false;
        }
        self.frontier.push_back(FrontierEntry {
            url: normalized,
            depth,
            attempts: 0,
            next_attempt_ms: now_ms,
        });
        true
    }
}

/// Atomic JSON job store.
///
/// Writing goes to a sibling `*.tmp` file and is renamed over the target, so a
/// reader never observes a half-written document and a crash leaves either the
/// old or the new state.
#[derive(Debug, Clone)]
pub struct CrawlStore {
    path: PathBuf,
}

/// On-disk envelope: schema version plus the job.
#[derive(Debug, Serialize, Deserialize)]
struct StoredJob {
    schema: u32,
    job: CrawlJob,
}

impl CrawlStore {
    /// A store for one job file. The file is created on the first save.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Path of the job file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the job file already exists.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Create a new store, refusing to overwrite an existing job.
    pub fn create(&self, job: &CrawlJob) -> Result<()> {
        if self.path.exists() {
            return Err(ZeroError::new(
                ErrorCode::AlreadyExists,
                format!(
                    "crawl job store `{}` already exists; load it or choose another path",
                    self.path.display()
                ),
            ));
        }
        self.save(job)
    }

    /// Atomically persist one job.
    pub fn save(&self, job: &CrawlJob) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let stored = StoredJob {
            schema: CRAWL_SCHEMA_VERSION,
            job: job.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&stored)?;
        let temp = self.path.with_extension("tmp");
        std::fs::write(&temp, bytes)?;
        std::fs::rename(&temp, &self.path)?;
        Ok(())
    }

    /// Load one job, refusing a corrupt document or an unknown schema.
    pub fn load(&self) -> Result<CrawlJob> {
        let text = std::fs::read_to_string(&self.path)?;
        let stored: StoredJob = serde_json::from_str(&text).map_err(|error| {
            ZeroError::new(
                ErrorCode::Corrupt,
                format!("crawl store `{}` is corrupt: {error}", self.path.display()),
            )
        })?;
        if stored.schema != CRAWL_SCHEMA_VERSION {
            return Err(ZeroError::new(
                ErrorCode::SchemaVersion,
                format!(
                    "crawl store `{}` has schema {}; this build reads schema {}",
                    self.path.display(),
                    stored.schema,
                    CRAWL_SCHEMA_VERSION
                ),
            ));
        }
        Ok(stored.job)
    }

    /// Summarize every `*.json` job in a directory, sorted by path.
    ///
    /// A missing directory is empty. Unreadable or corrupt files are skipped:
    /// listing is diagnostic and one bad job must not hide the others.
    pub fn list(dir: impl AsRef<Path>) -> Result<Vec<JobSummary>> {
        let dir = dir.as_ref();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension.to_str() == Some("json"))
            })
            .collect();
        paths.sort();
        let mut summaries = Vec::new();
        for path in paths {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(stored) = serde_json::from_str::<StoredJob>(&text) else {
                continue;
            };
            if stored.schema == CRAWL_SCHEMA_VERSION {
                summaries.push(JobSummary::from_job(&stored.job, &path));
            }
        }
        Ok(summaries)
    }
}

/// One row of [`CrawlStore::list`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSummary {
    pub id: String,
    pub path: PathBuf,
    pub state: CrawlState,
    pub queued: usize,
    pub completed: usize,
    pub failed: usize,
    pub robots_blocked: usize,
    pub updated_ms: u64,
}

impl JobSummary {
    fn from_job(job: &CrawlJob, path: &Path) -> Self {
        Self {
            id: job.id.clone(),
            path: path.to_path_buf(),
            state: job.state,
            queued: job.frontier.len(),
            completed: job.completed.len(),
            failed: job.failed.len(),
            robots_blocked: job.robots_blocked.len(),
            updated_ms: job.updated_ms,
        }
    }
}

/// One response body as returned by a [`Fetcher`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchedPage {
    /// Final URL after redirects.
    pub url: String,
    pub status: u16,
    pub body: String,
    /// Raw href values found in the body.
    pub links: Vec<String>,
    /// Response body size in bytes.
    pub bytes: u64,
}

/// The transport a crawl drives. Tests script it; no implementation ships in
/// this crate yet.
pub trait Fetcher {
    /// Fetch one absolute http(s) URL. `limits` lets an implementation cap the
    /// body before it is materialized.
    fn fetch(&self, url: &str, limits: &CrawlLimits) -> Result<FetchedPage>;
}

/// Outcome of one [`CrawlSession::step`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    /// One page was admitted.
    Fetched {
        url: String,
        status: u16,
        bytes: u64,
    },
    /// The page failed and is scheduled for another attempt.
    Retry {
        url: String,
        attempt: u32,
        next_attempt_ms: u64,
    },
    /// The page exhausted its retries and moved to the failure list.
    Failed { url: String, reason: String },
    /// robots.txt or a CAPTCHA/login wall refused the page.
    RobotsBlocked { url: String, status: u16 },
    /// A path rule discarded the URL.
    Skipped { url: String, reason: String },
    /// The frontier head is backing off; call again at `next_attempt_ms`.
    Waiting { url: String, next_attempt_ms: u64 },
    /// `max_pages` or `max_bytes` stopped the crawl before a fetch.
    LimitReached { limit: &'static str },
    /// Nothing left to do (frontier empty or the job is terminal).
    Idle,
    /// The job is cancelled; no fetch happened.
    Cancelled,
}

/// A loaded job plus its session-local robots cache.
///
/// The robots cache is not persisted: after a resume it is rebuilt on demand.
/// That only refetches `/robots.txt`, never a page that is already in `seen`.
pub struct CrawlSession {
    store: CrawlStore,
    job: CrawlJob,
    robots: BTreeMap<String, RobotsRules>,
}

impl CrawlSession {
    /// Create a new job and persist it before returning.
    pub fn create(
        store: CrawlStore,
        id: impl Into<String>,
        seeds: impl IntoIterator<Item = String>,
        limits: CrawlLimits,
        now_ms: u64,
    ) -> Result<Self> {
        let job = CrawlJob::new(id, seeds, limits, now_ms);
        store.create(&job)?;
        Ok(Self {
            store,
            job,
            robots: BTreeMap::new(),
        })
    }

    /// Resume the job stored at `store`.
    pub fn open(store: CrawlStore) -> Result<Self> {
        let job = store.load()?;
        Ok(Self {
            store,
            job,
            robots: BTreeMap::new(),
        })
    }

    /// The current job state.
    pub fn job(&self) -> &CrawlJob {
        &self.job
    }

    /// The backing store.
    pub fn store(&self) -> &CrawlStore {
        &self.store
    }

    /// Cancel the job and persist the transition. A cancelled job refuses every
    /// later fetch.
    pub fn cancel(&mut self, now_ms: u64) -> Result<()> {
        if self.job.cancel(now_ms) {
            self.store.save(&self.job)?;
        }
        Ok(())
    }

    /// Process one frontier entry and persist every transition.
    ///
    /// The entry is not removed until its outcome is recorded, so a crash
    /// during a fetch leaves it on the frontier and the resume refetches that
    /// one page (at-least-once). Pages already admitted are in `completed` and
    /// can never be rescheduled because their key is in `seen`.
    pub fn step(&mut self, fetcher: &dyn Fetcher, now_ms: u64) -> Result<StepOutcome> {
        if self.job.state == CrawlState::Cancelled {
            return Ok(StepOutcome::Cancelled);
        }
        if self.job.state.is_terminal() {
            return Ok(StepOutcome::Idle);
        }

        let Some(entry) = self.job.frontier.front().cloned() else {
            self.job.settle();
            self.persist(now_ms)?;
            return Ok(StepOutcome::Idle);
        };

        if entry.next_attempt_ms > now_ms {
            return Ok(StepOutcome::Waiting {
                url: entry.url.clone(),
                next_attempt_ms: entry.next_attempt_ms,
            });
        }
        if self.job.processed() >= self.job.limits.max_pages {
            self.job.state = CrawlState::Completed;
            self.persist(now_ms)?;
            return Ok(StepOutcome::LimitReached { limit: "max_pages" });
        }
        if self.job.bytes_fetched() >= self.job.limits.max_bytes {
            self.job.state = CrawlState::Completed;
            self.persist(now_ms)?;
            return Ok(StepOutcome::LimitReached { limit: "max_bytes" });
        }
        if entry.depth > self.job.limits.max_depth {
            self.job.frontier.pop_front();
            self.job.skipped += 1;
            self.job.settle();
            self.persist(now_ms)?;
            return Ok(StepOutcome::Skipped {
                url: entry.url,
                reason: bounded_reason("depth limit reached"),
            });
        }

        let path = url_path_for_robots(&entry.url);
        if !self.job.limits.path_allowed(&path) {
            self.job.frontier.pop_front();
            self.job.skipped += 1;
            self.job.settle();
            self.persist(now_ms)?;
            return Ok(StepOutcome::Skipped {
                url: entry.url,
                reason: bounded_reason("path denied by crawl limits"),
            });
        }

        let origin = url_origin(&entry.url);
        if !self.robots.contains_key(&origin) {
            let rules = fetch_robots(fetcher, &origin, &self.job.limits);
            self.robots.insert(origin.clone(), rules);
        }
        if let Some(rules) = self.robots.get(&origin) {
            if !rules.allowed(&path) {
                self.job.frontier.pop_front();
                self.job.robots_blocked.push(RobotsBlock {
                    url: entry.url.clone(),
                    status: 0,
                    reason: bounded_reason("disallowed by robots.txt"),
                });
                self.job.settle();
                self.persist(now_ms)?;
                return Ok(StepOutcome::RobotsBlocked {
                    url: entry.url,
                    status: 0,
                });
            }
        }

        self.job.state = CrawlState::Scraping;
        match fetcher.fetch(&entry.url, &self.job.limits) {
            Err(error) => {
                let reason = bounded_reason(&error.to_string());
                self.record_failure(entry, reason, now_ms)
            }
            Ok(page) => {
                if is_captcha_or_login(page.status, &page.body) {
                    self.job.frontier.pop_front();
                    self.job.robots_blocked.push(RobotsBlock {
                        url: entry.url.clone(),
                        status: page.status,
                        reason: bounded_reason("CAPTCHA or login wall"),
                    });
                    self.job.settle();
                    self.persist(now_ms)?;
                    return Ok(StepOutcome::RobotsBlocked {
                        url: entry.url,
                        status: page.status,
                    });
                }
                if !(200..300).contains(&page.status) {
                    let reason = bounded_reason(&format!("HTTP status {}", page.status));
                    return self.record_failure(entry, reason, now_ms);
                }
                let projected = self.job.bytes_fetched().saturating_add(page.bytes);
                if projected > self.job.limits.max_bytes {
                    // The body was read by the transport, but it is never
                    // admitted, so the recorded total stays under the limit.
                    self.job.frontier.pop_front();
                    self.job.state = CrawlState::Completed;
                    self.persist(now_ms)?;
                    return Ok(StepOutcome::LimitReached { limit: "max_bytes" });
                }

                self.job.frontier.pop_front();
                self.job.completed.push(CrawlResult {
                    url: entry.url.clone(),
                    status: page.status,
                    bytes: page.bytes,
                    depth: entry.depth,
                    fetched_at_ms: now_ms,
                });
                let child_depth = entry.depth + 1;
                for link in &page.links {
                    if let Some(resolved) = resolve_link(&page.url, link) {
                        self.job.schedule(&resolved, child_depth, now_ms);
                    }
                }
                self.job.settle();
                self.persist(now_ms)?;
                Ok(StepOutcome::Fetched {
                    url: entry.url,
                    status: page.status,
                    bytes: page.bytes,
                })
            }
        }
    }

    fn record_failure(
        &mut self,
        mut entry: FrontierEntry,
        reason: String,
        now_ms: u64,
    ) -> Result<StepOutcome> {
        self.job.frontier.pop_front();
        entry.attempts += 1;
        if entry.attempts > self.job.limits.max_retries {
            self.job.failed.push(CrawlFailure {
                url: entry.url.clone(),
                attempts: entry.attempts,
                reason: reason.clone(),
            });
            self.job.settle();
            self.persist(now_ms)?;
            return Ok(StepOutcome::Failed {
                url: entry.url,
                reason,
            });
        }
        let url = entry.url.clone();
        let attempt = entry.attempts;
        let next_attempt_ms = now_ms.saturating_add(retry_delay_ms(attempt));
        entry.next_attempt_ms = next_attempt_ms;
        self.job.frontier.push_front(entry);
        self.persist(now_ms)?;
        Ok(StepOutcome::Retry {
            url,
            attempt,
            next_attempt_ms,
        })
    }

    fn persist(&mut self, now_ms: u64) -> Result<()> {
        self.job.updated_ms = now_ms;
        self.store.save(&self.job)
    }
}

/// Retry delay for the given attempt count (1 = first failure).
///
/// `RETRY_BASE_MS * 2^(attempt - 1)`, capped at [`RETRY_MAX_MS`] and
/// saturating instead of overflowing.
pub fn retry_delay_ms(attempt: u32) -> u64 {
    let exponent = attempt.saturating_sub(1).min(63);
    RETRY_BASE_MS
        .saturating_mul(1u64 << exponent)
        .min(RETRY_MAX_MS)
}

fn is_captcha_or_login(status: u16, body: &str) -> bool {
    matches!(status, 403 | 429) && is_bench_refusal(body)
}

fn fetch_robots(fetcher: &dyn Fetcher, origin: &str, limits: &CrawlLimits) -> RobotsRules {
    let url = format!("{origin}/robots.txt");
    match fetcher.fetch(&url, limits) {
        Ok(page) if (200..300).contains(&page.status) => {
            RobotsRules::parse(&page.body, CRAWLER_USER_AGENT)
        }
        // A server error is not permission; be conservative.
        Ok(page) if page.status >= 500 => RobotsRules::disallow_all(CRAWLER_USER_AGENT),
        // 4xx or a transport failure: no policy is published, so the standard
        // crawl rule is allow-all.
        _ => RobotsRules::allow_all(CRAWLER_USER_AGENT),
    }
}

/// One robots.txt rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RobotsRule {
    /// `true` for `Allow`, `false` for `Disallow`.
    pub allow: bool,
    /// Path pattern as written, including `*`, `$`, and the leading slash.
    pub pattern: String,
}

/// Parsed robots.txt rules for one user-agent (RFC 9309 subset).
///
/// Supported: `User-agent`, `Allow`, `Disallow`, `Sitemap`, `*` and `$`
/// wildcards, group selection, longest-rule-pattern wins, and
/// allow-beats-disallow on a tie. An empty `Disallow:` means allow all.
/// Unknown directives are ignored.
///
/// Specificity is the length of the rule pattern, the common "most specific
/// path" interpretation for robots.txt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RobotsRules {
    user_agent: String,
    rules: Vec<RobotsRule>,
    sitemaps: Vec<String>,
}

impl RobotsRules {
    /// Parse a robots.txt body and select the rules that apply to `user_agent`.
    ///
    /// A matching specific group wins over `*`; if no specific group matches,
    /// the `*` groups are merged. Rules from every matching group are combined.
    pub fn parse(text: &str, user_agent: &str) -> Self {
        let (groups, sitemaps) = parse_robot_groups(text);
        let wanted = user_agent.trim().to_ascii_lowercase();
        let mut selected: Vec<RobotsRule> = Vec::new();
        let mut specific = false;
        for (agents, rules) in &groups {
            let is_specific = agents
                .iter()
                .any(|agent| agent != "*" && !agent.is_empty() && wanted.contains(agent.as_str()));
            if is_specific {
                specific = true;
                selected.extend(rules.iter().cloned());
            }
        }
        if !specific {
            for (agents, rules) in &groups {
                if agents.iter().any(|agent| agent == "*") {
                    selected.extend(rules.iter().cloned());
                }
            }
        }
        Self {
            user_agent: user_agent.to_string(),
            rules: selected,
            sitemaps,
        }
    }

    /// A rules object that allows every path.
    pub fn allow_all(user_agent: &str) -> Self {
        Self {
            user_agent: user_agent.to_string(),
            rules: Vec::new(),
            sitemaps: Vec::new(),
        }
    }

    /// A rules object that refuses every path.
    pub fn disallow_all(user_agent: &str) -> Self {
        Self {
            user_agent: user_agent.to_string(),
            rules: vec![RobotsRule {
                allow: false,
                pattern: "/".to_string(),
            }],
            sitemaps: Vec::new(),
        }
    }

    /// The user-agent these rules were selected for.
    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    /// The selected rules, in file order.
    pub fn rules(&self) -> &[RobotsRule] {
        &self.rules
    }

    /// Sitemap URLs declared anywhere in the file.
    pub fn sitemaps(&self) -> &[String] {
        &self.sitemaps
    }

    /// Whether `path` (path plus optional query) may be fetched.
    ///
    /// Empty rule set means allow all. The longest rule pattern wins; on an
    /// equal length an `Allow` beats a `Disallow`.
    pub fn allowed(&self, path: &str) -> bool {
        let mut best: Option<(usize, bool)> = None;
        for rule in &self.rules {
            if !glob_match(&rule.pattern, path) {
                continue;
            }
            let length = rule.pattern.chars().count();
            match best {
                Some((best_length, best_allow))
                    if length < best_length || (length == best_length && best_allow) => {}
                _ => best = Some((length, rule.allow)),
            }
        }
        best.map(|(_, allow)| allow).unwrap_or(true)
    }
}

type RobotGroups = Vec<(Vec<String>, Vec<RobotsRule>)>;

fn parse_robot_groups(text: &str) -> (RobotGroups, Vec<String>) {
    let mut groups: RobotGroups = Vec::new();
    let mut agents: Vec<String> = Vec::new();
    let mut rules: Vec<RobotsRule> = Vec::new();
    let mut in_rules = false;
    let mut sitemaps: Vec<String> = Vec::new();

    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        match key.as_str() {
            "user-agent" => {
                if in_rules {
                    if !agents.is_empty() {
                        groups.push((std::mem::take(&mut agents), std::mem::take(&mut rules)));
                    }
                    in_rules = false;
                }
                if !value.is_empty() {
                    agents.push(value.to_ascii_lowercase());
                }
            }
            "allow" | "disallow" => {
                if agents.is_empty() {
                    continue;
                }
                in_rules = true;
                let allow = key == "allow";
                if value.is_empty() {
                    // `Disallow:` with no value imposes no restriction; an
                    // empty Allow is meaningless.
                    continue;
                }
                rules.push(RobotsRule {
                    allow,
                    pattern: value.to_string(),
                });
            }
            "sitemap" if !value.is_empty() => {
                sitemaps.push(value.to_string());
            }
            _ => {}
        }
    }
    if !agents.is_empty() {
        groups.push((agents, rules));
    }
    (groups, sitemaps)
}

/// Tiny path matcher used by robots rules and crawl path limits.
///
/// - A pattern without `*` and without a trailing `$` is an exact **prefix**:
///   `/docs` matches `/docs`, `/docs/a`, and `/docs?x=1`.
/// - `*` matches any run of characters, including none.
/// - A trailing `$` anchors the match at the end, so `/a$` matches only `/a`.
/// - Unlike a regex there are no character classes, escaping, or alternation:
///   `*` is the only metacharacter besides the anchor. Multiple `*` work
///   because matching backtracks.
pub fn path_matches(pattern: &str, path: &str) -> bool {
    glob_match(pattern, path)
}

/// Wildcard match with prefix semantics unless the pattern ends in `$`.
fn glob_match(pattern: &str, text: &str) -> bool {
    let (pattern, anchored) = match pattern.strip_suffix('$') {
        Some(stripped) => (stripped, true),
        None => (pattern, false),
    };
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();

    let mut pattern_index = 0;
    let mut text_index = 0;
    let mut star: Option<usize> = None;
    let mut star_from = 0;

    while text_index < text.len() {
        if pattern_index < pattern.len() && pattern[pattern_index] == '*' {
            star = Some(pattern_index);
            star_from = text_index;
            pattern_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == text[text_index] {
            pattern_index += 1;
            text_index += 1;
            if !anchored && pattern_index == pattern.len() {
                return true;
            }
        } else if let Some(star_index) = star {
            // Let the last `*` swallow one more character and retry.
            star_from += 1;
            text_index = star_from;
            pattern_index = star_index + 1;
        } else {
            return false;
        }
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == '*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

/// `<loc>` values from a sitemap or sitemap-index body, entity-decoded and
/// deduplicated in document order.
pub fn sitemap_locs(body: &str) -> Vec<String> {
    let lower = body.to_ascii_lowercase();
    let mut locs = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cursor = 0;
    while let Some(offset) = lower[cursor..].find("<loc") {
        let tag_start = cursor + offset;
        let Some(open_offset) = lower[tag_start..].find('>') else {
            break;
        };
        let open_end = tag_start + open_offset + 1;
        let Some(close_offset) = lower[open_end..].find("</loc") else {
            break;
        };
        let close = open_end + close_offset;
        let decoded = decode_entities(body[open_end..close].trim());
        if !decoded.is_empty() && seen.insert(decoded.clone()) {
            locs.push(decoded);
        }
        cursor = close + "</loc".len();
    }
    locs
}

/// Whether a sitemap body is a sitemap index.
pub fn is_sitemap_index(body: &str) -> bool {
    body.to_ascii_lowercase().contains("<sitemapindex")
}

/// Discover page URLs from sitemap documents.
///
/// Each input URL is fetched. A sitemap index is expanded exactly one level:
/// its child sitemaps are fetched, their `<loc>` values are returned, and any
/// child that is itself an index is **not** expanded further (the depth-1
/// rule). Relative `<loc>` values resolve against the sitemap URL. Results are
/// deduplicated by canonical URL key. A transport error aborts discovery; a
/// non-2xx sitemap is skipped.
pub fn discover_sitemaps(
    fetcher: &dyn Fetcher,
    sitemap_urls: &[String],
    limits: &CrawlLimits,
) -> Result<Vec<String>> {
    let mut pages: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    for sitemap in sitemap_urls {
        let page = fetcher.fetch(sitemap, limits)?;
        if !(200..300).contains(&page.status) {
            continue;
        }
        if is_sitemap_index(&page.body) {
            for child in sitemap_locs(&page.body) {
                let child_url = resolve_link(sitemap, &child).unwrap_or(child);
                let child_page = fetcher.fetch(&child_url, limits)?;
                if (200..300).contains(&child_page.status) && !is_sitemap_index(&child_page.body) {
                    collect_locations(
                        sitemap_locs(&child_page.body),
                        &child_page.url,
                        &mut pages,
                        &mut seen,
                    );
                }
            }
        } else {
            collect_locations(sitemap_locs(&page.body), &page.url, &mut pages, &mut seen);
        }
    }
    Ok(pages)
}

fn collect_locations(
    locations: Vec<String>,
    base: &str,
    pages: &mut Vec<String>,
    seen: &mut BTreeSet<String>,
) {
    for location in locations {
        let resolved = resolve_link(base, &location).unwrap_or(location);
        let key = canonical_url_key(&resolved);
        if !key.is_empty() && seen.insert(key) {
            pages.push(resolved);
        }
    }
}

fn window<T: Clone>(items: &[T], offset: usize, limit: usize) -> Vec<T> {
    items.iter().skip(offset).take(limit).cloned().collect()
}

fn bounded_reason(reason: &str) -> String {
    if reason.chars().count() <= MAX_REASON_CHARS {
        return reason.to_string();
    }
    let mut bounded: String = reason.chars().take(MAX_REASON_CHARS).collect();
    bounded.push_str("...");
    bounded
}

/// Split an absolute http(s) URL into lowercased scheme, lowercased authority,
/// and path plus query. Fragments and userinfo are refused.
fn split_http(url: &str) -> Option<(String, String, String)> {
    let (scheme, rest) = url.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let rest = rest.split('#').next().unwrap_or("");
    let cut = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..cut];
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let tail = &rest[cut..];
    let path = if tail.is_empty() {
        "/".to_string()
    } else if tail.starts_with('?') {
        format!("/{tail}")
    } else {
        tail.to_string()
    };
    Some((
        scheme.to_ascii_lowercase(),
        authority.to_ascii_lowercase(),
        path,
    ))
}

/// Normalize one absolute http(s) URL: strip the fragment, lowercase the scheme
/// and authority, default the path to `/`.
fn normalize_http_url(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (scheme, authority, path) = split_http(trimmed)?;
    Some(format!("{scheme}://{authority}{path}"))
}

/// `scheme://authority` for the robots.txt lookup.
fn url_origin(url: &str) -> String {
    match split_http(url) {
        Some((scheme, authority, _)) => format!("{scheme}://{authority}"),
        None => String::new(),
    }
}

/// Path plus query used for robots and path rules.
fn url_path_for_robots(url: &str) -> String {
    match split_http(url) {
        Some((_, _, path)) => path,
        None => "/".to_string(),
    }
}

/// Resolve one raw href against the page URL. Non-http(s), fragment-only, and
/// userinfo links yield `None`.
pub(crate) fn resolve_link(base: &str, link: &str) -> Option<String> {
    let link = link.trim();
    if link.is_empty() || link.starts_with('#') {
        return None;
    }
    let (base_scheme, base_authority, base_path) = split_http(base)?;
    if let Some(rest) = link.strip_prefix("//") {
        return normalize_http_url(&format!("{base_scheme}://{rest}"));
    }
    if link.contains("://") {
        return normalize_http_url(link);
    }
    let link = link.split('#').next().unwrap_or("");
    if link.is_empty() {
        return None;
    }
    // A scheme-looking prefix we did not handle above (`mailto:`, `data:`,
    // `javascript:`, ...) is not a crawlable link.
    if let Some(colon) = link.find(':') {
        let boundary = link.find(['/', '?']).unwrap_or(link.len());
        if colon < boundary {
            return None;
        }
    }
    let joined = if link.starts_with('/') {
        link.to_string()
    } else if link.starts_with('?') {
        format!("{}{link}", base_path.split('?').next().unwrap_or("/"))
    } else {
        let directory = match base_path.rfind('/') {
            Some(index) => &base_path[..=index],
            None => "/",
        };
        format!("{directory}{link}")
    };
    let path = normalize_path(&joined);
    Some(format!("{base_scheme}://{base_authority}{path}"))
}

/// Remove `.` and `..` segments, collapse repeated separators, and keep the
/// query. The result always starts with `/`.
fn normalize_path(path: &str) -> String {
    let (path, query) = match path.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path, None),
    };
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    let mut normalized = String::from("/");
    normalized.push_str(&segments.join("/"));
    if path.ends_with('/') && !normalized.ends_with('/') {
        normalized.push('/');
    }
    if let Some(query) = query {
        normalized.push('?');
        normalized.push_str(query);
    }
    normalized
}

pub(crate) fn decode_entities(text: &str) -> String {
    let mut decoded = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(position) = rest.find('&') {
        decoded.push_str(&rest[..position]);
        let tail = &rest[position..];
        if let Some(semicolon) = tail.find(';') {
            if let Some(character) = decode_entity(&tail[1..semicolon]) {
                decoded.push(character);
                rest = &tail[semicolon + 1..];
                continue;
            }
        }
        decoded.push('&');
        rest = &tail[1..];
    }
    decoded.push_str(rest);
    decoded
}

fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => {
            if let Some(hex) = entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
            {
                u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
            } else {
                entity
                    .strip_prefix('#')
                    .and_then(|decimal| decimal.parse::<u32>().ok())
                    .and_then(char::from_u32)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    type CallLog = Rc<RefCell<Vec<String>>>;

    enum Reply {
        Page {
            status: u16,
            body: String,
            links: Vec<String>,
        },
        Error,
    }

    struct ScriptFetcher {
        pages: RefCell<BTreeMap<String, Reply>>,
        calls: CallLog,
    }

    impl ScriptFetcher {
        fn new() -> Self {
            Self {
                pages: RefCell::new(BTreeMap::new()),
                calls: Rc::new(RefCell::new(Vec::new())),
            }
        }

        fn sharing(log: CallLog) -> Self {
            Self {
                pages: RefCell::new(BTreeMap::new()),
                calls: log,
            }
        }

        fn with_page(self, url: &str, status: u16, body: &str, links: &[&str]) -> Self {
            self.pages.borrow_mut().insert(
                url.to_string(),
                Reply::Page {
                    status,
                    body: body.to_string(),
                    links: links.iter().map(|link| (*link).to_string()).collect(),
                },
            );
            self
        }

        fn with_error(self, url: &str) -> Self {
            self.pages
                .borrow_mut()
                .insert(url.to_string(), Reply::Error);
            self
        }

        fn page_calls(&self) -> Vec<String> {
            self.calls
                .borrow()
                .iter()
                .filter(|url| !url.ends_with("/robots.txt"))
                .cloned()
                .collect()
        }
    }

    impl Fetcher for ScriptFetcher {
        fn fetch(&self, url: &str, _limits: &CrawlLimits) -> Result<FetchedPage> {
            self.calls.borrow_mut().push(url.to_string());
            let reply = self.pages.borrow().get(url).map(|reply| match reply {
                Reply::Page {
                    status,
                    body,
                    links,
                } => Ok((*status, body.clone(), links.clone())),
                Reply::Error => Err(()),
            });
            match reply {
                Some(Ok((status, body, links))) => Ok(FetchedPage {
                    url: url.to_string(),
                    status,
                    bytes: body.len() as u64,
                    body,
                    links,
                }),
                Some(Err(())) => Err(ZeroError::new(
                    ErrorCode::Unavailable,
                    "scripted transport failure",
                )),
                None => Ok(FetchedPage {
                    url: url.to_string(),
                    status: 404,
                    body: String::new(),
                    links: Vec::new(),
                    bytes: 0,
                }),
            }
        }
    }

    fn limits(max_pages: usize, max_depth: usize) -> CrawlLimits {
        CrawlLimits {
            max_pages,
            max_depth,
            max_bytes: 10_000_000,
            max_retries: 0,
            allowed_paths: Vec::new(),
            denied_paths: Vec::new(),
            concurrency: 1,
        }
    }

    fn seed_session(store: &CrawlStore, seeds: &[&str], limits: CrawlLimits) -> CrawlSession {
        CrawlSession::create(
            store.clone(),
            "job",
            seeds.iter().map(|seed| (*seed).to_string()),
            limits,
            1_000,
        )
        .expect("create job")
    }

    fn run_to_idle(session: &mut CrawlSession, fetcher: &dyn Fetcher, mut now_ms: u64) -> u64 {
        for _ in 0..200 {
            match session.step(fetcher, now_ms).expect("step") {
                StepOutcome::Idle => return now_ms,
                _ => now_ms += 10_000,
            }
        }
        panic!("crawl did not settle");
    }

    #[test]
    fn bfs_order_respects_depth() {
        let dir = tempfile::tempdir().unwrap();
        let store = CrawlStore::new(dir.path().join("job.json"));
        let fetcher = ScriptFetcher::new()
            .with_page(
                "https://a.example/",
                200,
                "seed",
                &["/one", "https://b.example/two"],
            )
            .with_page("https://a.example/one", 200, "one", &["/deep"])
            .with_page("https://b.example/two", 200, "two", &[])
            .with_page("https://a.example/deep", 200, "deep", &["/too-deep"])
            .with_page("https://a.example/too-deep", 200, "nope", &[]);

        let mut session = seed_session(&store, &["https://a.example/"], limits(10, 2));
        let mut order = Vec::new();
        for step in 0..10 {
            match session.step(&fetcher, 1_000 + step * 10).unwrap() {
                StepOutcome::Fetched { url, .. } => order.push(url),
                StepOutcome::Idle => break,
                other => panic!("unexpected outcome {other:?}"),
            }
        }

        assert_eq!(
            order,
            [
                "https://a.example/",
                "https://a.example/one",
                "https://b.example/two",
                "https://a.example/deep",
            ]
        );
        assert_eq!(session.job().completed.len(), 4);
        // `too-deep` is depth 3 and was never scheduled or fetched.
        assert!(!fetcher
            .page_calls()
            .iter()
            .any(|url| url.contains("too-deep")));
    }

    #[test]
    fn duplicate_and_canonical_urls_are_fetched_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = CrawlStore::new(dir.path().join("job.json"));
        let fetcher = ScriptFetcher::new()
            .with_page(
                "https://example.com/a?x=1",
                200,
                "seed",
                &["/a?y=2#frag", "HTTPS://EXAMPLE.COM/a/", "/b", "/b?utm=1"],
            )
            .with_page("https://example.com/b", 200, "b", &[]);

        let mut session = seed_session(&store, &["https://Example.com/a?x=1"], limits(10, 1));
        run_to_idle(&mut session, &fetcher, 1_000);

        assert_eq!(
            fetcher.page_calls(),
            ["https://example.com/a?x=1", "https://example.com/b"]
        );
        assert_eq!(session.job().completed.len(), 2);
        assert_eq!(session.job().seen.len(), 2);
    }

    #[test]
    fn page_limit_stops_before_exceeding() {
        let dir = tempfile::tempdir().unwrap();
        let store = CrawlStore::new(dir.path().join("job.json"));
        let fetcher = ScriptFetcher::new()
            .with_page("https://x.example/1", 200, "1", &["/2"])
            .with_page("https://x.example/2", 200, "2", &["/3"])
            .with_page("https://x.example/3", 200, "3", &["/4"])
            .with_page("https://x.example/4", 200, "4", &[]);

        let mut session = seed_session(&store, &["https://x.example/1"], limits(2, 3));
        assert!(matches!(
            session.step(&fetcher, 1_000).unwrap(),
            StepOutcome::Fetched { .. }
        ));
        assert!(matches!(
            session.step(&fetcher, 2_000).unwrap(),
            StepOutcome::Fetched { .. }
        ));
        assert_eq!(
            session.step(&fetcher, 3_000).unwrap(),
            StepOutcome::LimitReached { limit: "max_pages" }
        );

        assert_eq!(session.job().completed.len(), 2);
        assert_eq!(session.job().state, CrawlState::Completed);
        assert_eq!(fetcher.page_calls().len(), 2);
    }

    #[test]
    fn byte_limit_stops_before_exceeding() {
        let dir = tempfile::tempdir().unwrap();
        let store = CrawlStore::new(dir.path().join("job.json"));
        let body = "0123456789"; // 10 bytes
        let fetcher = ScriptFetcher::new()
            .with_page("https://x.example/1", 200, body, &["/2"])
            .with_page("https://x.example/2", 200, body, &["/3"])
            .with_page("https://x.example/3", 200, body, &[]);

        let mut crafted = limits(10, 3);
        crafted.max_bytes = 25;
        let mut session = seed_session(&store, &["https://x.example/1"], crafted);

        assert!(matches!(
            session.step(&fetcher, 1_000).unwrap(),
            StepOutcome::Fetched { .. }
        ));
        assert!(matches!(
            session.step(&fetcher, 2_000).unwrap(),
            StepOutcome::Fetched { .. }
        ));
        assert_eq!(
            session.step(&fetcher, 3_000).unwrap(),
            StepOutcome::LimitReached { limit: "max_bytes" }
        );
        assert_eq!(session.job().completed.len(), 2);
        assert_eq!(session.job().bytes_fetched(), 20);
        assert!(session.job().bytes_fetched() <= 25);
    }

    #[test]
    fn path_rules_allow_deny_and_anchor() {
        assert!(path_matches("/docs", "/docs"));
        assert!(path_matches("/docs", "/docs/a"));
        assert!(!path_matches("/docs", "/documentation"));
        assert!(path_matches("/docs/*", "/docs/a/b"));
        assert!(!path_matches("/docs/*", "/docs"));
        assert!(path_matches("/*.pdf$", "/paper.pdf"));
        assert!(!path_matches("/*.pdf$", "/paper.pdf?download=1"));
        assert!(path_matches("/a*b$", "/axxb"));
        assert!(!path_matches("/a*b$", "/axxbc"));
        assert!(path_matches("/a*b*c$", "/axxbyyc"));
        assert!(!path_matches("/a*b*c$", "/axxbyy"));
        assert!(path_matches("/*/edit$", "/wiki/page/edit"));
        assert!(path_matches("*", "/anything"));

        let limits = CrawlLimits {
            allowed_paths: vec!["/docs/*".to_string(), "/blog$".to_string()],
            denied_paths: vec!["/docs/private*".to_string()],
            ..CrawlLimits::default()
        };
        assert!(limits.path_allowed("/docs/guide"));
        assert!(!limits.path_allowed("/docs/private/key"));
        assert!(limits.path_allowed("/blog"));
        assert!(!limits.path_allowed("/blog/post"));
        assert!(!limits.path_allowed("/other"));
    }

    #[test]
    fn denied_paths_are_skipped_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        let store = CrawlStore::new(dir.path().join("job.json"));
        let fetcher = ScriptFetcher::new()
            .with_page("https://x.example/", 200, "seed", &["/private/a", "/ok"])
            .with_page("https://x.example/ok", 200, "ok", &[]);

        let mut limits = limits(10, 2);
        limits.denied_paths.push("/private*".to_string());
        let mut session = seed_session(&store, &["https://x.example/"], limits);
        run_to_idle(&mut session, &fetcher, 1_000);

        assert_eq!(
            fetcher.page_calls(),
            ["https://x.example/", "https://x.example/ok"]
        );
        assert_eq!(session.job().completed.len(), 2);
        assert_eq!(session.job().skipped, 1);
        assert_eq!(session.job().progress().skipped, 1);
    }

    #[test]
    fn retries_back_off_then_fail() {
        let dir = tempfile::tempdir().unwrap();
        let store = CrawlStore::new(dir.path().join("job.json"));
        let fetcher = ScriptFetcher::new().with_error("https://x.example/broken");

        let mut limits = limits(10, 0);
        limits.max_retries = 2;
        let mut session = seed_session(&store, &["https://x.example/broken"], limits);

        assert_eq!(
            session.step(&fetcher, 1_000).unwrap(),
            StepOutcome::Retry {
                url: "https://x.example/broken".to_string(),
                attempt: 1,
                next_attempt_ms: 2_000,
            }
        );
        assert_eq!(
            session.step(&fetcher, 1_500).unwrap(),
            StepOutcome::Waiting {
                url: "https://x.example/broken".to_string(),
                next_attempt_ms: 2_000,
            }
        );
        assert_eq!(fetcher.page_calls().len(), 1, "no fetch while backing off");

        assert_eq!(
            session.step(&fetcher, 2_000).unwrap(),
            StepOutcome::Retry {
                url: "https://x.example/broken".to_string(),
                attempt: 2,
                next_attempt_ms: 4_000,
            }
        );
        match session.step(&fetcher, 4_000).unwrap() {
            StepOutcome::Failed { url, reason } => {
                assert_eq!(url, "https://x.example/broken");
                assert!(reason.contains("scripted transport failure"), "{reason}");
            }
            other => panic!("expected failure, got {other:?}"),
        }

        assert_eq!(fetcher.page_calls().len(), 3);
        assert_eq!(session.job().failed.len(), 1);
        assert_eq!(session.job().failed[0].attempts, 3);
        assert_eq!(session.job().state, CrawlState::Failed);
    }

    #[test]
    fn retry_delay_doubles_and_caps() {
        assert_eq!(retry_delay_ms(1), 1_000);
        assert_eq!(retry_delay_ms(2), 2_000);
        assert_eq!(retry_delay_ms(3), 4_000);
        assert_eq!(retry_delay_ms(10), 60_000);
        assert_eq!(retry_delay_ms(u32::MAX), 60_000);
    }

    #[test]
    fn failure_list_records_status_and_bounded_reason() {
        let dir = tempfile::tempdir().unwrap();
        let store = CrawlStore::new(dir.path().join("job.json"));
        let fetcher = ScriptFetcher::new()
            .with_page("https://x.example/500", 500, "boom", &[])
            .with_page("https://x.example/404", 404, "gone", &[]);

        let mut session = seed_session(
            &store,
            &["https://x.example/500", "https://x.example/404"],
            limits(10, 0),
        );
        run_to_idle(&mut session, &fetcher, 1_000);

        assert_eq!(session.job().failed.len(), 2);
        assert!(session
            .job()
            .failed
            .iter()
            .any(|failure| failure.reason == "HTTP status 500"));
        assert!(session
            .job()
            .failed
            .iter()
            .any(|failure| failure.reason == "HTTP status 404"));
        assert_eq!(session.job().state, CrawlState::Failed);
    }

    #[test]
    fn robots_allow_disallow_longest_and_tie() {
        let rules = RobotsRules::parse(
            "User-agent: *\nDisallow: /private\nAllow: /private/public\n",
            "zero-crawler",
        );
        assert!(rules.allowed("/"));
        assert!(!rules.allowed("/private"));
        assert!(!rules.allowed("/private/key"));
        assert!(rules.allowed("/private/public/page"));

        let tie = RobotsRules::parse(
            "User-agent: *\nDisallow: /secret\nAllow: /secret\n",
            "zero-crawler",
        );
        assert!(tie.allowed("/secret"), "allow wins an equal-length tie");

        let empty = RobotsRules::parse("User-agent: *\nDisallow:\n", "zero-crawler");
        assert!(empty.allowed("/anything"));

        let wildcard = RobotsRules::parse("User-agent: *\nDisallow: /*.pdf$\n", "zero-crawler");
        assert!(!wildcard.allowed("/paper.pdf"));
        assert!(wildcard.allowed("/paper.html"));
    }

    #[test]
    fn robots_group_selection_prefers_specific_agent() {
        let text = "\
User-agent: other-bot
Disallow: /

User-agent: zero-crawler
Disallow: /nope

Sitemap: https://example.com/sitemap.xml

User-agent: *
Disallow: /
";
        let rules = RobotsRules::parse(text, "zero-crawler");
        assert!(rules.allowed("/allowed"));
        assert!(!rules.allowed("/nope"));
        assert_eq!(rules.sitemaps().len(), 1);
        assert_eq!(rules.sitemaps()[0], "https://example.com/sitemap.xml");

        let wildcard = RobotsRules::parse(text, "unknown-bot");
        assert!(!wildcard.allowed("/allowed"), "falls back to the * group");
    }

    #[test]
    fn robots_blocked_are_separate_from_failures() {
        let dir = tempfile::tempdir().unwrap();
        let store = CrawlStore::new(dir.path().join("job.json"));
        let fetcher = ScriptFetcher::new()
            .with_page(
                "https://x.example/robots.txt",
                200,
                "User-agent: *\nDisallow: /blocked\n",
                &[],
            )
            .with_page("https://x.example/blocked", 200, "must not fetch", &[])
            .with_page("https://x.example/open", 200, "open", &[]);

        let mut session = seed_session(
            &store,
            &["https://x.example/blocked", "https://x.example/open"],
            limits(10, 0),
        );
        let mut outcomes = Vec::new();
        for step in 0..5 {
            outcomes.push(session.step(&fetcher, 1_000 + step * 10).unwrap());
        }

        assert_eq!(
            outcomes[0],
            StepOutcome::RobotsBlocked {
                url: "https://x.example/blocked".to_string(),
                status: 0,
            }
        );
        assert_eq!(session.job().robots_blocked.len(), 1);
        assert!(session.job().failed.is_empty());
        assert!(!fetcher
            .page_calls()
            .iter()
            .any(|url| url.ends_with("/blocked")));
        // The open page still crawls.
        assert_eq!(session.job().completed.len(), 1);
    }

    #[test]
    fn captcha_status_is_robots_blocked_not_failed() {
        let dir = tempfile::tempdir().unwrap();
        let store = CrawlStore::new(dir.path().join("job.json"));
        let fetcher = ScriptFetcher::new().with_page(
            "https://x.example/wall",
            429,
            "Please verify you are human",
            &[],
        );

        let mut session = seed_session(&store, &["https://x.example/wall"], limits(10, 0));
        assert_eq!(
            session.step(&fetcher, 1_000).unwrap(),
            StepOutcome::RobotsBlocked {
                url: "https://x.example/wall".to_string(),
                status: 429,
            }
        );
        assert_eq!(session.job().robots_blocked.len(), 1);
        assert_eq!(session.job().robots_blocked[0].status, 429);
        assert!(session.job().failed.is_empty());
    }

    #[test]
    fn plain_403_without_marker_is_a_retryable_failure() {
        let dir = tempfile::tempdir().unwrap();
        let store = CrawlStore::new(dir.path().join("job.json"));
        let fetcher = ScriptFetcher::new().with_page("https://x.example/403", 403, "denied", &[]);

        let mut session = seed_session(&store, &["https://x.example/403"], limits(10, 0));
        assert!(matches!(
            session.step(&fetcher, 1_000).unwrap(),
            StepOutcome::Failed { .. }
        ));
        assert!(session.job().robots_blocked.is_empty());
    }

    #[test]
    fn cancel_stops_further_fetches() {
        let dir = tempfile::tempdir().unwrap();
        let store = CrawlStore::new(dir.path().join("job.json"));
        let fetcher = ScriptFetcher::new()
            .with_page("https://x.example/1", 200, "1", &["/2"])
            .with_page("https://x.example/2", 200, "2", &[]);

        let mut session = seed_session(&store, &["https://x.example/1"], limits(10, 2));
        session.step(&fetcher, 1_000).unwrap();
        let calls_before = fetcher.page_calls().len();

        session.cancel(2_000).unwrap();
        assert_eq!(session.job().state, CrawlState::Cancelled);
        assert_eq!(
            session.step(&fetcher, 3_000).unwrap(),
            StepOutcome::Cancelled
        );
        assert_eq!(fetcher.page_calls().len(), calls_before);

        // The cancelled state is durable.
        drop(session);
        let reopened = CrawlSession::open(store).unwrap();
        assert_eq!(reopened.job().state, CrawlState::Cancelled);
    }

    #[test]
    fn progress_and_paging_windows() {
        let mut job = CrawlJob::new(
            "paged",
            vec!["https://x.example/".to_string()],
            limits(10, 1),
            100,
        );
        job.state = CrawlState::Scraping;
        for index in 0..3 {
            job.completed.push(CrawlResult {
                url: format!("https://x.example/{index}"),
                status: 200,
                bytes: 10,
                depth: 0,
                fetched_at_ms: 1_000 + index as u64,
            });
        }
        job.failed.push(CrawlFailure {
            url: "https://x.example/fail".to_string(),
            attempts: 1,
            reason: "boom".to_string(),
        });
        job.robots_blocked.push(RobotsBlock {
            url: "https://x.example/blocked".to_string(),
            status: 0,
            reason: "disallowed by robots.txt".to_string(),
        });
        job.skipped = 4;

        let progress = job.progress();
        assert_eq!(progress.completed, 3);
        assert_eq!(progress.failed, 1);
        assert_eq!(progress.robots_blocked, 1);
        assert_eq!(progress.skipped, 4);
        assert_eq!(progress.bytes, 30);
        assert_eq!(progress.queued, 1);
        assert_eq!(progress.max_pages, 10);
        assert_eq!(progress.max_depth, 1);

        let first = job.page(0, 1);
        assert_eq!(first.completed.len(), 1);
        assert_eq!(first.completed[0].url, "https://x.example/0");
        assert_eq!(first.failed.len(), 1);
        assert_eq!(first.robots_blocked.len(), 1);
        assert_eq!(first.total_completed, 3);

        let second = job.page(1, 1);
        assert_eq!(second.completed.len(), 1);
        assert_eq!(second.completed[0].url, "https://x.example/1");
        assert_eq!(second.failed.len(), 0);

        let tail = job.page(2, 10);
        assert_eq!(tail.completed.len(), 1);
        assert_eq!(tail.completed[0].url, "https://x.example/2");

        assert!(job.page(9, 5).completed.is_empty());
        assert!(job.page(0, 0).completed.is_empty());
    }

    #[test]
    fn sitemap_locs_decode_entities_and_deduplicate() {
        let body = r#"<?xml version="1.0"?>
<urlset>
  <url><loc>https://example.com/a?x=1&amp;y=2</loc></url>
  <url><loc>https://example.com/a?x=1&amp;y=2</loc></url>
  <url><loc>  https://example.com/b  </loc></url>
  <url><loc>https://example.com/&#x63;</loc></url>
</urlset>"#;
        assert_eq!(
            sitemap_locs(body),
            [
                "https://example.com/a?x=1&y=2",
                "https://example.com/b",
                "https://example.com/c",
            ]
        );
        assert!(!is_sitemap_index(body));
        assert!(is_sitemap_index("<sitemapindex></sitemapindex>"));
    }

    #[test]
    fn sitemap_index_expands_one_level_and_dedupes() {
        let fetcher = ScriptFetcher::new()
            .with_page(
                "https://example.com/sitemap-index.xml",
                200,
                r#"<sitemapindex>
                    <sitemap><loc>https://example.com/s1.xml</loc></sitemap>
                    <sitemap><loc>https://example.com/s2.xml</loc></sitemap>
                </sitemapindex>"#,
                &[],
            )
            .with_page(
                "https://example.com/s1.xml",
                200,
                r#"<urlset>
                    <url><loc>https://example.com/a</loc></url>
                    <url><loc>https://example.com/shared</loc></url>
                </urlset>"#,
                &[],
            )
            .with_page(
                "https://example.com/s2.xml",
                200,
                r#"<urlset>
                    <url><loc>https://example.com/shared</loc></url>
                    <url><loc>https://example.com/b</loc></url>
                </urlset>"#,
                &[],
            );

        let pages = discover_sitemaps(
            &fetcher,
            &["https://example.com/sitemap-index.xml".to_string()],
            &limits(10, 1),
        )
        .unwrap();
        assert_eq!(
            pages,
            [
                "https://example.com/a",
                "https://example.com/shared",
                "https://example.com/b",
            ]
        );
    }

    #[test]
    fn sitemap_index_expansion_stops_at_depth_one() {
        let fetcher = ScriptFetcher::new()
            .with_page(
                "https://example.com/index.xml",
                200,
                r#"<sitemapindex>
                    <sitemap><loc>https://example.com/s1.xml</loc></sitemap>
                    <sitemap><loc>https://example.com/nested.xml</loc></sitemap>
                </sitemapindex>"#,
                &[],
            )
            .with_page(
                "https://example.com/s1.xml",
                200,
                r#"<urlset><url><loc>https://example.com/a</loc></url></urlset>"#,
                &[],
            )
            .with_page(
                "https://example.com/nested.xml",
                200,
                r#"<sitemapindex>
                    <sitemap><loc>https://example.com/grand.xml</loc></sitemap>
                </sitemapindex>"#,
                &[],
            )
            .with_page(
                "https://example.com/grand.xml",
                200,
                r#"<urlset><url><loc>https://example.com/grand</loc></url></urlset>"#,
                &[],
            );

        let pages = discover_sitemaps(
            &fetcher,
            &["https://example.com/index.xml".to_string()],
            &limits(10, 1),
        )
        .unwrap();
        assert_eq!(pages, ["https://example.com/a"]);
        assert!(
            !fetcher
                .page_calls()
                .iter()
                .any(|url| url.ends_with("grand.xml")),
            "a nested index must not be expanded again"
        );
    }

    #[test]
    fn kill_and_resume_preserves_the_job_and_never_refetches() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("job.json");
        let store = CrawlStore::new(path.clone());

        let log: CallLog = Rc::new(RefCell::new(Vec::new()));
        let seeds: Vec<String> = (0..10)
            .map(|index| format!("https://x.example/{index}"))
            .collect();
        let mut fetcher = ScriptFetcher::sharing(Rc::clone(&log));
        for seed in &seeds {
            fetcher = fetcher.with_page(seed, 200, "body", &[]);
        }

        let mut session =
            CrawlSession::create(store.clone(), "resume", seeds.clone(), limits(10, 0), 1_000)
                .unwrap();
        for step in 0..3 {
            assert!(matches!(
                session.step(&fetcher, 1_000 + step * 10).unwrap(),
                StepOutcome::Fetched { .. }
            ));
        }

        let before = serde_json::to_string(session.job()).unwrap();
        let before_frontier = session.job().frontier.clone();
        assert_eq!(session.job().completed.len(), 3);
        assert_eq!(session.job().frontier.len(), 7);
        drop(session);
        drop(fetcher);
        drop(store);

        let store = CrawlStore::new(path.clone());
        let mut resumed = CrawlSession::open(store).unwrap();
        assert_eq!(serde_json::to_string(resumed.job()).unwrap(), before);
        assert_eq!(resumed.job().frontier, before_frontier);
        assert_eq!(resumed.job().completed.len(), 3);
        assert_eq!(resumed.job().seen.len(), 10);

        let resumed_log: CallLog = Rc::new(RefCell::new(Vec::new()));
        let mut resumed_fetcher = ScriptFetcher::sharing(Rc::clone(&resumed_log));
        for seed in &seeds {
            resumed_fetcher = resumed_fetcher.with_page(seed, 200, "body", &[]);
        }
        run_to_idle(&mut resumed, &resumed_fetcher, 10_000);

        assert_eq!(resumed.job().completed.len(), 10);
        assert_eq!(resumed.job().state, CrawlState::Completed);
        // Only the seven unseen pages were fetched on the resumed run.
        let resumed_pages: Vec<String> = resumed_log
            .borrow()
            .iter()
            .filter(|url| !url.ends_with("/robots.txt"))
            .cloned()
            .collect();
        assert_eq!(resumed_pages.len(), 7);

        let all: Vec<String> = log
            .borrow()
            .iter()
            .chain(resumed_log.borrow().iter())
            .filter(|url| !url.ends_with("/robots.txt"))
            .cloned()
            .collect();
        let mut unique = BTreeSet::new();
        for url in &all {
            assert!(unique.insert(url.clone()), "refetched {url}");
        }
        assert_eq!(unique.len(), 10);
    }

    #[test]
    fn corrupt_store_is_a_typed_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("job.json");
        std::fs::write(&path, "{not json").unwrap();

        let error = CrawlStore::new(path.clone()).load().unwrap_err();
        assert_eq!(error.code(), ErrorCode::Corrupt);
        assert!(error.message().contains("corrupt"), "{}", error.message());
    }

    #[test]
    fn unknown_schema_is_refused_but_the_job_still_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("job.json");
        let store = CrawlStore::new(path.clone());
        let job = CrawlJob::new(
            "schema",
            vec!["https://x.example/".to_string()],
            limits(4, 1),
            500,
        );
        store.create(&job).unwrap();
        assert_eq!(store.load().unwrap(), job);
        assert!(store.create(&job).is_err(), "create must not overwrite");

        let mut document: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        document["schema"] = serde_json::json!(CRAWL_SCHEMA_VERSION + 1);
        std::fs::write(&path, serde_json::to_string(&document).unwrap()).unwrap();

        let error = store.load().unwrap_err();
        assert_eq!(error.code(), ErrorCode::SchemaVersion);
        assert!(error.message().contains("schema"), "{}", error.message());
    }

    #[test]
    fn store_list_summarizes_jobs_and_skips_noise() {
        let dir = tempfile::tempdir().unwrap();
        let first = CrawlStore::new(dir.path().join("a.json"));
        let second = CrawlStore::new(dir.path().join("b.json"));
        let job = CrawlJob::new(
            "first",
            vec!["https://x.example/".to_string()],
            limits(4, 1),
            700,
        );
        first.create(&job).unwrap();
        second
            .create(&CrawlJob::new(
                "second",
                vec!["https://y.example/".to_string()],
                limits(4, 1),
                800,
            ))
            .unwrap();
        std::fs::write(dir.path().join("notes.txt"), "ignore me").unwrap();
        std::fs::write(dir.path().join("bad.json"), "{").unwrap();

        let summaries = CrawlStore::list(dir.path()).unwrap();
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].id, "first");
        assert_eq!(summaries[0].state, CrawlState::Queued);
        assert_eq!(summaries[0].queued, 1);
        assert_eq!(summaries[1].id, "second");
        assert!(CrawlStore::list(dir.path().join("missing"))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn relative_links_resolve_against_the_page() {
        assert_eq!(
            resolve_link("https://example.com/docs/page", "../a?x=1#f").as_deref(),
            Some("https://example.com/a?x=1")
        );
        assert_eq!(
            resolve_link("https://example.com/docs/page", "/root").as_deref(),
            Some("https://example.com/root")
        );
        assert_eq!(
            resolve_link("https://example.com/docs/page?old=1", "?page=2").as_deref(),
            Some("https://example.com/docs/page?page=2")
        );
        assert_eq!(
            resolve_link("https://example.com/docs/page", "//other.example/x").as_deref(),
            Some("https://other.example/x")
        );
        assert_eq!(resolve_link("https://example.com/", "#top"), None);
        assert_eq!(resolve_link("https://example.com/", "mailto:a@b"), None);
    }
}
