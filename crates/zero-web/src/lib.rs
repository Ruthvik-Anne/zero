//! `zero-web` — see `architecture.md` section 5 for the module contract.
//!
//! Implements the keyless search adapter contract, reciprocal-rank fusion
//! (WEB-01, WEB-02), result filters (WEB-03), date provenance (WEB-04), the
//! SQLite FTS5 search cache (WEB-06), per-engine resilience policy (WEB-05),
//! the SSRF/egress gate (WEB-16, WEB-17), crawl budgets (WEB-11, WEB-21), the
//! untrusted-content envelope (WEB-19), archive safety (WEB-10, WEB-18), and
//! resumable crawl jobs with robots.txt, sitemaps, limits, and retries
//! (WEB-11, WEB-12), URL discovery and schema-validated extraction
//! (WEB-07, WEB-13, WEB-14), the fetch reader for HTML, text, office
//! documents, EPUB, and PDF (WEB-04, WEB-08, WEB-10), the DevTools-protocol
//! browser seam (WEB-15, T-WEB-08), and the headless-browser JS fallback with a
//! checksummed install and per-session profiles (WEB-09, T-WEB-05). The real
//! WebSocket browser transport is deferred; the crawler drives a
//! caller-supplied `Fetcher` and the browser session a caller-supplied
//! `CdpTransport`. The deterministic loss/latency/partition simulator and the
//! network-impairment suite live in `impairment` (TST-05); the NAT matrix is an
//! external `zero-mesh` gate.

pub mod archive;
pub mod browser;
pub mod budget;
pub mod cache;
pub mod crawl;
pub mod egress;
pub mod extract;
pub mod filter;
pub mod headless;
pub mod impairment;
pub mod reader;
pub mod resilience;
pub mod search;

pub use archive::{
    extract, inspect, ArchiveEntryInfo, ArchiveError, ArchiveLimits, ArchiveReport, ArchiveResult,
    ArchiveSource, ExtractionError, ExtractionReport,
};

pub use browser::{
    BrowserConfig, BrowserSession, CdpDownload, CdpEvent, CdpTransport, DEFAULT_BROWSER_TIMEOUT_MS,
    DEFAULT_MAX_DOWNLOAD_BYTES, DEFAULT_MAX_EVALUATE_BYTES, DEFAULT_MAX_SCREENSHOT_BYTES,
    DEFAULT_POLL_INTERVAL_MS, MAX_CDP_ERROR_CHARS, MAX_POLL_PROBES,
};

pub use budget::{
    BudgetLimits, BudgetPermit, BudgetRemaining, BudgetSpent, CrawlBudget, PageCost,
    UntrustedContent, MAX_RENDERED_BYTES, TRUNCATION_MARKER, UNTRUSTED_DATA_LABEL,
    UNTRUSTED_WARNING,
};

pub use egress::{
    classify_address, AddressClass, EgressGuard, EgressScheme, NetworkPolicy, PinnedDestination,
    PinnedRequest, Resolver, SystemResolver, DEFAULT_MAX_REDIRECTS,
};

pub use cache::{IndexHit, SearchCache, TtlPolicy, DEFAULT_TTL_MS};
pub use crawl::{
    discover_sitemaps, is_sitemap_index, path_matches, retry_delay_ms, sitemap_locs, CrawlFailure,
    CrawlJob, CrawlLimits, CrawlPage, CrawlProgress, CrawlResult, CrawlSession, CrawlState,
    CrawlStore, FetchedPage, Fetcher, FrontierEntry, JobSummary, RobotsBlock, RobotsRule,
    RobotsRules, StepOutcome, CRAWLER_USER_AGENT, CRAWL_SCHEMA_VERSION, DEFAULT_CONCURRENCY,
    DEFAULT_MAX_BYTES, DEFAULT_MAX_DEPTH, DEFAULT_MAX_PAGES, DEFAULT_MAX_RETRIES, MAX_REASON_CHARS,
    RETRY_BASE_MS, RETRY_MAX_MS,
};
pub use extract::{
    extract as extract_json, extract_from_content_type, extract_html, map_urls, validate,
    validate_schema, Extraction, MapLimits, Schema, SchemaType, UrlMap, DEFAULT_MAX_PER_PAGE,
    DEFAULT_MAX_URLS, MAX_ATTRIBUTES_PER_TAG, MAX_ATTRIBUTE_CHARS, MAX_ENUM_VALUES,
    MAX_FIELD_CHARS, MAX_HTML_TAGS, MAX_SCHEMA_DEPTH, MAX_SCHEMA_NODES, MAX_SOURCE_BYTES,
    MAX_VALUE_DEPTH,
};
pub use filter::{
    apply, canonical_host, category_for, parse_timestamp_ms, DateSource, FilteredResponse,
    FilteredResult, Freshness, Provenance, SearchFilters, DAY_MS,
};
pub use headless::{
    find_system_browser, install_archive_limits, ArchiveKind, BrowserCandidate, BrowserChannel,
    BrowserProcess, Downloader, HeadlessBrowser, HeadlessConfig, InstallManifest, InstalledBrowser,
    Installer, LaunchRequest, ProcessOutput, Profile, RenderedPage, SystemProcess,
    DEFAULT_HEADLESS_TIMEOUT_MS, DEFAULT_MAX_HEADLESS_OUTPUT_BYTES, DEFAULT_MAX_STDERR_BYTES,
    MAX_DATA_URL_BYTES, MAX_INLINE_HTML_BYTES, MAX_STDERR_CHARS,
};
pub use impairment::{
    assert_suite_green, run_impairment_suite, simulate_request, simulate_sequence, Impairment,
    ImpairmentReport, ImpairmentSuiteError, NetworkModel, ScenarioResult, SimulatedEngine,
    SplitMix64, MAX_LOSS_BPS, NAT_MATRIX_CELLS, NAT_MATRIX_GATE, REQUIRED_EXTERNAL_SUITES,
    SCENARIO_BASELINE, SCENARIO_HIGH_LOSS, SCENARIO_LATENCY_OVER, SCENARIO_LATENCY_WITHIN,
    SCENARIO_LOSS_10, SCENARIO_PARTITION,
};
pub use reader::{
    detect_format, read, read_file, DocumentFormat, ReadDocument, ReaderLimits,
    DEFAULT_MAX_INPUT_BYTES, DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_MAX_TAGS, DEFAULT_READER_MAX_PAGES,
    MAX_LINKS, MAX_TABLE_CELL_CHARS, MAX_TABLE_COLS, MAX_TABLE_ROWS, MAX_TITLE_CHARS,
    READER_TRUNCATION_MARKER,
};
pub use resilience::{
    is_bench_refusal, next_backoff_ms, BreakerState, CircuitBreaker, EnginePolicy, EngineState,
    ResilientSearch, BENCH_MARKERS, RATE_WINDOW_MS,
};
pub use search::{
    canonical_url_key, fuse, normalize_title, search, EngineRank, FusedResult, SearchEngine,
    SearchError, SearchHit, SearchResponse, RRF_K,
};
