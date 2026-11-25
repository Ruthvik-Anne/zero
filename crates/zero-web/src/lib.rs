//! `zero-web` — see `architecture.md` section 5 for the module contract.
//!
//! Implements the keyless search adapter contract, reciprocal-rank fusion
//! (WEB-01, WEB-02), result filters (WEB-03), date provenance (WEB-04), the
//! SQLite FTS5 search cache (WEB-06), per-engine resilience policy (WEB-05),
//! and the SSRF/egress gate (WEB-16, WEB-17). Fetch and crawling are later
//! tasks; no live network adapters ship here yet.

pub mod cache;
pub mod egress;
pub mod filter;
pub mod resilience;
pub mod search;

pub use egress::{
    classify_address, AddressClass, EgressGuard, EgressScheme, NetworkPolicy, PinnedDestination,
    PinnedRequest, Resolver, SystemResolver, DEFAULT_MAX_REDIRECTS,
};

pub use cache::{IndexHit, SearchCache, TtlPolicy, DEFAULT_TTL_MS};
pub use filter::{
    apply, canonical_host, category_for, parse_timestamp_ms, DateSource, FilteredResponse,
    FilteredResult, Freshness, Provenance, SearchFilters, DAY_MS,
};
pub use resilience::{
    is_bench_refusal, next_backoff_ms, BreakerState, CircuitBreaker, EnginePolicy, EngineState,
    ResilientSearch, BENCH_MARKERS, RATE_WINDOW_MS,
};
pub use search::{
    canonical_url_key, fuse, normalize_title, search, EngineRank, FusedResult, SearchEngine,
    SearchError, SearchHit, SearchResponse, RRF_K,
};
