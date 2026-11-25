//! `zero-web` — see `architecture.md` section 5 for the module contract.
//!
//! Implements the keyless search adapter contract, reciprocal-rank fusion
//! (WEB-01, WEB-02), result filters (WEB-03), and date provenance (WEB-04).
//! Caching, fetch, and crawling are later tasks; no live network adapters ship
//! here yet.

pub mod filter;
pub mod search;

pub use filter::{
    apply, canonical_host, category_for, parse_timestamp_ms, DateSource, FilteredResponse,
    FilteredResult, Freshness, Provenance, SearchFilters, DAY_MS,
};
pub use search::{
    canonical_url_key, fuse, normalize_title, search, EngineRank, FusedResult, SearchEngine,
    SearchError, SearchHit, SearchResponse, RRF_K,
};
