//! `zero-web` — see `architecture.md` section 5 for the module contract.
//!
//! Implements the keyless search adapter contract and reciprocal-rank fusion
//! (WEB-01, WEB-02). Filters, provenance dates, caching, fetch, and crawling
//! are later tasks; no live network adapters ship here yet.

pub mod search;

pub use search::{
    canonical_url_key, fuse, normalize_title, search, EngineRank, FusedResult, SearchEngine,
    SearchError, SearchHit, SearchResponse, RRF_K,
};
