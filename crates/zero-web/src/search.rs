//! Keyless search adapters and reciprocal-rank fusion (WEB-01, WEB-02).
//!
//! A backend implements [`SearchEngine`] and hands back its own ranking of
//! [`SearchHit`]s. [`search`] runs every healthy adapter in parallel, keeps a
//! per-engine failure local to [`SearchResponse::failed`], and fuses the
//! survivors with reciprocal rank fusion (k = 60, [`RRF_K`]).
//!
//! [`fuse`] is the pure fusion step: callers that already hold per-engine
//! rankings (a cache, a replay fixture, or another orchestrator) can fuse them
//! without spawning threads.

use std::cmp::Ordering;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zero_types::error::Result;

/// Reciprocal-rank-fusion constant.
///
/// Each contributing rank adds `1 / (RRF_K + rank)` to a result's score.
pub const RRF_K: f64 = 60.0;

/// One keyless search backend.
///
/// Implementations must be safe to call from several searches at once
/// (`Send + Sync`); [`search`] gives each engine its own thread per query.
pub trait SearchEngine: Send + Sync {
    /// Stable adapter name, reported as provenance on fused results.
    fn name(&self) -> &str;

    /// Run one query. `limit` is the adapter's target result count.
    fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>>;

    /// Whether this adapter should participate in a search.
    ///
    /// An unhealthy engine is skipped silently: it is neither queried nor
    /// listed in [`SearchResponse::failed`]. The default is healthy.
    fn healthy(&self) -> bool {
        true
    }
}

/// One result as returned by a single engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchHit {
    pub title: String,
    pub url: String,
    pub snippet: String,
    /// Raw publish date as reported by the engine; interpretation and
    /// provenance are a later task (WEB-04).
    pub published: Option<String>,
}

/// Why one engine did not contribute to a search.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("search engine `{engine}` failed: {message}")]
pub struct SearchError {
    pub engine: String,
    pub message: String,
}

/// Where one fused result came from and how it ranked in that engine.
///
/// `rank` is 1-based: the first hit an engine returned has rank 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineRank {
    pub engine: String,
    pub rank: usize,
}

/// A deduplicated result after reciprocal-rank fusion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FusedResult {
    pub title: String,
    pub url: String,
    pub snippet: String,
    pub published: Option<String>,
    /// Sum of `1 / (RRF_K + rank)` over every contributing engine rank.
    pub score: f64,
    /// Every engine rank that contributed, ordered by engine order.
    pub sources: Vec<EngineRank>,
}

/// The result of one search: surviving results plus engines that failed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchResponse {
    pub query: String,
    pub results: Vec<FusedResult>,
    pub failed: Vec<SearchError>,
}

/// Search every healthy engine in parallel and fuse the rankings.
///
/// Engines run on separate threads and are collected in the order they were
/// passed in, so the output is deterministic even though completion order is
/// not. A failed or panicking engine lands in [`SearchResponse::failed`] and
/// does not fail the search.
///
/// An empty or whitespace-only query, or `limit == 0`, returns an empty
/// response without consulting any engine.
pub fn search(engines: &[&dyn SearchEngine], query: &str, limit: usize) -> SearchResponse {
    if limit == 0 || query.trim().is_empty() {
        return SearchResponse {
            query: query.to_string(),
            results: Vec::new(),
            failed: Vec::new(),
        };
    }

    let active: Vec<&dyn SearchEngine> = engines
        .iter()
        .copied()
        .filter(|engine| engine.healthy())
        .collect();

    // Scoped threads let the engines borrow `query` and the caller's engines;
    // joining every handle also prevents a panicking engine from escaping the
    // scope and aborting the search.
    let outcomes = std::thread::scope(|scope| {
        let handles: Vec<_> = active
            .iter()
            .map(|engine| {
                let engine = *engine;
                let name = engine.name().to_string();
                let handle = scope.spawn(move || engine.search(query, limit));
                (name, handle)
            })
            .collect();

        handles
            .into_iter()
            .map(|(name, handle)| (name, handle.join()))
            .collect::<Vec<_>>()
    });

    let mut ranked: Vec<(String, Vec<SearchHit>)> = Vec::new();
    let mut failed: Vec<SearchError> = Vec::new();
    for (name, outcome) in outcomes {
        match outcome {
            Ok(Ok(hits)) => ranked.push((name, hits)),
            Ok(Err(error)) => failed.push(SearchError {
                engine: name,
                message: error.to_string(),
            }),
            Err(_) => failed.push(SearchError {
                engine: name,
                message: "engine panicked".to_string(),
            }),
        }
    }

    let mut response = fuse(query, &ranked, limit);
    response.failed = failed;
    response
}

/// Fuse already-collected per-engine rankings.
///
/// `ranked` is `(engine name, hits in that engine's order)`; the slice order is
/// the engine order used for deterministic tie-breaking and provenance
/// ordering. Duplicates are merged by canonical URL or by normalized title.
pub fn fuse(query: &str, ranked: &[(String, Vec<SearchHit>)], limit: usize) -> SearchResponse {
    let mut results = Vec::new();
    if limit == 0 {
        return SearchResponse {
            query: query.to_string(),
            results,
            failed: Vec::new(),
        };
    }

    let mut groups: Vec<Group> = Vec::new();
    // Union-find over groups: two groups merge when a hit is a duplicate of
    // both (and they were not already the same group).
    let mut parent: Vec<usize> = Vec::new();
    let mut by_url: HashMap<String, usize> = HashMap::new();
    let mut by_title: HashMap<String, usize> = HashMap::new();

    for (engine_index, (engine_name, hits)) in ranked.iter().enumerate() {
        for (offset, hit) in hits.iter().enumerate() {
            let rank = offset + 1;
            let source = EngineRank {
                engine: engine_name.clone(),
                rank,
            };
            let url_key = url_dedupe_key(&hit.url);
            let title_key = title_dedupe_key(&hit.title);

            let url_group = url_key
                .as_ref()
                .and_then(|key| by_url.get(key).copied())
                .map(|index| find(&mut parent, index));
            let title_group = title_key
                .as_ref()
                .and_then(|key| by_title.get(key).copied())
                .map(|index| find(&mut parent, index));

            let group_index = match (url_group, title_group) {
                (None, None) => {
                    let index = groups.len();
                    groups.push(Group::new(hit, rank, engine_index, source));
                    parent.push(index);
                    index
                }
                (Some(first), Some(second)) if first != second => {
                    let (keep, drop) = if first < second {
                        (first, second)
                    } else {
                        (second, first)
                    };
                    {
                        let (before_drop, from_drop) = groups.split_at_mut(drop);
                        before_drop[keep].merge(&mut from_drop[0]);
                    }
                    parent[drop] = keep;
                    groups[keep].absorb(hit, rank, engine_index, source);
                    keep
                }
                (Some(existing), _) | (None, Some(existing)) => {
                    groups[existing].absorb(hit, rank, engine_index, source);
                    existing
                }
            };

            if let Some(key) = url_key {
                by_url.insert(key, group_index);
            }
            if let Some(key) = title_key {
                by_title.insert(key, group_index);
            }
        }
    }

    let mut surviving: Vec<Group> = groups.into_iter().filter(|group| group.alive).collect();
    surviving.sort_by(compare_groups);
    surviving.truncate(limit);

    results.extend(surviving.into_iter().map(Group::into_result));

    SearchResponse {
        query: query.to_string(),
        results,
        failed: Vec::new(),
    }
}

/// Canonical host + path key used to deduplicate hits across engines.
///
/// Scheme, fragments, queries, trailing slashes, repeated slashes, a leading
/// `www.`, and default ports (`:80`, `:443`) are ignored; the host is
/// lowercased while the path keeps its case. An empty or host-less URL still
/// yields a path-only key, but [`fuse`] only applies URL deduplication to
/// non-empty URLs.
pub fn canonical_url_key(url: &str) -> String {
    let trimmed = url.trim();
    let before_fragment = trimmed.split('#').next().unwrap_or("");
    let before_query = before_fragment.split('?').next().unwrap_or("");
    let rest = match before_query.split_once("://") {
        Some((_, rest)) => rest,
        None => before_query.strip_prefix("//").unwrap_or(before_query),
    };

    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };

    let authority = authority
        .rsplit('@')
        .next()
        .unwrap_or(authority)
        .to_ascii_lowercase();
    let authority = authority.trim_end_matches('.');
    let authority = authority.strip_prefix("www.").unwrap_or(authority);
    let host = strip_default_port(authority);

    let mut path_key = String::new();
    for segment in path.split('/').filter(|segment| !segment.is_empty()) {
        path_key.push('/');
        path_key.push_str(segment);
    }
    if path_key.is_empty() {
        path_key.push('/');
    }

    if host.is_empty() {
        path_key
    } else {
        format!("{host}{path_key}")
    }
}

/// Normalize a title for fuzzy deduplication: lowercase, alphanumerics only.
///
/// `"Rust 1.90 Released!"` and `"rust 1.90 released"` both become
/// `"rust190released"`. An empty result (a title with no letters or digits) is
/// not used for deduplication, so untitled hits do not collapse together.
pub fn normalize_title(title: &str) -> String {
    title
        .chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// Short normalized titles are too ambiguous to merge across hosts ("Home",
/// "News", "Docs"). Only title keys of at least this many characters dedupe.
const MIN_TITLE_KEY: usize = 8;

fn title_dedupe_key(title: &str) -> Option<String> {
    let key = normalize_title(title);
    if key.chars().count() >= MIN_TITLE_KEY {
        Some(key)
    } else {
        None
    }
}

fn url_dedupe_key(url: &str) -> Option<String> {
    if url.trim().is_empty() {
        None
    } else {
        Some(canonical_url_key(url))
    }
}

fn strip_default_port(host: &str) -> &str {
    host.strip_suffix(":80")
        .or_else(|| host.strip_suffix(":443"))
        .unwrap_or(host)
}

fn reciprocal_rank(rank: usize) -> f64 {
    1.0 / (RRF_K + rank as f64)
}

fn find(parent: &mut [usize], mut index: usize) -> usize {
    while parent[index] != index {
        parent[index] = parent[parent[index]];
        index = parent[index];
    }
    index
}

fn compare_groups(left: &Group, right: &Group) -> Ordering {
    right
        .score
        .partial_cmp(&left.score)
        .unwrap_or(Ordering::Equal)
        .then_with(|| left.best_rank.cmp(&right.best_rank))
        .then_with(|| left.best_engine.cmp(&right.best_engine))
        .then_with(|| left.url.cmp(&right.url))
}

struct Group {
    title: String,
    url: String,
    snippet: String,
    published: Option<String>,
    score: f64,
    best_rank: usize,
    best_engine: usize,
    sources: Vec<(usize, EngineRank)>,
    alive: bool,
}

impl Group {
    fn new(hit: &SearchHit, rank: usize, engine_index: usize, source: EngineRank) -> Self {
        Self {
            title: hit.title.clone(),
            url: hit.url.clone(),
            snippet: hit.snippet.clone(),
            published: hit.published.clone(),
            score: reciprocal_rank(rank),
            best_rank: rank,
            best_engine: engine_index,
            sources: vec![(engine_index, source)],
            alive: true,
        }
    }

    fn absorb(&mut self, hit: &SearchHit, rank: usize, engine_index: usize, source: EngineRank) {
        self.score += reciprocal_rank(rank);
        self.sources.push((engine_index, source));
        if (rank, engine_index) < (self.best_rank, self.best_engine) {
            self.best_rank = rank;
            self.best_engine = engine_index;
            self.title = hit.title.clone();
            self.url = hit.url.clone();
            self.snippet = hit.snippet.clone();
            self.published = hit.published.clone();
        }
    }

    fn merge(&mut self, other: &mut Self) {
        self.score += other.score;
        self.sources.append(&mut other.sources);
        if (other.best_rank, other.best_engine) < (self.best_rank, self.best_engine) {
            self.best_rank = other.best_rank;
            self.best_engine = other.best_engine;
            self.title = std::mem::take(&mut other.title);
            self.url = std::mem::take(&mut other.url);
            self.snippet = std::mem::take(&mut other.snippet);
            self.published = other.published.take();
        }
        other.alive = false;
    }

    fn into_result(mut self) -> FusedResult {
        self.sources
            .sort_by_key(|(engine_index, source)| (*engine_index, source.rank));
        FusedResult {
            title: self.title,
            url: self.url,
            snippet: self.snippet,
            published: self.published,
            score: self.score,
            sources: self.sources.into_iter().map(|(_, source)| source).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_types::error::{ErrorCode, ZeroError};

    struct FixtureEngine {
        name: &'static str,
        hits: Vec<SearchHit>,
        healthy: bool,
        error: Option<&'static str>,
    }

    impl FixtureEngine {
        fn new(name: &'static str, hits: Vec<SearchHit>) -> Self {
            Self {
                name,
                hits,
                healthy: true,
                error: None,
            }
        }

        fn failing(name: &'static str, message: &'static str) -> Self {
            Self {
                name,
                hits: Vec::new(),
                healthy: true,
                error: Some(message),
            }
        }
    }

    impl SearchEngine for FixtureEngine {
        fn name(&self) -> &str {
            self.name
        }

        fn search(&self, _query: &str, _limit: usize) -> Result<Vec<SearchHit>> {
            match self.error {
                Some(message) => Err(ZeroError::new(ErrorCode::Unavailable, message)),
                None => Ok(self.hits.clone()),
            }
        }

        fn healthy(&self) -> bool {
            self.healthy
        }
    }

    struct PanicEngine {
        name: &'static str,
        healthy: bool,
    }

    impl SearchEngine for PanicEngine {
        fn name(&self) -> &str {
            self.name
        }

        fn search(&self, _query: &str, _limit: usize) -> Result<Vec<SearchHit>> {
            panic!("engine `{}` must not be consulted", self.name);
        }

        fn healthy(&self) -> bool {
            self.healthy
        }
    }

    fn hit(title: &str, url: &str, snippet: &str, published: Option<&str>) -> SearchHit {
        SearchHit {
            title: title.to_string(),
            url: url.to_string(),
            snippet: snippet.to_string(),
            published: published.map(str::to_string),
        }
    }

    fn engines<'a>(list: &[&'a dyn SearchEngine]) -> Vec<&'a dyn SearchEngine> {
        list.to_vec()
    }

    #[test]
    fn three_engine_fixture_fuses_by_reciprocal_rank() {
        let alpha = FixtureEngine::new(
            "alpha",
            vec![
                hit(
                    "Rust 1.90 Released!",
                    "https://example.com/rust",
                    "alpha release",
                    Some("2026-11-20"),
                ),
                hit(
                    "Alpha Notes",
                    "https://alpha.example/notes",
                    "alpha only",
                    None,
                ),
                hit(
                    "Shared Page",
                    "https://shared.example/x",
                    "alpha shared",
                    None,
                ),
            ],
        );
        let beta = FixtureEngine::new(
            "beta",
            vec![
                hit(
                    "Shared Page",
                    "https://shared.example/x",
                    "beta shared",
                    Some("2026-11-19"),
                ),
                hit(
                    "Beta Notes",
                    "https://beta.example/notes",
                    "beta only",
                    None,
                ),
            ],
        );
        let gamma = FixtureEngine::new(
            "gamma",
            vec![
                // Different headline, tracking query, and the same canonical
                // host + path: only URL deduplication can merge this hit.
                hit(
                    "Completely Different Headline",
                    "https://shared.example/x?utm_source=gamma",
                    "gamma shared",
                    None,
                ),
                hit(
                    "Rust 1.90 released",
                    "https://example.com/rust/",
                    "gamma release",
                    None,
                ),
            ],
        );

        let all = engines(&[&alpha, &beta, &gamma]);
        let response = search(&all, "rust", 10);

        assert_eq!(response.query, "rust");
        assert!(response.failed.is_empty(), "{:?}", response.failed);

        let order: Vec<&str> = response
            .results
            .iter()
            .map(|result| result.url.as_str())
            .collect();
        assert_eq!(
            order,
            [
                "https://shared.example/x",
                "https://example.com/rust",
                "https://alpha.example/notes",
                "https://beta.example/notes",
            ]
        );

        let shared = &response.results[0];
        let expected_shared = 1.0 / 63.0 + 2.0 / 61.0;
        assert!(
            (shared.score - expected_shared).abs() < 1e-12,
            "score {} != {expected_shared}",
            shared.score
        );
        assert_eq!(
            shared.sources,
            vec![
                EngineRank {
                    engine: "alpha".to_string(),
                    rank: 3,
                },
                EngineRank {
                    engine: "beta".to_string(),
                    rank: 1,
                },
                EngineRank {
                    engine: "gamma".to_string(),
                    rank: 1,
                },
            ]
        );
        // The representative fields come from the best rank (beta, rank 1).
        assert_eq!(shared.title, "Shared Page");
        assert_eq!(shared.snippet, "beta shared");
        assert_eq!(shared.published.as_deref(), Some("2026-11-19"));

        let rust = &response.results[1];
        let expected_rust = 1.0 / 61.0 + 1.0 / 62.0;
        assert!(
            (rust.score - expected_rust).abs() < 1e-12,
            "score {} != {expected_rust}",
            rust.score
        );
        assert_eq!(
            rust.sources,
            vec![
                EngineRank {
                    engine: "alpha".to_string(),
                    rank: 1,
                },
                EngineRank {
                    engine: "gamma".to_string(),
                    rank: 2,
                },
            ]
        );
        assert_eq!(rust.title, "Rust 1.90 Released!");
        assert_eq!(rust.published.as_deref(), Some("2026-11-20"));

        // Distinct hits with equal scores keep the deterministic engine order.
        let expected_single = 1.0 / 62.0;
        for result in &response.results[2..] {
            assert!((result.score - expected_single).abs() < 1e-12);
            assert_eq!(result.sources.len(), 1);
        }
    }

    #[test]
    fn duplicate_urls_merge_into_one_result() {
        let first = FixtureEngine::new(
            "first",
            vec![hit(
                "First headline",
                "https://Example.com/story/?utm_source=first#top",
                "first snippet",
                None,
            )],
        );
        let second = FixtureEngine::new(
            "second",
            vec![hit(
                "Second headline",
                "http://example.com/story",
                "second snippet",
                None,
            )],
        );

        let all = engines(&[&first, &second]);
        let response = search(&all, "story", 10);

        assert_eq!(response.results.len(), 1);
        let fused = &response.results[0];
        assert_eq!(fused.url, "https://Example.com/story/?utm_source=first#top");
        assert!((fused.score - 2.0 / 61.0).abs() < 1e-12);
        assert_eq!(
            fused.sources,
            vec![
                EngineRank {
                    engine: "first".to_string(),
                    rank: 1,
                },
                EngineRank {
                    engine: "second".to_string(),
                    rank: 1,
                },
            ]
        );
        // Rank 1 in both engines: the earlier engine supplies the fields.
        assert_eq!(fused.title, "First headline");
        assert_eq!(fused.snippet, "first snippet");
    }

    #[test]
    fn fuzzy_titles_merge_when_urls_differ() {
        let first = FixtureEngine::new(
            "first",
            vec![hit(
                "Rust 1.90 Released!",
                "https://one.example/story",
                "one",
                None,
            )],
        );
        let second = FixtureEngine::new(
            "second",
            vec![hit(
                "Rust 1.90 released",
                "https://two.example/story",
                "two",
                None,
            )],
        );

        assert_ne!(
            canonical_url_key("https://one.example/story"),
            canonical_url_key("https://two.example/story")
        );

        let all = engines(&[&first, &second]);
        let response = search(&all, "rust", 10);

        assert_eq!(response.results.len(), 1);
        let fused = &response.results[0];
        assert!((fused.score - 2.0 / 61.0).abs() < 1e-12);
        assert_eq!(fused.sources.len(), 2);
        assert_eq!(fused.title, "Rust 1.90 Released!");
    }

    #[test]
    fn short_generic_titles_do_not_collapse_across_hosts() {
        let first =
            FixtureEngine::new("first", vec![hit("Home", "https://one.example/", "", None)]);
        let second = FixtureEngine::new(
            "second",
            vec![hit("Home", "https://two.example/", "", None)],
        );

        let all = engines(&[&first, &second]);
        let response = search(&all, "x", 10);
        assert_eq!(response.results.len(), 2, "{:?}", response.results);
    }

    #[test]
    fn failed_engine_is_reported_without_failing_search() {
        let good = FixtureEngine::new(
            "good",
            vec![hit("Kept", "https://good.example/kept", "survives", None)],
        );
        let broken = FixtureEngine::failing("broken", "rate limited");

        let all = engines(&[&good, &broken]);
        let response = search(&all, "anything", 10);

        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].title, "Kept");
        assert_eq!(response.failed.len(), 1);
        assert_eq!(response.failed[0].engine, "broken");
        assert!(response.failed[0].message.contains("rate limited"));
    }

    #[test]
    fn unhealthy_engine_is_skipped() {
        let healthy = FixtureEngine::new(
            "healthy",
            vec![hit(
                "Healthy hit",
                "https://healthy.example/hit",
                "ok",
                None,
            )],
        );
        let unhealthy = PanicEngine {
            name: "unhealthy",
            healthy: false,
        };

        let all = engines(&[&unhealthy, &healthy]);
        let response = search(&all, "anything", 10);

        assert_eq!(response.results.len(), 1);
        assert!(response.failed.is_empty());
        assert_eq!(
            response.results[0].sources,
            vec![EngineRank {
                engine: "healthy".to_string(),
                rank: 1,
            }]
        );
    }

    #[test]
    fn empty_query_and_zero_limit_return_no_results() {
        let untouchable = PanicEngine {
            name: "untouchable",
            healthy: true,
        };
        let all = engines(&[&untouchable]);

        for query in ["", "   ", "\t\n"] {
            let response = search(&all, query, 10);
            assert!(response.results.is_empty());
            assert!(response.failed.is_empty());
            assert_eq!(response.query, query);
        }

        let response = search(&all, "rust", 0);
        assert!(response.results.is_empty());
        assert!(response.failed.is_empty());
    }

    #[test]
    fn canonical_url_key_normalizes_noise() {
        assert_eq!(
            canonical_url_key("https://WWW.Example.COM:443/a/b/?q=1#frag"),
            "example.com/a/b"
        );
        assert_eq!(
            canonical_url_key("http://Example.com/a//b/"),
            "example.com/a/b"
        );
        assert_eq!(
            canonical_url_key("https://example.com"),
            canonical_url_key("https://example.com/")
        );
        assert_eq!(
            canonical_url_key("https://example.com/Path"),
            "example.com/Path"
        );
        assert_eq!(
            canonical_url_key("https://example.com:8443/x"),
            "example.com:8443/x"
        );
        assert_eq!(
            canonical_url_key("https://user:pw@example.com/x"),
            "example.com/x"
        );
    }

    #[test]
    fn title_normalization_ignores_punctuation_and_case() {
        assert_eq!(
            normalize_title("Rust 1.90 Released!"),
            normalize_title("Rust 1.90 released")
        );
        assert_eq!(normalize_title("Rust 1.90 released"), "rust190released");
        assert_eq!(normalize_title("!!!"), "");
    }

    #[test]
    fn fuse_respects_limit_and_empty_input() {
        let ranked = vec![(
            "only".to_string(),
            vec![
                hit("One", "https://one.example/", "1", None),
                hit("Two", "https://two.example/", "2", None),
            ],
        )];

        let response = fuse("query", &ranked, 1);
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].title, "One");

        let empty = fuse("query", &[], 5);
        assert!(empty.results.is_empty());
        assert!(empty.failed.is_empty());
    }
}
