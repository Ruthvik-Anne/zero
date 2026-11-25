# Web search and fusion

`zero-web` currently ships the keyless search contract and the fusion step
(T-WEB-01, WEB-01 and WEB-02). Filters, provenance dates, caching, fetch,
crawling, and browser automation are later tasks. No live engine adapter is
bundled yet; each adapter is a small implementation of the trait below.

## Adapter contract

Every backend implements `zero_web::SearchEngine`:

```rust
pub trait SearchEngine: Send + Sync {
    fn name(&self) -> &str;
    fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>>;
    fn healthy(&self) -> bool { true }
}
```

- `name` is the stable identifier used in provenance (`EngineRank.engine`).
- `search` returns the adapter's own ranking. The first hit is rank 1; the
  adapter owns provider-specific parsing, pagination, and request limits.
- `healthy` defaults to `true`. Returning `false` skips the adapter for this
  search without querying it and without reporting a failure. It is the hook
  for a later circuit breaker or bench list (WEB-05).
- Adapters must be `Send + Sync`: one thread per engine calls `search` for each
  query.

`SearchHit` carries `title`, `url`, `snippet`, and an optional raw `published`
string. Turning dates into a comparable age and naming the date source is
WEB-04, so fusion passes `published` through from the best-ranked source
unchanged.

## Parallel execution

`search(engines, query, limit)`:

1. Returns an empty response immediately when `limit == 0` or the query is
   empty or whitespace only. No adapter is consulted in that case.
2. Skips engines whose `healthy()` is `false`.
3. Spawns one scoped thread per surviving engine and joins them all.
4. Collects outcomes in the order the engines were passed in, so the output is
   deterministic although completion order is not.
5. Fuses surviving rankings with RRF; failures go to `SearchResponse::failed`.

Engines are `&dyn SearchEngine`, so callers own the adapter objects and may
reuse them across searches.

## Reciprocal rank fusion

For an engine rank `r` (1-based), a hit contributes

```text
1 / (60 + r)
```

to its fused score (`RRF_K = 60`). Scores from every contributing engine are
summed. RRF only uses positions, never provider scores, so engines with
incompatible scoring scales can be mixed safely.

Results sort by:

1. fused score, descending;
2. best (lowest) contributing rank, ascending;
3. earliest contributing engine in caller order;
4. canonical URL, ascending.

The final list is truncated to `limit`.

`fuse(query, ranked, limit)` exposes the same step for rankings that are
already collected (cache, replay fixture, another orchestrator). `ranked` is a
slice of `(engine name, hits in engine order)`, and the slice order defines the
engine order.

## Deduplication

Two hits are duplicates when either key matches:

- **Canonical host plus path.** `canonical_url_key` drops the scheme, fragment,
  and query string, lowercases the host, strips a leading `www.`, strips
  default ports `:80` and `:443`, and normalizes the path by dropping repeated
  and trailing slashes. The path itself keeps its case because HTTP paths are
  case-sensitive. Dropping the query means tracking parameters do not create
  duplicates; it also means `?id=1` and `?id=2` on the same path are treated as
  one page.
- **Fuzzy title.** `normalize_title` lowercases the title and keeps only
  alphanumeric characters, so `Rust 1.90 Released!` and `Rust 1.90 released`
  both become `rust190released`. Title keys shorter than eight characters are
  ignored, so generic headings such as `Home` or `News` on unrelated hosts do
  not collapse together.

Deduplication is transitive: if one hit matches group A by URL and another
matches group A by title, all of them form one result. The group keeps the
fields (title, URL, snippet, published) of its best-ranked hit; ties go to the
earlier engine. All contributing `EngineRank`s are kept and sorted by engine
order, and duplicate scores are summed. An empty URL is not used as a URL key;
such a hit can still merge by title.

## Failure policy

A single engine must never fail the search:

- `Err(ZeroError)` from an adapter becomes one `SearchError { engine, message }`
  in `SearchResponse::failed`; the message is the display form of the typed
  error, including its stable code.
- A panicking adapter is caught at the thread join and reported as
  `engine panicked` in the same list.
- Unhealthy engines are skipped silently and are not failures.
- Other engines' results are still fused and returned.

Callers decide how to surface partial results: `results` may be non-empty while
`failed` reports one or more engines.

## Tests

`cargo test -p zero-web` runs scripted fixtures with no network access: a
three-engine relevance fixture, URL and fuzzy-title deduplication, an engine
error, an unhealthy engine, empty-query and zero-limit behavior, and key
normalization.
