# Web search and fusion

`zero-web` currently ships the keyless search contract, the fusion step, result
filters, and date provenance (T-WEB-01, T-WEB-02; WEB-01 through WEB-04).
Caching, fetch, crawling, and browser automation are later tasks. No live engine
adapter is bundled yet; each adapter is a small implementation of the trait
below.

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

## Filters and provenance

`apply(filters, response, now_ms)` (also `SearchResponse::apply`) narrows a
fused response without touching fusion: surviving results keep their original
scores, source ranks, and order. `FilteredResponse` carries the surviving
`FilteredResult`s, the engine failures, and a `dropped` count.

Every `SearchFilters` field is an ANDed restriction; an empty list imposes no
restriction:

| Field | Rule |
|---|---|
| `freshness` | keep results whose age in whole days is at most the window: `Day` 1, `Week` 7, `Month` 30, `Year` 365 |
| `include_domains` | host must equal an entry or be one of its subdomains |
| `exclude_domains` | host must equal an entry or be one of its subdomains; exclusion wins over inclusion |
| `categories` | keep only the listed `category_for` values; empty keeps every category |
| `required_substrings` | every entry must appear in `title + snippet`, case-insensitively |
| `forbidden_substrings` | no entry may appear in `title + snippet`, case-insensitively |

Domain matching uses the canonical host: lowercased, with a leading `www.` and
any port removed. Entries tolerate a scheme and a leading `*.`, so
`https://example.com:8443` matches `example.com`. `example.com` matches
`example.com`, `docs.example.com`, and `www.example.com`, but not
`notexample.com`. `exclude_domains` is checked first, so a host that is both
included and excluded is dropped. A URL without a host survives only when
`include_domains` is empty.

Substring matching lowercases both the haystack (`title` and `snippet`) and the
needle. Blank needles are ignored, so a stray empty entry can neither keep nor
forbid everything.

### Categories

`category_for(url)` assigns exactly one of four values; the first matching row
wins:

| Category | Match |
|---|---|
| `docs` | host starts with `docs.` or `developer.`, or the first path segment is `docs` or `documentation` |
| `code` | host is `github.com`, `gitlab.com`, or `bitbucket.org`, or the first path segment is `src` |
| `news` | host starts with `news.` or `blog.`, or the first path segment is `news`, `blog`, or `press` |
| `general` | everything else, including host-less URLs |

That table is the whole taxonomy; no other categories exist. A non-empty
`categories` filter keeps only the listed values.

### Result age and date source

Every `FilteredResult` carries
`Provenance { published, age_days, source }`. `published` is the engine's raw
string and is kept even when it cannot be parsed. `age_days` is the number of
whole days between the parsed instant and `now_ms`, clamped to zero for a
timestamp ahead of `now_ms` (clock skew).

`parse_timestamp_ms` accepts exactly:

- `YYYY-MM-DD`, interpreted as midnight UTC;
- an RFC 3339 timestamp: `YYYY-MM-DDTHH:MM:SS` followed by `Z` or a `+HH:MM` /
  `-HH:MM` offset, with optional fractional seconds (truncated).

Anything else — a space separator, a missing offset, an out-of-range field, or
a non-leap `02-29` — yields `age_days: None`, `source: DateSource::Unknown`,
and the original string. A date is never guessed from surrounding text.

`DateSource` is `Engine` today because fetching does not exist yet: every
parseable engine value is attributed to the engine. `Page` is reserved for
reader-mode extraction (T-WEB-04), and `Unknown` means no parseable date.

Freshness fails closed: when `freshness` is set, a result with
`age_days: None` is dropped. Without a freshness window, results with unknown
dates are kept and reported with `source: Unknown`.

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
error, an unhealthy engine, empty-query and zero-limit behavior, key
normalization, timestamp parsing, a 19-case filter matrix, provenance ages and
date sources, and category classification.
