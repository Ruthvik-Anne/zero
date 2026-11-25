# Web search and fusion

`zero-web` currently ships the keyless search contract, the fusion step, result
filters, date provenance, the SQLite FTS5 cache, per-engine resilience policy,
and the SSRF/egress gate (T-WEB-01 through T-WEB-03 and T-WEB-09; WEB-01 through
WEB-06, WEB-16, and WEB-17). Fetch, reader mode, crawling, and browser
automation are later tasks. No live engine adapter is bundled yet; each adapter
is a small implementation of the trait below.

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
  search without querying it and without reporting a failure. `ResilientSearch`
  keeps its own breaker and bench list, so `healthy` is only needed by callers
  that use the plain `search` path.
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

## Cache and resilience

Two cooperating pieces sit around the adapter contract: `SearchCache` (WEB-06)
remembers fused responses in SQLite, and `ResilientSearch` (WEB-05) decides
which engines may be called right now.

### Cache schema

`SearchCache::open(path)` creates the database (and its parent directory) and
verifies that the running SQLite build has FTS5. A build without FTS5 returns
`ErrorCode::Unsupported` instead of panicking.

| Object | Columns | Purpose |
|---|---|---|
| `cache_entries` | `key` (PK), `query`, `category`, `stored_at_ms`, `expires_at_ms`, `payload` | one whole `SearchResponse` as JSON |
| `cache_fts` | `query`, `title`, `snippet`, `url` (FTS5, `unicode61`) | text index over cached results |
| `cache_fts_map` | `rowid` (PK), `entry_key`, `category` | ties each FTS row to its entry so replacement, invalidation, and expiry can delete index rows |

`key` is the category plus a normalized query: trimmed, internal whitespace
collapsed, lowercased. Lookups are therefore case-insensitive, and the same
query text in two categories is two entries. `put` replaces an existing key and
drops its old index rows first, so superseded text is never searchable.

The payload comes from the web and is **untrusted data**. It is serialized to
JSON, stored, and deserialized back into `SearchResponse`; nothing in it is
evaluated as code, SQL, or a path. Titles and snippets are only ever indexed as
text. SQL parameters are always bound, so a hostile title cannot alter the
schema.

### TTL and cache age

- `put(query, category, response, now_ms, ttl_ms)` stores an entry until
  `now_ms + ttl_ms`. A TTL at or below zero is already expired on the next read.
- `TtlPolicy` maps category to lifetime with a default (`DEFAULT_TTL_MS` is 15
  minutes). `put_with_policy` uses `ttl_for(category)`; category names are
  matched case-insensitively, unlisted categories use the default.
- `get` treats `expires_at_ms <= now_ms` as a miss and deletes the entry and its
  index rows.
- `get_with_max_age(..., max_age_ms)` is the cache-age filter: even an
  unexpired entry is a miss when `now_ms - stored_at_ms > max_age_ms`. A
  max-age rejection does **not** delete the entry, because a later caller with a
  looser bound may still use it. Age is clamped at zero for clock skew.
- A payload that no longer deserializes is a miss and is deleted: a corrupt
  cache must never fail a search.
- `invalidate_category(category)` removes one category and returns how many
  entries it removed; `clear` empties everything; `purge_expired(now_ms)`
  removes only entries past their TTL.

`search_index(text, limit)` queries the FTS5 table. `text` is split into
alphanumeric tokens; each token is quoted and all tokens must match (implicit
AND), so characters such as `"`, `*`, `-`, or `:` are separators rather than
query syntax. The match is restricted to `title` and `snippet`, results are
ordered by FTS5 rank, and each row carries a `snippet()` rendering with `[` `]`
around the match. This searches what was already cached; it never calls an
engine.

### Resilience policy

`EnginePolicy` (all fields are caller-set; these are the defaults):

| Field | Default | Effect |
|---|---|---|
| `max_requests_per_minute` | 30 | requests per 60 s window, `0` means unlimited |
| `initial_backoff_ms` | 1 000 | delay after the first consecutive failure |
| `max_backoff_ms` | 60 000 | cap for the doubling delay |
| `breaker_threshold` | 3 | consecutive failures that open the breaker (`0` behaves as `1`) |
| `breaker_cooldown_ms` | 300 000 | open-breaker and bench duration |

**Rate limit.** Each engine has a 60 000 ms window anchored at its first
request. Once the window holds `max_requests_per_minute` requests, the engine is
skipped until the window refills.

**Backoff.** After a non-bench failure, `next_backoff_ms` returns
`initial * 2^attempt`, capped at `max`, where attempt 0 is the first failure
and a zero initial delay is raised to 1 ms. A `max` below the initial delay
never shortens that first delay. The result is the engine's earliest next call
(`now_ms + backoff`). Consecutive failures keep doubling the delay; a success
clears it.

**Circuit breaker.** `CircuitBreaker` is `Closed`, `Open { until_ms }`, or
`HalfOpen`. Consecutive failures at the threshold move it to `Open` for
`now_ms + breaker_cooldown_ms`; calls are rejected while open. Once the
cooldown elapses, `allow` moves it to `HalfOpen` and lets one probe through: a
success closes the breaker and clears the failure count, a failure reopens it
for another cooldown.

**Benching.** A CAPTCHA or login refusal is not an engine failure. If the error
message contains one of these case-insensitive markers, the engine is benched
for `breaker_cooldown_ms`:

- `captcha`
- `verify you are human`
- `login required`
- `sign in to continue`

A benched engine is excluded from subsequent searches until the cooldown
elapses, is **not** added to `SearchResponse::failed`, and does not feed the
breaker. Other engines still contribute, so the search succeeds. After the
cooldown the engine is tried again and is re-benched if the wall is still
there. `is_bench_refusal` exposes the classification and
`benched(engine, now_ms)` reports the current bench state.

**Reserve engine.** `with_reserve` attaches one fallback with its own breaker,
rate window, backoff, and bench state. It is used only when no primary engine
was available, where "available" means a primary returned `Ok` — an engine that
answers with zero hits is still available, so the reserve does not mask an
empty result set. If every primary failed or was skipped, the reserve is tried
under the same policy.

**Execution order.** `ResilientSearch::run` calls engines sequentially because
each outcome determines whether the next call is allowed; `search` remains the
parallel path for callers without policy. Both paths finish through `fuse`, so
result ordering, deduplication, and scores are identical. A panicking adapter
is caught and reported as a failure rather than aborting the search. An empty
query or `limit == 0` returns an empty response without consulting an engine.

`engine_state(name)` returns an `EngineState` snapshot (breaker position,
consecutive failures, requests in the window, next allowed instant, backoff,
bench end) for diagnostics and tests. Engine names must be unique across the
primary list and the reserve.

### Remaining

- No real keyless adapter ships yet: every engine is a fixture or a caller's
  implementation of `SearchEngine`.
- No live HTTP fetch, reader-mode extraction, crawling, or headless-browser
  fallback exists, so cached payloads and benched engines are exercised only by
  scripted tests.
- `SearchCache` is single-writer (one `rusqlite::Connection` per instance) and
  is not shared across threads; a later daemon task may add a connection pool if
  concurrent crawl and search writers are needed.

## SSRF and egress

`EgressGuard` (WEB-16, WEB-17) is the gate every outbound web request passes
through. The fetch layer (T-WEB-04) will call `check_request`, then connect only
to the pinned addresses it returns; no other web code may open a socket.

### Network policy

The caller maps its operating mode to one policy; the guard never infers it.

| Policy | Public HTTP(S) | Loopback, RFC 1918, ULA, CGNAT | Link-local, metadata, multicast, unspecified, broadcast, reserved | Non-HTTP(S) |
|---|---|---|---|---|
| `Offline` | deny | deny | deny | deny |
| `Restricted` | allow | deny | deny | deny |
| `Full` | allow | allow | deny | deny |

`Restricted` is the normal default for unattended web work. `Full` is an
explicit opt-in for local development targets; it still refuses cloud metadata,
link-local, multicast, unspecified, broadcast, and reserved addresses, and every
non-HTTP(S) scheme. `Offline` refuses every URL, redirect, and request; local
files and the search cache keep working because they never consult the guard.

### Pinned addresses

`check_url` parses the URL, refuses userinfo, and resolves the host once. Every
answer is classified; a single forbidden address rejects the whole request, so a
DNS answer that mixes a public and a private address cannot win a race against
the connect logic. The surviving list is deduplicated and returned in
`PinnedDestination::addresses`. The fetch layer connects to those exact
addresses and must not resolve the host again (preventing DNS rebinding), while
sending the original host for the `Host` header and TLS SNI.

Address classes:

| Class | Ranges |
|---|---|
| `Public` | everything not listed below |
| `Loopback` | `127.0.0.0/8`, `::1`, IPv4-mapped forms |
| `Private` | `10/8`, `172.16/12`, `192.168/16`, `100.64/10` (CGNAT), `fc00::/7` |
| `LinkLocal` | `169.254/16`, `fe80::/10` |
| `Metadata` | the endpoints below |
| `Multicast` | `224/4`, `ff00::/8` |
| `Unspecified` | `0.0.0.0`, `::` |
| `Broadcast` | `255.255.255.255` |
| `Reserved` | `0/8`, `192.0.0/24`, `192.88.99/24`, TEST-NETs, `198.18/15`, `240/4`, IPv6 outside `2000::/3`, `2001:db8::/32`, `3fff::/20`, Teredo, ORCHID, 6to4, NAT64, `100::/64` |

Cloud metadata addresses and names are refused in every policy:

- IPv4: `169.254.169.254`, `169.254.170.2`, `100.100.100.200`,
  `168.63.129.16`, `192.0.0.192`;
- IPv6: `fd00:ec2::254`;
- hostnames: `metadata.google.internal`, `metadata.goog`,
  `metadata.azure.internal`, `instance-data`, `metadata`.

IPv4-mapped and IPv4-compatible IPv6 forms are unwrapped before classification,
so `::ffff:127.0.0.1` is loopback and `::ffff:169.254.169.254` is metadata.

### Redirects

`check_redirect` re-runs the full check on every hop: scheme, userinfo, host,
resolution, and every resolved address. A relative `Location` resolves against
the current URL. The default budget is five hops (`DEFAULT_MAX_REDIRECTS`,
configurable with `with_max_redirects`); exceeding it is a policy denial. An
HTTPS-to-HTTP downgrade is refused, an HTTP-to-HTTPS upgrade is allowed, and a
non-HTTP(S) target (`file`, `javascript`, `data`, `ftp`, ...) is refused by the
same scheme check as a direct request.

### Secret checks

`with_secrets` registers values that must never leave the device.
`assert_no_secrets` refuses a haystack containing any non-empty registered or
per-request secret; `check_request` applies it to the URL, every header value,
and the body. This is a plain substring check, not secret detection: only values
the caller registers are caught. Errors name the offending request part and
never echo the value.

`check_request` also requires the method and header names to be HTTP tokens and
rejects a header value containing a line break, so a caller cannot smuggle a
second request.

### Egress test matrix

The egress fixtures use a scripted resolver; no test opens a socket.

| Fixture | Expected |
|---|---|
| metadata IPv4, IPv4-mapped, IPv6, hostname | blocked in every policy |
| loopback v4/v6, `127.1`, mapped loopback | blocked in `Restricted`, allowed in `Full` |
| RFC 1918, CGNAT, ULA | blocked in `Restricted`, allowed in `Full` |
| link-local, multicast, unspecified, broadcast, reserved | blocked in `Full` too |
| `file`, `javascript`, `data`, `ftp`, `ws`, userinfo | refused |
| public HTTP(S), public IPv6, IP literals | pinned; IP literals skip resolution |
| resolver failure or empty answer | `Unavailable` |
| resolver returns public and private | rejected |
| redirect to private, metadata, or loopback | rejected |
| HTTPS-to-HTTP redirect | rejected |
| redirect past the budget | rejected |
| secret in URL, header value, or body | rejected without echoing it |
| clean request | returns `PinnedRequest` |

## Tests

`cargo test -p zero-web` runs 70 scripted tests with no network access and no
sleeps, plus one doc test:

- 9 search/fusion tests: a three-engine relevance fixture, URL and fuzzy-title
  deduplication, an engine error, an unhealthy engine, empty-query and
  zero-limit behavior, key normalization.
- 9 filter/provenance tests: timestamp parsing, a 19-case filter matrix,
  provenance ages and date sources, category classification.
- 16 cache tests: round trip, expired-entry miss and deletion, per-category
  TTL, cache-age rejection, category invalidation, replacement, clear, purge,
  FTS5 title/snippet search, hostile-payload round trip, corrupt-payload miss,
  and reopen persistence.
- 17 resilience tests: breaker transitions and half-open probes, exponential
  backoff and its cap, rate-limit windows, backoff gating, CAPTCHA benching and
  cooldown expiry, login-marker matching, reserve fallback, panic isolation, and
  fused-order parity with `search`.
- 19 egress tests: the policy matrix, metadata and loopback fixtures, private
  and reserved ranges, scheme and userinfo refusals, DNS-rebinding rejection,
  redirect re-checks and the redirect budget, downgrade refusal, secret checks
  in URL/header/body, request-token validation, and clean pinning.
