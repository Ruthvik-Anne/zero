//! SQLite FTS5 search cache (WEB-06).
//!
//! [`SearchCache`] stores one whole [`SearchResponse`] as JSON under a
//! `(query, category)` key and mirrors each result into an FTS5 table, so a
//! later research step can search titles and snippets it already fetched
//! without calling an engine again. Entries expire on a per-category TTL and a
//! caller may additionally impose a tighter maximum age.
//!
//! Cached payloads come from the web and are untrusted: they are stored and
//! returned as data. Nothing in a payload is ever evaluated as code, SQL, or a
//! path; the FTS index only treats the text as text. A payload that does not
//! deserialize back into a [`SearchResponse`] is dropped and reported as a
//! cache miss, because a corrupt cache must never fail a search.
//!
//! FTS5 is compiled into the bundled SQLite used by `rusqlite`. [`SearchCache::open`]
//! verifies that the module is present and returns [`ErrorCode::Unsupported`]
//! when the running SQLite build lacks FTS5; it never panics.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::search::SearchResponse;

/// Default entry lifetime: 15 minutes.
pub const DEFAULT_TTL_MS: i64 = 15 * 60 * 1000;

/// Per-category cache lifetimes.
///
/// A category that is not listed falls back to the policy's default. Category
/// names are the values produced by [`crate::filter::category_for`]
/// (`docs`, `code`, `news`, `general`) and are matched case-insensitively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TtlPolicy {
    default_ms: i64,
    per_category: HashMap<String, i64>,
}

impl TtlPolicy {
    /// A policy with one default and no category overrides.
    pub fn new(default_ms: i64) -> Self {
        Self {
            default_ms,
            per_category: HashMap::new(),
        }
    }

    /// Add an override for one category; chainable.
    pub fn with_category(mut self, category: impl Into<String>, ttl_ms: i64) -> Self {
        self.per_category.insert(category.into(), ttl_ms);
        self
    }

    /// The fallback lifetime.
    pub fn default_ms(&self) -> i64 {
        self.default_ms
    }

    /// Lifetime for `category`, or the default when it has no override.
    pub fn ttl_for(&self, category: &str) -> i64 {
        self.per_category
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(category))
            .map(|(_, ttl_ms)| *ttl_ms)
            .unwrap_or(self.default_ms)
    }
}

impl Default for TtlPolicy {
    fn default() -> Self {
        Self::new(DEFAULT_TTL_MS)
    }
}

/// One cached result found through the FTS5 index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexHit {
    /// The cached query this result was fetched for.
    pub query: String,
    pub title: String,
    pub snippet: String,
    pub url: String,
    /// `snippet()` rendering of the matched text, with `[` `]` around the
    /// match. Untrusted content, shown as plain text.
    pub highlighted: String,
}

/// A SQLite-backed cache for fused search responses, indexed with FTS5.
pub struct SearchCache {
    conn: Connection,
    path: PathBuf,
}

impl SearchCache {
    /// Open (or create) the cache at `path` and verify FTS5 support.
    ///
    /// `":memory:"` opens a transient cache. The parent directory is created
    /// when it does not exist.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open(&path).map_err(sql_err)?;
        conn.busy_timeout(Duration::from_millis(5_000))
            .map_err(sql_err)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(sql_err)?;
        let cache = Self { conn, path };
        cache.migrate()?;
        Ok(cache)
    }

    /// The database file backing this cache.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn migrate(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS cache_entries (
                     key TEXT PRIMARY KEY,
                     query TEXT NOT NULL,
                     category TEXT NOT NULL,
                     stored_at_ms INTEGER NOT NULL,
                     expires_at_ms INTEGER NOT NULL,
                     payload TEXT NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS cache_entries_category
                     ON cache_entries(category);
                 CREATE INDEX IF NOT EXISTS cache_entries_expiry
                     ON cache_entries(expires_at_ms);",
            )
            .map_err(sql_err)?;
        self.conn
            .execute_batch(
                "CREATE VIRTUAL TABLE IF NOT EXISTS cache_fts
                     USING fts5(query, title, snippet, url, tokenize = 'unicode61');
                 CREATE TABLE IF NOT EXISTS cache_fts_map (
                     rowid INTEGER PRIMARY KEY,
                     entry_key TEXT NOT NULL,
                     category TEXT NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS cache_fts_map_key
                     ON cache_fts_map(entry_key);
                 CREATE INDEX IF NOT EXISTS cache_fts_map_category
                     ON cache_fts_map(category);",
            )
            .map_err(fts_err)?;
        Ok(())
    }

    /// Store `response` under `(query, category)` until `now_ms + ttl_ms`.
    ///
    /// A TTL at or below zero already expired the entry on the next read. An
    /// existing entry for the same key is replaced and its old index rows are
    /// removed first, so stale result text is never searchable.
    pub fn put(
        &self,
        query: &str,
        category: &str,
        response: &SearchResponse,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<()> {
        let key = entry_key(query, category);
        let expires_at_ms = now_ms.saturating_add(ttl_ms.max(0));
        let payload = serde_json::to_string(response)?;

        let tx = self.conn.unchecked_transaction().map_err(sql_err)?;
        tx.execute(
            "INSERT INTO cache_entries(key, query, category, stored_at_ms, expires_at_ms, payload)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(key) DO UPDATE SET
                 query = excluded.query,
                 category = excluded.category,
                 stored_at_ms = excluded.stored_at_ms,
                 expires_at_ms = excluded.expires_at_ms,
                 payload = excluded.payload",
            params![
                key.as_str(),
                query,
                category,
                now_ms,
                expires_at_ms,
                payload
            ],
        )
        .map_err(sql_err)?;

        Self::delete_index_rows(&tx, &key)?;
        for result in &response.results {
            tx.execute(
                "INSERT INTO cache_fts(query, title, snippet, url) VALUES(?1, ?2, ?3, ?4)",
                params![query, result.title, result.snippet, result.url],
            )
            .map_err(sql_err)?;
            let rowid = tx.last_insert_rowid();
            tx.execute(
                "INSERT INTO cache_fts_map(rowid, entry_key, category) VALUES(?1, ?2, ?3)",
                params![rowid, key.as_str(), category],
            )
            .map_err(sql_err)?;
        }
        tx.commit().map_err(sql_err)?;
        Ok(())
    }

    /// Store `response` using the lifetime this policy assigns to `category`.
    pub fn put_with_policy(
        &self,
        query: &str,
        category: &str,
        response: &SearchResponse,
        now_ms: i64,
        policy: &TtlPolicy,
    ) -> Result<()> {
        self.put(query, category, response, now_ms, policy.ttl_for(category))
    }

    /// Return the cached response for `(query, category)` if it is still valid.
    ///
    /// An entry at or past `expires_at_ms` is deleted and reported as a miss.
    /// Query lookup is case-insensitive and whitespace-normalized.
    pub fn get(&self, query: &str, category: &str, now_ms: i64) -> Result<Option<SearchResponse>> {
        self.get_with_max_age(query, category, now_ms, i64::MAX)
    }

    /// Like [`SearchCache::get`], but also reject entries older than
    /// `max_age_ms` even when their TTL has not elapsed.
    ///
    /// This is the cache-age filter: a caller that needs fresher data than the
    /// category TTL allows passes its own bound. Age is `now_ms - stored_at_ms`
    /// (clamped at zero for clock skew). A rejected entry is **not** deleted,
    /// because a later caller with a looser bound may still use it; only an
    /// expired entry is deleted.
    pub fn get_with_max_age(
        &self,
        query: &str,
        category: &str,
        now_ms: i64,
        max_age_ms: i64,
    ) -> Result<Option<SearchResponse>> {
        let key = entry_key(query, category);
        let row: Option<(i64, i64, String)> = self
            .conn
            .query_row(
                "SELECT stored_at_ms, expires_at_ms, payload
                 FROM cache_entries WHERE key = ?1",
                params![key.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(sql_err)?;
        let Some((stored_at_ms, expires_at_ms, payload)) = row else {
            return Ok(None);
        };

        if expires_at_ms <= now_ms {
            self.remove_entry(&key)?;
            return Ok(None);
        }
        if now_ms.saturating_sub(stored_at_ms) > max_age_ms {
            return Ok(None);
        }

        match serde_json::from_str::<SearchResponse>(&payload) {
            Ok(response) => Ok(Some(response)),
            // A cache that cannot be read is a miss, never an error: the
            // caller can simply search again.
            Err(_) => {
                self.remove_entry(&key)?;
                Ok(None)
            }
        }
    }

    /// Drop every entry in `category` and its index rows; returns the number of
    /// entries removed.
    pub fn invalidate_category(&self, category: &str) -> Result<usize> {
        let tx = self.conn.unchecked_transaction().map_err(sql_err)?;
        tx.execute(
            "DELETE FROM cache_fts WHERE rowid IN (
                 SELECT rowid FROM cache_fts_map WHERE category = ?1
             )",
            params![category],
        )
        .map_err(sql_err)?;
        tx.execute(
            "DELETE FROM cache_fts_map WHERE category = ?1",
            params![category],
        )
        .map_err(sql_err)?;
        let removed = tx
            .execute(
                "DELETE FROM cache_entries WHERE category = ?1",
                params![category],
            )
            .map_err(sql_err)?;
        tx.commit().map_err(sql_err)?;
        Ok(removed)
    }

    /// Remove every entry and every index row.
    pub fn clear(&self) -> Result<()> {
        let tx = self.conn.unchecked_transaction().map_err(sql_err)?;
        tx.execute("DELETE FROM cache_fts", []).map_err(sql_err)?;
        tx.execute("DELETE FROM cache_fts_map", [])
            .map_err(sql_err)?;
        tx.execute("DELETE FROM cache_entries", [])
            .map_err(sql_err)?;
        tx.commit().map_err(sql_err)?;
        Ok(())
    }

    /// Delete entries whose TTL has elapsed; returns how many were removed.
    pub fn purge_expired(&self, now_ms: i64) -> Result<usize> {
        let tx = self.conn.unchecked_transaction().map_err(sql_err)?;
        tx.execute(
            "DELETE FROM cache_fts WHERE rowid IN (
                 SELECT map.rowid FROM cache_fts_map map
                 JOIN cache_entries entry ON entry.key = map.entry_key
                 WHERE entry.expires_at_ms <= ?1
             )",
            params![now_ms],
        )
        .map_err(sql_err)?;
        tx.execute(
            "DELETE FROM cache_fts_map WHERE entry_key IN (
                 SELECT key FROM cache_entries WHERE expires_at_ms <= ?1
             )",
            params![now_ms],
        )
        .map_err(sql_err)?;
        let removed = tx
            .execute(
                "DELETE FROM cache_entries WHERE expires_at_ms <= ?1",
                params![now_ms],
            )
            .map_err(sql_err)?;
        tx.commit().map_err(sql_err)?;
        Ok(removed)
    }

    /// Full-text search over cached titles and snippets.
    ///
    /// `text` is split into alphanumeric tokens and every token must match
    /// (implicit AND), so arbitrary punctuation cannot turn into FTS5 syntax.
    /// Results are ordered by FTS5 rank and truncated to `limit`; an empty or
    /// token-free `text` and `limit == 0` return no rows.
    pub fn search_index(&self, text: &str, limit: usize) -> Result<Vec<IndexHit>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let Some(match_expression) = fts_match_expression(text) else {
            return Ok(Vec::new());
        };

        let mut statement = self
            .conn
            .prepare(
                "SELECT query, title, snippet, url,
                        snippet(cache_fts, 2, '[', ']', '...', 12)
                 FROM cache_fts
                 WHERE cache_fts MATCH ?1
                 ORDER BY rank
                 LIMIT ?2",
            )
            .map_err(sql_err)?;
        let rows = statement
            .query_map(params![match_expression, limit as i64], |row| {
                Ok(IndexHit {
                    query: row.get(0)?,
                    title: row.get(1)?,
                    snippet: row.get(2)?,
                    url: row.get(3)?,
                    highlighted: row.get(4)?,
                })
            })
            .map_err(sql_err)?;

        let mut hits = Vec::new();
        for row in rows {
            hits.push(row.map_err(sql_err)?);
        }
        Ok(hits)
    }

    fn delete_index_rows(conn: &Connection, key: &str) -> Result<()> {
        conn.execute(
            "DELETE FROM cache_fts WHERE rowid IN (
                 SELECT rowid FROM cache_fts_map WHERE entry_key = ?1
             )",
            params![key],
        )
        .map_err(sql_err)?;
        conn.execute(
            "DELETE FROM cache_fts_map WHERE entry_key = ?1",
            params![key],
        )
        .map_err(sql_err)?;
        Ok(())
    }

    fn remove_entry(&self, key: &str) -> Result<()> {
        let tx = self.conn.unchecked_transaction().map_err(sql_err)?;
        Self::delete_index_rows(&tx, key)?;
        tx.execute("DELETE FROM cache_entries WHERE key = ?1", params![key])
            .map_err(sql_err)?;
        tx.commit().map_err(sql_err)?;
        Ok(())
    }
}

/// Normalize a query for keying: trimmed, whitespace collapsed, lowercased.
fn normalize_query(query: &str) -> String {
    let mut normalized = String::with_capacity(query.len());
    for word in query.split_whitespace() {
        if !normalized.is_empty() {
            normalized.push(' ');
        }
        normalized.push_str(&word.to_lowercase());
    }
    normalized
}

/// Storage key for one `(category, query)` pair. The unit separator cannot
/// appear in a category or a query, so the two parts cannot be confused.
fn entry_key(query: &str, category: &str) -> String {
    format!("{category}\u{1f}{}", normalize_query(query))
}

/// Build an FTS5 MATCH expression restricted to titles and snippets.
///
/// Each token is quoted, so user text such as `rust" -purpose` becomes an
/// ordinary phrase search instead of syntax.
fn fts_match_expression(text: &str) -> Option<String> {
    let mut tokens: Vec<String> = Vec::new();
    for token in text.split(|character: char| !character.is_alphanumeric()) {
        if token.is_empty() {
            continue;
        }
        tokens.push(format!("\"{}\"", token.replace('"', "\"\"")));
    }
    if tokens.is_empty() {
        None
    } else {
        Some(format!("{{title snippet}} : ({})", tokens.join(" ")))
    }
}

fn sql_err(error: rusqlite::Error) -> ZeroError {
    ZeroError::new(ErrorCode::Io, format!("sqlite: {error}"))
}

/// Map a failed schema statement to `Unsupported` when the SQLite build has no
/// FTS5 module, and to `Io` for every other failure.
fn fts_err(error: rusqlite::Error) -> ZeroError {
    let message = error.to_string();
    let lowercase = message.to_ascii_lowercase();
    if lowercase.contains("no such module") || lowercase.contains("fts5") {
        ZeroError::new(
            ErrorCode::Unsupported,
            format!("this SQLite build has no FTS5 support: {message}"),
        )
    } else {
        sql_err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::{EngineRank, FusedResult, SearchError};

    const MINUTE_MS: i64 = 60_000;

    struct Fixture {
        dir: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().expect("temp dir"),
            }
        }

        fn db_path(&self) -> PathBuf {
            self.dir.path().join("cache.db")
        }

        fn open(&self) -> SearchCache {
            SearchCache::open(self.db_path()).expect("cache opens")
        }
    }

    fn response(query: &str, hits: &[(&str, &str, &str)]) -> SearchResponse {
        SearchResponse {
            query: query.to_string(),
            results: hits
                .iter()
                .enumerate()
                .map(|(offset, (title, url, snippet))| FusedResult {
                    title: title.to_string(),
                    url: url.to_string(),
                    snippet: snippet.to_string(),
                    published: None,
                    score: 1.0 / (60.0 + offset as f64 + 1.0),
                    sources: vec![EngineRank {
                        engine: "fixture".to_string(),
                        rank: offset + 1,
                    }],
                })
                .collect(),
            failed: Vec::new(),
        }
    }

    fn rust_response() -> SearchResponse {
        response(
            "rust",
            &[
                (
                    "Rust ownership guide",
                    "https://docs.example.com/rust/ownership",
                    "the borrow checker enforces memory safety",
                ),
                (
                    "Async Rust notes",
                    "https://example.com/async-rust",
                    "futures and executors explained",
                ),
            ],
        )
    }

    #[test]
    fn put_then_get_round_trips_the_response() {
        let fixture = Fixture::new();
        let cache = fixture.open();
        let original = rust_response();

        cache
            .put("rust", "docs", &original, 1_000, 5 * MINUTE_MS)
            .expect("put");
        let cached = cache
            .get("rust", "docs", 2_000)
            .expect("get")
            .expect("entry is present");
        assert_eq!(cached, original);
    }

    #[test]
    fn query_keys_are_trimmed_and_case_insensitive() {
        let fixture = Fixture::new();
        let cache = fixture.open();
        cache
            .put("  Rust  Ownership ", "docs", &rust_response(), 0, MINUTE_MS)
            .expect("put");

        assert!(cache.get("rust ownership", "docs", 1).unwrap().is_some());
        assert!(cache.get("RUST", "docs", 1).unwrap().is_none());
        assert!(cache.get("rust ownership", "news", 1).unwrap().is_none());
    }

    #[test]
    fn expired_entry_is_a_miss_and_is_deleted() {
        let fixture = Fixture::new();
        let cache = fixture.open();
        cache
            .put("rust", "docs", &rust_response(), 0, 1_000)
            .expect("put");

        assert!(cache.get("rust", "docs", 999).unwrap().is_some());
        assert!(cache.get("rust", "docs", 1_000).unwrap().is_none());
        // The expired entry and its index rows were removed, not just hidden.
        assert!(cache.get("rust", "docs", 1_001).unwrap().is_none());
        assert!(cache.search_index("ownership", 10).unwrap().is_empty());
    }

    #[test]
    fn per_category_ttl_uses_the_policy() {
        let fixture = Fixture::new();
        let cache = fixture.open();
        let policy = TtlPolicy::new(MINUTE_MS)
            .with_category("news", 1_000)
            .with_category("docs", 10 * MINUTE_MS);

        cache
            .put_with_policy("rust", "news", &rust_response(), 0, &policy)
            .expect("news put");
        cache
            .put_with_policy("rust", "docs", &rust_response(), 0, &policy)
            .expect("docs put");
        cache
            .put_with_policy("rust", "general", &rust_response(), 0, &policy)
            .expect("general put");

        assert!(cache.get("rust", "news", 1_500).unwrap().is_none());
        assert!(cache.get("rust", "docs", 1_500).unwrap().is_some());
        // `general` has no override, so the default applies.
        assert!(cache.get("rust", "general", 1_500).unwrap().is_some());
        assert!(cache.get("rust", "general", MINUTE_MS).unwrap().is_none());
    }

    #[test]
    fn max_age_rejects_fresh_but_old_entries_without_deleting_them() {
        let fixture = Fixture::new();
        let cache = fixture.open();
        cache
            .put("rust", "docs", &rust_response(), 0, 60 * MINUTE_MS)
            .expect("put");

        // Two minutes old: fresh by TTL, too old for a one-minute caller.
        assert!(cache
            .get_with_max_age("rust", "docs", 2 * MINUTE_MS, MINUTE_MS)
            .unwrap()
            .is_none());
        // The stricter caller did not evict the entry.
        assert!(cache
            .get_with_max_age("rust", "docs", 2 * MINUTE_MS, 5 * MINUTE_MS)
            .unwrap()
            .is_some());
        assert!(cache.get("rust", "docs", 2 * MINUTE_MS).unwrap().is_some());
    }

    #[test]
    fn invalidate_category_removes_only_that_category() {
        let fixture = Fixture::new();
        let cache = fixture.open();
        cache
            .put("rust", "docs", &rust_response(), 0, MINUTE_MS)
            .expect("docs put");
        cache
            .put("rust", "news", &rust_response(), 0, MINUTE_MS)
            .expect("news put");

        assert_eq!(cache.invalidate_category("news").expect("invalidate"), 1);
        assert!(cache.get("rust", "news", 1).unwrap().is_none());
        assert!(cache.get("rust", "docs", 1).unwrap().is_some());
        // Only the docs rows remain in the index.
        let hits = cache.search_index("ownership", 10).unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn fts_index_finds_title_and_snippet_terms() {
        let fixture = Fixture::new();
        let cache = fixture.open();
        cache
            .put("rust", "docs", &rust_response(), 0, MINUTE_MS)
            .expect("put");

        let by_snippet = cache.search_index("checker", 10).unwrap();
        assert_eq!(by_snippet.len(), 1);
        assert_eq!(by_snippet[0].query, "rust");
        assert_eq!(by_snippet[0].title, "Rust ownership guide");
        assert!(by_snippet[0].highlighted.contains("[checker]"));

        let by_title = cache.search_index("executors", 10).unwrap();
        assert_eq!(by_title.len(), 1);
        assert_eq!(by_title[0].url, "https://example.com/async-rust");

        // Every token must match the same cached result; terms spread across
        // two different results do not.
        assert_eq!(cache.search_index("rust checker", 10).unwrap().len(), 1);
        assert!(cache.search_index("async checker", 10).unwrap().is_empty());
        assert!(cache
            .search_index("rust kubernetes", 10)
            .unwrap()
            .is_empty());
        assert!(cache.search_index("kubernetes", 10).unwrap().is_empty());
        // Punctuation and FTS5 operators are treated as separators.
        assert_eq!(
            cache
                .search_index("ownership, checker!*", 10)
                .unwrap()
                .len(),
            1
        );
        assert!(cache.search_index("  --  ", 10).unwrap().is_empty());
        assert!(cache.search_index("", 10).unwrap().is_empty());
        assert!(cache.search_index("ownership", 0).unwrap().is_empty());
    }

    #[test]
    fn reopening_the_same_file_preserves_entries() {
        let fixture = Fixture::new();
        {
            let cache = fixture.open();
            cache
                .put("rust", "docs", &rust_response(), 0, MINUTE_MS)
                .expect("put");
        }
        let reopened = fixture.open();
        let cached = reopened
            .get("rust", "docs", 1)
            .expect("get")
            .expect("entry survives reopen");
        assert_eq!(cached, rust_response());
        assert_eq!(reopened.search_index("checker", 10).unwrap().len(), 1);
    }

    #[test]
    fn clear_removes_entries_and_index_rows() {
        let fixture = Fixture::new();
        let cache = fixture.open();
        cache
            .put("rust", "docs", &rust_response(), 0, MINUTE_MS)
            .expect("put");
        cache.clear().expect("clear");

        assert!(cache.get("rust", "docs", 1).unwrap().is_none());
        assert!(cache.search_index("checker", 10).unwrap().is_empty());
    }

    #[test]
    fn purge_expired_removes_only_expired_entries() {
        let fixture = Fixture::new();
        let cache = fixture.open();
        cache
            .put("rust", "docs", &rust_response(), 0, 1_000)
            .expect("short put");
        cache
            .put("rust", "news", &rust_response(), 0, MINUTE_MS)
            .expect("long put");

        assert_eq!(cache.purge_expired(2_000).expect("purge"), 1);
        assert!(cache.get("rust", "docs", 2_000).unwrap().is_none());
        assert!(cache.get("rust", "news", 2_000).unwrap().is_some());
    }

    #[test]
    fn replacing_an_entry_replaces_its_index_rows() {
        let fixture = Fixture::new();
        let cache = fixture.open();
        cache
            .put("rust", "docs", &rust_response(), 0, MINUTE_MS)
            .expect("first put");
        cache
            .put(
                "rust",
                "docs",
                &response(
                    "rust",
                    &[(
                        "Replacement page",
                        "https://example.com/replacement",
                        "entirely different words",
                    )],
                ),
                1,
                MINUTE_MS,
            )
            .expect("second put");

        assert!(cache.search_index("checker", 10).unwrap().is_empty());
        assert_eq!(cache.search_index("different", 10).unwrap().len(), 1);
        assert_eq!(
            cache.get("rust", "docs", 2).unwrap().unwrap().results.len(),
            1
        );
    }

    #[test]
    fn hostile_payload_round_trips_as_inert_data() {
        let fixture = Fixture::new();
        let cache = fixture.open();
        let hostile = response(
            "'; DROP TABLE cache_entries; --",
            &[(
                "<script>alert(1)</script>",
                "https://example.com/x",
                "'; DELETE FROM cache_fts; --</script>",
            )],
        );
        cache
            .put(
                "'; DROP TABLE cache_entries; --",
                "general",
                &hostile,
                0,
                MINUTE_MS,
            )
            .expect("hostile put");

        let cached = cache
            .get("'; DROP TABLE cache_entries; --", "general", 1)
            .expect("get")
            .expect("entry stored as data");
        assert_eq!(cached, hostile);
        // The schema survived, and the text is indexed as ordinary text.
        assert_eq!(cache.search_index("script", 10).unwrap().len(), 1);
        cache
            .clear()
            .expect("clear still works after hostile content");
    }

    #[test]
    fn failed_payload_is_a_miss_and_is_deleted() {
        let fixture = Fixture::new();
        let cache = fixture.open();
        cache
            .put("rust", "docs", &rust_response(), 0, MINUTE_MS)
            .expect("put");
        cache
            .conn
            .execute(
                "UPDATE cache_entries SET payload = 'not json' WHERE key = ?1",
                params![entry_key("rust", "docs")],
            )
            .expect("corrupt the payload");

        assert!(cache.get("rust", "docs", 1).unwrap().is_none());
        // Corrupt content is removed so it cannot be retried forever.
        assert!(cache.get("rust", "docs", 1).unwrap().is_none());
    }

    #[test]
    fn identical_keys_in_different_categories_do_not_collide() {
        let fixture = Fixture::new();
        let cache = fixture.open();
        cache
            .put("rust", "docs", &rust_response(), 0, MINUTE_MS)
            .expect("docs put");
        cache
            .put(
                "rust",
                "code",
                &response("rust", &[("Repo", "https://github.com/x/y", "code")]),
                0,
                MINUTE_MS,
            )
            .expect("code put");

        assert_eq!(
            cache.get("rust", "docs", 1).unwrap().unwrap().results.len(),
            2
        );
        assert_eq!(
            cache.get("rust", "code", 1).unwrap().unwrap().results.len(),
            1
        );
    }

    #[test]
    fn ttl_policy_reports_category_overrides() {
        let policy = TtlPolicy::new(1_000)
            .with_category("news", 10)
            .with_category("docs", 20);
        assert_eq!(policy.default_ms(), 1_000);
        assert_eq!(policy.ttl_for("news"), 10);
        assert_eq!(policy.ttl_for("NEWS"), 10);
        assert_eq!(policy.ttl_for("general"), 1_000);
        assert_eq!(TtlPolicy::default().default_ms(), DEFAULT_TTL_MS);
    }

    #[test]
    fn failed_search_is_stored_as_part_of_the_response() {
        let fixture = Fixture::new();
        let cache = fixture.open();
        let mut original = rust_response();
        original.failed = vec![SearchError {
            engine: "broken".to_string(),
            message: "rate limited".to_string(),
        }];
        cache
            .put("rust", "docs", &original, 0, MINUTE_MS)
            .expect("put");

        let cached = cache.get("rust", "docs", 1).unwrap().unwrap();
        assert_eq!(cached.failed, original.failed);
    }
}
