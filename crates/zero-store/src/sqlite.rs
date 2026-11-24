//! SQLite store in WAL mode with a schema version gate (FND-04, FND-09).
//!
//! One writer per database is the invariant. WAL gives readers a coherent
//! snapshot while the writer appends.

use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result, ZeroError};

pub const SCHEMA_VERSION: u32 = 1;

pub struct SqliteStore {
    conn: Connection,
    path: PathBuf,
}

impl std::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteStore").field("path", &self.path).finish()
    }
}

impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(&path).map_err(sql_err)?;
        conn.pragma_update(None, "journal_mode", "WAL").map_err(sql_err)?;
        conn.pragma_update(None, "synchronous", "FULL").map_err(sql_err)?;
        conn.pragma_update(None, "foreign_keys", "ON").map_err(sql_err)?;
        let store = Self { conn, path };
        store.migrate()?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn migrate(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS events (
                     seq INTEGER PRIMARY KEY,
                     ts INTEGER NOT NULL,
                     kind TEXT NOT NULL,
                     payload TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS kv (
                     scope TEXT NOT NULL,
                     key TEXT NOT NULL,
                     value TEXT NOT NULL,
                     PRIMARY KEY (scope, key)
                 );",
            )
            .map_err(sql_err)?;
        let current: u32 = self
            .conn
            .query_row("SELECT value FROM meta WHERE key='schema_version'", [], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .map_err(sql_err)?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if current > SCHEMA_VERSION {
            return Err(ZeroError::new(
                ErrorCode::SchemaVersion,
                format!(
                    "database {} is schema {current}, this build supports {SCHEMA_VERSION}; downgrade refused",
                    self.path.display()
                ),
            ));
        }
        self.conn
            .execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?1)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![SCHEMA_VERSION.to_string()],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn schema_version(&self) -> Result<u32> {
        let v: String = self
            .conn
            .query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0))
            .map_err(sql_err)?;
        v.parse().map_err(|_| ZeroError::new(ErrorCode::Corrupt, "schema_version is not a number"))
    }

    pub fn journal_mode(&self) -> Result<String> {
        self.conn
            .query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))
            .map_err(sql_err)
    }

    pub fn append_event(&mut self, seq: u64, ts: i64, kind: &str, payload: &serde_json::Value) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO events(seq, ts, kind, payload) VALUES(?1, ?2, ?3, ?4)",
                params![seq as i64, ts, kind, serde_json::to_string(payload)?],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn event_count(&self) -> Result<u64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get::<_, i64>(0))
            .map(|v| v as u64)
            .map_err(sql_err)
    }

    pub fn put(&mut self, scope: &str, key: &str, value: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO kv(scope, key, value) VALUES(?1, ?2, ?3)
                 ON CONFLICT(scope, key) DO UPDATE SET value=excluded.value",
                params![scope, key, value],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    pub fn get(&self, scope: &str, key: &str) -> Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT value FROM kv WHERE scope=?1 AND key=?2",
                params![scope, key],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql_err)
    }
}

use rusqlite::OptionalExtension;

fn sql_err(e: rusqlite::Error) -> ZeroError {
    ZeroError::new(ErrorCode::Io, format!("sqlite: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wal_mode_is_on_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zero.db");
        {
            let mut s = SqliteStore::open(&path).unwrap();
            assert_eq!(s.journal_mode().unwrap().to_lowercase(), "wal");
            assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
            s.append_event(1, 100, "hello", &serde_json::json!({"a":1})).unwrap();
            s.put("config", "mode", "manual").unwrap();
        }
        let s = SqliteStore::open(&path).unwrap();
        assert_eq!(s.event_count().unwrap(), 1);
        assert_eq!(s.get("config", "mode").unwrap().as_deref(), Some("manual"));
    }

    #[test]
    fn newer_schema_is_refused_not_downgraded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zero.db");
        drop(SqliteStore::open(&path).unwrap());
        let conn = Connection::open(&path).unwrap();
        conn.execute("UPDATE meta SET value='999' WHERE key='schema_version'", []).unwrap();
        drop(conn);
        let err = SqliteStore::open(&path).unwrap_err();
        assert_eq!(err.code(), ErrorCode::SchemaVersion);
    }
}
