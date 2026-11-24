//! Structured logging with correlation IDs and redaction at the sink (FND-06).
//!
//! A record always carries level, component, session, project, and correlation
//! IDs. Every field, including the message, passes through [`RedactionEngine`]
//! before reaching any sink.

use crate::error::{ErrorCode, Result, ZeroError};
use crate::redact::RedactionEngine;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Trace => "trace",
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Fields {
    #[serde(flatten)]
    pub values: serde_json::Map<String, serde_json::Value>,
}

impl Fields {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.values.insert(key.to_string(), value.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub ts: i64,
    pub level: String,
    pub component: String,
    pub session: Option<String>,
    pub project: Option<String>,
    pub correlation: Option<String>,
    pub message: String,
    #[serde(flatten)]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

pub trait Sink: Send + Sync {
    fn write_record(&self, line: &str) -> std::io::Result<()>;
    fn flush(&self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Captures lines in memory; used by tests and the `doctor` snapshot.
#[derive(Default, Clone)]
pub struct MemorySink {
    lines: Arc<Mutex<Vec<String>>>,
}

impl MemorySink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lines(&self) -> Vec<String> {
        self.lines.lock().expect("lock").clone()
    }

    pub fn text(&self) -> String {
        self.lines.lock().expect("lock").join("\n")
    }
}

impl Sink for MemorySink {
    fn write_record(&self, line: &str) -> std::io::Result<()> {
        self.lines.lock().expect("lock").push(line.to_string());
        Ok(())
    }
}

/// Appends JSONL and fsyncs on flush.
pub struct FileSink {
    path: PathBuf,
    file: Mutex<std::fs::File>,
}

impl FileSink {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self { path, file: Mutex::new(file) })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Sink for FileSink {
    fn write_record(&self, line: &str) -> std::io::Result<()> {
        let mut f = self.file.lock().expect("lock");
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        f.flush()
    }

    fn flush(&self) -> std::io::Result<()> {
        let f = self.file.lock().expect("lock");
        f.sync_data()
    }
}

/// Writes to stderr; used by the CLI default.
pub struct StderrSink;

impl Sink for StderrSink {
    fn write_record(&self, line: &str) -> std::io::Result<()> {
        eprintln!("{line}");
        Ok(())
    }
}

pub struct Logger {
    component: String,
    session: Option<String>,
    project: Option<String>,
    correlation: Option<String>,
    min_level: Level,
    redaction: RedactionEngine,
    sinks: Vec<Arc<dyn Sink>>,
    clock: Arc<dyn crate::id::Clock>,
}

impl Logger {
    pub fn new(component: impl Into<String>, clock: Arc<dyn crate::id::Clock>) -> Self {
        Self {
            component: component.into(),
            session: None,
            project: None,
            correlation: None,
            min_level: Level::Info,
            redaction: RedactionEngine::new(),
            sinks: Vec::new(),
            clock,
        }
    }

    pub fn with_session(mut self, session: impl Into<String>) -> Self {
        self.session = Some(session.into());
        self
    }

    pub fn with_project(mut self, project: impl Into<String>) -> Self {
        self.project = Some(project.into());
        self
    }

    pub fn with_correlation(mut self, correlation: impl Into<String>) -> Self {
        self.correlation = Some(correlation.into());
        self
    }

    pub fn with_min_level(mut self, level: Level) -> Self {
        self.min_level = level;
        self
    }

    pub fn with_redaction(mut self, engine: RedactionEngine) -> Self {
        self.redaction = engine;
        self
    }

    pub fn add_sink(mut self, sink: Arc<dyn Sink>) -> Self {
        self.sinks.push(sink);
        self
    }

    /// Register a secret so every future record redacts it.
    pub fn register_secret(&mut self, secret: impl Into<String>) {
        self.redaction.register(secret);
    }

    pub fn log(&self, level: Level, message: impl AsRef<str>, fields: Fields) -> Result<()> {
        if level < self.min_level {
            return Ok(());
        }
        let mut record = Record {
            ts: self.clock.now().millis(),
            level: level.as_str().to_string(),
            component: self.component.clone(),
            session: self.session.clone(),
            project: self.project.clone(),
            correlation: self.correlation.clone(),
            message: self.redaction.redact(message.as_ref()).text,
            fields: serde_json::Map::new(),
        };
        for (k, v) in fields.values {
            let redacted = match v {
                serde_json::Value::String(s) => serde_json::Value::String(self.redaction.redact(&s).text),
                other => {
                    let rendered = other.to_string();
                    let r = self.redaction.redact(&rendered);
                    if r.rules.is_empty() {
                        other
                    } else {
                        serde_json::Value::String(r.text)
                    }
                }
            };
            record.fields.insert(self.redaction.redact(&k).text, redacted);
        }
        let line = serde_json::to_string(&record)?;
        for sink in &self.sinks {
            sink.write_record(&line).map_err(|e| {
                ZeroError::new(ErrorCode::Io, format!("log sink failed: {e}"))
            })?;
        }
        Ok(())
    }

    pub fn info(&self, message: impl AsRef<str>) -> Result<()> {
        self.log(Level::Info, message, Fields::new())
    }

    pub fn error(&self, message: impl AsRef<str>) -> Result<()> {
        self.log(Level::Error, message, Fields::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::FakeClock;

    fn seeded() -> RedactionEngine {
        let mut r = RedactionEngine::new();
        r.register("sk-test-SEEDED-FAKE-SECRET-0123456789");
        r
    }

    #[test]
    fn seeded_secret_never_appears_in_any_sink() {
        let dir = tempfile::tempdir().unwrap();
        let mem = Arc::new(MemorySink::new());
        let file = Arc::new(FileSink::open(dir.path().join("zero.log")).unwrap());
        let logger = Logger::new("test", Arc::new(FakeClock::at(0)))
            .with_session("s-1")
            .with_project("p-1")
            .with_correlation("c-1")
            .with_redaction(seeded())
            .add_sink(mem.clone())
            .add_sink(file.clone());

        let secret = "sk-test-SEEDED-FAKE-SECRET-0123456789";
        logger
            .log(Level::Info, format!("request with {secret} failed"), Fields::new().with("auth", secret))
            .unwrap();
        logger.info("plain message").unwrap();

        assert!(!mem.text().contains(secret));
        let disk = std::fs::read_to_string(file.path()).unwrap();
        assert!(!disk.contains(secret));
        assert!(disk.contains("[REDACTED:registered]"));

        // Structure: every record carries the five correlation fields.
        let first: Record = serde_json::from_str(mem.lines()[0].as_str()).unwrap();
        assert_eq!(first.component, "test");
        assert_eq!(first.session.as_deref(), Some("s-1"));
        assert_eq!(first.project.as_deref(), Some("p-1"));
        assert_eq!(first.correlation.as_deref(), Some("c-1"));
        assert_eq!(first.level, "info");
    }

    #[test]
    fn level_filter_drops_lower_records() {
        let mem = Arc::new(MemorySink::new());
        let logger = Logger::new("test", Arc::new(FakeClock::at(0)))
            .with_min_level(Level::Warn)
            .add_sink(mem.clone());
        logger.info("dropped").unwrap();
        logger.error("kept").unwrap();
        assert_eq!(mem.lines().len(), 1);
        assert!(mem.lines()[0].contains("kept"));
    }

    #[test]
    fn fields_are_redacted_too() {
        let mem = Arc::new(MemorySink::new());
        let logger = Logger::new("test", Arc::new(FakeClock::at(0)))
            .with_redaction(seeded())
            .add_sink(mem.clone());
        logger
            .log(Level::Info, "x", Fields::new().with("key", "sk-test-SEEDED-FAKE-SECRET-0123456789"))
            .unwrap();
        assert!(!mem.text().contains("SEEDED"));
    }
}
