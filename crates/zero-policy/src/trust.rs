//! Workspace trust (TRU-01, TRU-02): explicit, per-project, revocable.
//!
//! Untrusted project content is inert: hooks, monitors, MCP servers, skills,
//! instruction files, and `.halcyon-mode` are not loaded, and policy runs
//! plan-equivalent.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustEntry {
    pub project_key: String,
    pub path: String,
    pub trusted_at: i64,
    pub trusted_by: String,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TrustFile {
    entries: BTreeMap<String, TrustEntry>,
}

pub struct TrustStore {
    path: PathBuf,
    entries: BTreeMap<String, TrustEntry>,
}

impl TrustStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let entries = if path.exists() {
            serde_json::from_str::<TrustFile>(&std::fs::read_to_string(&path)?)?.entries
        } else {
            BTreeMap::new()
        };
        Ok(Self { path, entries })
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&TrustFile { entries: self.entries.clone() })?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Explicit trust by the user. Re-trusting a revoked project is allowed.
    pub fn trust(&mut self, project_key: &str, path: impl AsRef<Path>, actor: &str, now_ms: i64) -> Result<TrustEntry> {
        if project_key.trim().is_empty() {
            return Err(ZeroError::new(ErrorCode::InvalidInput, "a project key is required"));
        }
        let entry = TrustEntry {
            project_key: project_key.to_string(),
            path: path.as_ref().display().to_string(),
            trusted_at: now_ms,
            trusted_by: actor.to_string(),
            revoked: false,
            revoked_at: None,
        };
        self.entries.insert(project_key.to_string(), entry.clone());
        self.save()?;
        Ok(entry)
    }

    pub fn revoke(&mut self, project_key: &str, now_ms: i64) -> Result<TrustEntry> {
        let entry = self
            .entries
            .get_mut(project_key)
            .ok_or_else(|| ZeroError::new(ErrorCode::TrustRequired, format!("`{project_key}` is not trusted")))?;
        entry.revoked = true;
        entry.revoked_at = Some(now_ms);
        let out = entry.clone();
        self.save()?;
        Ok(out)
    }

    pub fn is_trusted(&self, project_key: &str) -> bool {
        self.entries.get(project_key).map(|e| !e.revoked).unwrap_or(false)
    }

    pub fn get(&self, project_key: &str) -> Option<&TrustEntry> {
        self.entries.get(project_key)
    }
}

/// What a project contributes once trusted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectFeatures {
    pub hooks: Vec<String>,
    pub monitors: Vec<String>,
    pub mcp_servers: Vec<String>,
    pub skills: Vec<String>,
    pub instruction_files: Vec<String>,
    pub halcyon_mode: bool,
    /// True when nothing was loaded because the project is untrusted.
    pub inert: bool,
}

/// Load project-provided features only when the project is trusted.
pub fn load_project_features(root: &Path, trusted: bool) -> ProjectFeatures {
    if !trusted {
        return ProjectFeatures { inert: true, ..ProjectFeatures::default() };
    }
    let zero = root.join(".zero");
    let mut features = ProjectFeatures {
        hooks: read_list(&zero.join("hooks.json"), "hooks"),
        monitors: read_list(&zero.join("monitors.json"), "monitors"),
        mcp_servers: read_list(&zero.join("mcp.json"), "servers"),
        skills: read_list(&zero.join("skills.json"), "skills"),
        instruction_files: Vec::new(),
        halcyon_mode: root.join(".halcyon-mode").exists(),
        inert: false,
    };
    for name in ["AGENTS.md", "CLAUDE.md"] {
        if root.join(name).exists() {
            features.instruction_files.push(name.to_string());
        }
    }
    features
}

fn read_list(path: &Path, key: &str) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    match &value {
        serde_json::Value::Array(items) => items.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::Array(items)) = map.get(key) {
                items.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()
            } else {
                map.keys().cloned().collect()
            }
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(dir: &Path) {
        std::fs::create_dir_all(dir.join(".zero")).unwrap();
        std::fs::write(dir.join(".zero/hooks.json"), r#"{"hooks":["format-on-save"]}"#).unwrap();
        std::fs::write(dir.join(".zero/mcp.json"), r#"{"servers":["local-mcp"]}"#).unwrap();
        std::fs::write(dir.join(".zero/monitors.json"), r#"["ci-watch"]"#).unwrap();
        std::fs::write(dir.join(".zero/skills.json"), r#"{"skills":["deploy"]}"#).unwrap();
        std::fs::write(dir.join("AGENTS.md"), "repo instructions").unwrap();
        std::fs::write(dir.join(".halcyon-mode"), "{}").unwrap();
    }

    #[test]
    fn an_untrusted_repo_contributes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        project(dir.path());
        let features = load_project_features(dir.path(), false);
        assert!(features.inert);
        assert!(features.hooks.is_empty());
        assert!(features.mcp_servers.is_empty());
        assert!(features.monitors.is_empty());
        assert!(features.skills.is_empty());
        assert!(features.instruction_files.is_empty());
        assert!(!features.halcyon_mode);
    }

    #[test]
    fn trust_and_revocation_control_loading() {
        let dir = tempfile::tempdir().unwrap();
        project(dir.path());
        let store_path = dir.path().join("trust.json");
        {
            let mut store = TrustStore::open(&store_path).unwrap();
            assert!(!store.is_trusted("key-1"));
            store.trust("key-1", dir.path(), "user", 100).unwrap();
        }
        let mut store = TrustStore::open(&store_path).unwrap();
        assert!(store.is_trusted("key-1"));
        let features = load_project_features(dir.path(), store.is_trusted("key-1"));
        assert!(!features.inert);
        assert_eq!(features.hooks, vec!["format-on-save"]);
        assert_eq!(features.mcp_servers, vec!["local-mcp"]);
        assert_eq!(features.monitors, vec!["ci-watch"]);
        assert_eq!(features.skills, vec!["deploy"]);
        assert_eq!(features.instruction_files, vec!["AGENTS.md"]);
        assert!(features.halcyon_mode);

        store.revoke("key-1", 200).unwrap();
        assert!(!store.is_trusted("key-1"));
        let features = load_project_features(dir.path(), store.is_trusted("key-1"));
        assert!(features.inert);
        assert!(features.hooks.is_empty());
    }

    #[test]
    fn revocation_is_durable_and_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");
        {
            let mut store = TrustStore::open(&path).unwrap();
            store.trust("k", dir.path(), "user", 1).unwrap();
            store.revoke("k", 2).unwrap();
        }
        let store = TrustStore::open(&path).unwrap();
        let entry = store.get("k").unwrap();
        assert!(entry.revoked);
        assert_eq!(entry.revoked_at, Some(2));
        assert!(!store.is_trusted("k"));
    }
}
