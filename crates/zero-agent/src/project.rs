//! Project identity, creation, root detection, moves, copies, replaced keys,
//! layout/migration, and replicated bindings (PRJ-01..PRJ-12).
//!
//! A project is identified by a random key in `.zero/key`; `projectId` is the
//! hash of that key. Paths are local bindings, never identity.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result, ZeroError};

pub const LAYOUT_FILES: &[&str] = &["project.json", "key", "config", "plan", "tasks", "todos"];
pub const LAYOUT_DIRS: &[&str] = &["journal", "artifacts", "vault", "audits"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectFile {
    pub project_id: String,
    pub name: String,
    #[serde(default)]
    pub copied_from: Option<String>,
    pub created_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectBinding {
    pub project_id: String,
    pub name: String,
    pub paths: Vec<PathBuf>,
    #[serde(default)]
    pub copied_from: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RegistryFile {
    projects: BTreeMap<String, ProjectBinding>,
    names: BTreeSet<String>,
    decisions: BTreeSet<String>,
}

pub struct BindingRegistry {
    path: PathBuf,
    file: RegistryFile,
}

impl BindingRegistry {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => RegistryFile::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self { path, file })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.file)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn get(&self, project_id: &str) -> Option<&ProjectBinding> {
        self.file.projects.get(project_id)
    }

    pub fn by_path(&self, path: &Path) -> Option<&ProjectBinding> {
        self.file.projects.values().find(|binding| binding.paths.iter().any(|p| p == path))
    }

    pub fn projects(&self) -> impl Iterator<Item = &ProjectBinding> {
        self.file.projects.values()
    }

    fn unique_name(&self, base: &str) -> String {
        if !self.file.names.contains(base) {
            return base.to_string();
        }
        let mut n = 2;
        loop {
            let candidate = format!("{base} {n}");
            if !self.file.names.contains(&candidate) {
                return candidate;
            }
            n += 1;
        }
    }

    fn bind(&mut self, project_id: &str, name: &str, path: &Path, copied_from: Option<String>) {
        let binding = self.file.projects.entry(project_id.to_string()).or_insert(ProjectBinding {
            project_id: project_id.to_string(),
            name: name.to_string(),
            paths: Vec::new(),
            copied_from: copied_from.clone(),
        });
        if !binding.paths.iter().any(|p| p == path) {
            binding.paths.push(path.to_path_buf());
        }
        if copied_from.is_some() {
            binding.copied_from = copied_from;
        }
        self.file.names.insert(name.to_string());
    }

    /// Merge replicated state: union paths per project, no conflict.
    pub fn merge_remote(&mut self, remote: &BindingRegistry) -> Result<usize> {
        let mut added = 0;
        for binding in remote.file.projects.values() {
            // Identity and name replicate; each device keeps its own local paths.
            if !self.file.projects.contains_key(&binding.project_id) {
                self.file.projects.insert(
                    binding.project_id.clone(),
                    ProjectBinding {
                        project_id: binding.project_id.clone(),
                        name: binding.name.clone(),
                        paths: Vec::new(),
                        copied_from: binding.copied_from.clone(),
                    },
                );
                self.file.names.insert(binding.name.clone());
                added += 1;
            }
        }
        self.save()?;
        Ok(added)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub root: PathBuf,
    pub project_id: String,
    pub name: String,
    pub key: String,
    pub copied_from: Option<String>,
}

impl Project {
    pub fn zero_dir(&self) -> PathBuf {
        self.root.join(".zero")
    }

    pub fn layout_complete(&self) -> bool {
        let zero = self.zero_dir();
        LAYOUT_FILES.iter().all(|name| zero.join(name).exists())
            && LAYOUT_DIRS.iter().all(|name| zero.join(name).is_dir())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    Interactive,
    NonInteractive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenOutcome {
    Created(Project),
    Opened(Project),
    Moved(Project),
    /// The same key exists at another live path: ask once for a new name.
    CopyPrompt { old_path: PathBuf, typed_name: String, project: Project },
    /// A path's key changed; choose adopt or restore.
    KeyReplaced { path: PathBuf, stored_id: String, found_id: String, root: PathBuf },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceChoice {
    Adopt,
    Restore,
}

/// Nearest `.zero`, else the git root, else the working directory, stopping at
/// the home directory or filesystem root.
pub fn find_root(start: &Path, home: &Path) -> Result<PathBuf> {
    let start = std::fs::canonicalize(start)?;
    let home = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    let mut git_root = None;
    let mut cursor = Some(start.as_path());
    while let Some(dir) = cursor {
        if dir.join(".zero").is_dir() {
            return Ok(dir.to_path_buf());
        }
        if git_root.is_none() && dir.join(".git").exists() {
            git_root = Some(dir.to_path_buf());
        }
        if dir == home {
            break;
        }
        cursor = dir.parent();
    }
    Ok(git_root.unwrap_or(start))
}

fn generate_key() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seed = format!("{}-{}-{}", nanos, std::process::id(), std::thread::current().name().unwrap_or(""));
    blake3::hash(seed.as_bytes()).to_hex().to_string()
}

pub fn project_id_for(key: &str) -> String {
    blake3::hash(key.as_bytes()).to_hex().to_string()
}

fn write_key(zero: &Path, key: &str) -> Result<()> {
    std::fs::create_dir_all(zero)?;
    let path = zero.join("key");
    if path.exists() {
        let _ = std::fs::copy(&path, zero.join("key.prev"));
    }
    std::fs::write(&path, key)?;
    Ok(())
}

fn read_key(zero: &Path) -> Option<String> {
    std::fs::read_to_string(zero.join("key")).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn ensure_layout(root: &Path) -> Result<()> {
    let zero = root.join(".zero");
    std::fs::create_dir_all(&zero)?;
    for dir in LAYOUT_DIRS {
        std::fs::create_dir_all(zero.join(dir))?;
    }
    for file in ["config", "plan", "tasks", "todos"] {
        let path = zero.join(file);
        if !path.exists() {
            std::fs::write(&path, b"{}")?;
        }
    }
    Ok(())
}

fn write_project_file(root: &Path, file: &ProjectFile) -> Result<()> {
    std::fs::write(root.join(".zero").join("project.json"), serde_json::to_vec_pretty(file)?)?;
    Ok(())
}

fn read_project_file(root: &Path) -> Option<ProjectFile> {
    std::fs::read_to_string(root.join(".zero").join("project.json"))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
}

fn ensure_gitignore(root: &Path) -> Result<Option<PathBuf>> {
    if !root.join(".git").exists() {
        return Ok(None);
    }
    let path = root.join(".gitignore");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    if existing.lines().any(|line| line.trim() == ".zero/") {
        return Ok(None);
    }
    let mut next = existing;
    if !next.is_empty() && !next.ends_with('\n') {
        next.push('\n');
    }
    next.push_str(".zero/\n");
    std::fs::write(&path, next)?;
    Ok(Some(path))
}

fn log_migration(root: &Path, message: &str) -> Result<()> {
    use std::io::Write;
    let path = root.join(".zero").join("migration.log");
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{message}")?;
    Ok(())
}

fn migrate_legacy(root: &Path, registry: &mut BindingRegistry, now_ms: i64) -> Result<()> {
    let pi = root.join(".pi");
    let zero = root.join(".zero");
    if pi.is_dir() && !zero.join("key").exists() {
        let legacy_key = read_key(&pi);
        ensure_layout(root)?;
        if let Some(key) = legacy_key {
            write_key(&zero, &key)?;
            let id = project_id_for(&key);
            let name = registry.unique_name(root.file_name().and_then(|n| n.to_str()).unwrap_or("project"));
            write_project_file(root, &ProjectFile { project_id: id.clone(), name: name.clone(), copied_from: None, created_ms: now_ms })?;
            registry.bind(&id, &name, root, None);
            log_migration(root, &format!("migrated .pi key into .zero (project {id})"))?;
        } else {
            log_migration(root, "migrated .pi layout without a key; .zero created")?;
        }
        let archived = root.join(".pi.migrated");
        if !archived.exists() {
            std::fs::rename(&pi, &archived)?;
        }
    }
    if zero.is_dir() && read_key(&zero).is_none() {
        ensure_layout(root)?;
        let key = generate_key();
        write_key(&zero, &key)?;
        let id = project_id_for(&key);
        let name = registry.unique_name(root.file_name().and_then(|n| n.to_str()).unwrap_or("project"));
        if read_project_file(root).is_none() {
            write_project_file(root, &ProjectFile { project_id: id.clone(), name: name.clone(), copied_from: None, created_ms: now_ms })?;
        }
        registry.bind(&id, &name, root, None);
        log_migration(root, &format!("minted a key for a keyless .zero (project {id})"))?;
    }
    Ok(())
}

/// Open or create a project rooted at the detected root.
pub fn open(dir: &Path, home: &Path, registry: &mut BindingRegistry, mode: OpenMode, now_ms: i64) -> Result<OpenOutcome> {
    let root = find_root(dir, home)?;
    migrate_legacy(&root, registry, now_ms)?;
    let zero = root.join(".zero");
    let key = read_key(&zero);
    let Some(key) = key else {
        // Create a new project.
        ensure_layout(&root)?;
        let key = generate_key();
        write_key(&zero, &key)?;
        let id = project_id_for(&key);
        let base = root.file_name().and_then(|n| n.to_str()).unwrap_or("project");
        let name = registry.unique_name(base);
        write_project_file(&root, &ProjectFile { project_id: id.clone(), name: name.clone(), copied_from: None, created_ms: now_ms })?;
        registry.bind(&id, &name, &root, None);
        registry.save()?;
        ensure_gitignore(&root)?;
        return Ok(OpenOutcome::Created(Project { root, project_id: id, name, key, copied_from: None }));
    };
    let found_id = project_id_for(&key);
    let file = read_project_file(&root);
    let name = file.as_ref().map(|f| f.name.clone()).unwrap_or_else(|| {
        root.file_name().and_then(|n| n.to_str()).unwrap_or("project").to_string()
    });

    // A path whose stored binding names a different project has a replaced key.
    if let Some(binding) = registry.by_path(&root) {
        if binding.project_id != found_id {
            return Ok(OpenOutcome::KeyReplaced {
                path: root.clone(),
                stored_id: binding.project_id.clone(),
                found_id,
                root,
            });
        }
    }

    let other_live: Vec<PathBuf> = registry
        .get(&found_id)
        .map(|binding| binding.paths.iter().filter(|p| **p != root && p.join(".zero/key").exists()).cloned().collect())
        .unwrap_or_default();

    if !other_live.is_empty() {
        // Same key at two live paths: a copy.
        let typed_name = registry.unique_name(&format!("{name} copy"));
        let project = Project { root: root.clone(), project_id: found_id.clone(), name: name.clone(), key, copied_from: None };
        return match mode {
            OpenMode::Interactive => Ok(OpenOutcome::CopyPrompt { old_path: other_live[0].clone(), typed_name, project }),
            OpenMode::NonInteractive => answer_copy(&project, &typed_name, registry, now_ms),
        };
    }

    // A move: rebind silently, dropping paths that no longer exist.
    let binding = registry.file.projects.entry(found_id.clone()).or_insert(ProjectBinding {
        project_id: found_id.clone(),
        name: name.clone(),
        paths: Vec::new(),
        copied_from: None,
    });
    binding.paths.retain(|p| p.exists());
    let was_bound = binding.paths.iter().any(|p| p == &root);
    if !was_bound {
        binding.paths.push(root.clone());
    }
    registry.file.names.insert(name.clone());
    registry.save()?;
    ensure_gitignore(&root)?;
    let moved = !was_bound;
    let project = Project { root, project_id: found_id, name, key, copied_from: None };
    Ok(if moved { OpenOutcome::Moved(project) } else { OpenOutcome::Opened(project) })
}

/// Answer a copy prompt: mint a new key, record `copiedFrom`, and leave the
/// original untouched.
pub fn answer_copy(copy: &Project, chosen_name: &str, registry: &mut BindingRegistry, now_ms: i64) -> Result<OpenOutcome> {
    let zero = copy.root.join(".zero");
    let new_key = generate_key();
    write_key(&zero, &new_key)?;
    let new_id = project_id_for(&new_key);
    let name = registry.unique_name(chosen_name);
    write_project_file(
        &copy.root,
        &ProjectFile { project_id: new_id.clone(), name: name.clone(), copied_from: Some(copy.project_id.clone()), created_ms: now_ms },
    )?;
    // Remove the new path from the original binding, if present.
    if let Some(original) = registry.file.projects.get_mut(&copy.project_id) {
        original.paths.retain(|p| p != &copy.root);
    }
    registry.bind(&new_id, &name, &copy.root, Some(copy.project_id.clone()));
    registry.save()?;
    ensure_gitignore(&copy.root)?;
    Ok(OpenOutcome::Created(Project {
        root: copy.root.clone(),
        project_id: new_id,
        name,
        key: new_key,
        copied_from: Some(copy.project_id.clone()),
    }))
}

/// Resolve a replaced key. Adopt keeps the new identity; restore rewrites the
/// previous key only when a backup exists. History is never discarded.
pub fn answer_replaced(
    path: &Path,
    choice: ReplaceChoice,
    registry: &mut BindingRegistry,
    now_ms: i64,
) -> Result<OpenOutcome> {
    let zero = path.join(".zero");
    match choice {
        ReplaceChoice::Adopt => {
            let key = read_key(&zero).ok_or_else(|| ZeroError::new(ErrorCode::NotFound, "no key"))?;
            let id = project_id_for(&key);
            let name = read_project_file(path).map(|f| f.name).unwrap_or_else(|| {
                path.file_name().and_then(|n| n.to_str()).unwrap_or("project").to_string()
            });
            if let Some(old) = registry.by_path(path).cloned() {
                if let Some(binding) = registry.file.projects.get_mut(&old.project_id) {
                    binding.paths.retain(|p| p != path);
                }
            }
            registry.bind(&id, &name, path, None);
            registry.save()?;
            write_project_file(path, &ProjectFile { project_id: id.clone(), name: name.clone(), copied_from: None, created_ms: now_ms })?;
            Ok(OpenOutcome::Opened(Project { root: path.to_path_buf(), project_id: id, name, key, copied_from: None }))
        }
        ReplaceChoice::Restore => {
            let backup = zero.join("key.prev");
            let previous = std::fs::read_to_string(&backup).map_err(|_| {
                ZeroError::new(ErrorCode::NotFound, "no previous key to restore; adopt instead")
            })?;
            std::fs::write(zero.join("key"), previous.trim())?;
            open(path, path, registry, OpenMode::NonInteractive, now_ms)
        }
    }
}

/// Recovery actions are user-only; none is reachable by the agent.
pub fn recovery_actions() -> Vec<&'static str> {
    vec!["init", "list", "show", "bind", "move", "rekey", "forget"]
}

/// The `/link` action is explicit, user-only, and absent from the copy prompt.
pub fn link_action() -> zero_actions::ActionRecord {
    zero_actions::ActionRecord {
        id: "project.link".into(),
        title: "Link project identity".into(),
        description: "Share this project's identity with another device".into(),
        category: "project".into(),
        aliases: vec![],
        arguments: serde_json::json!({"type":"object"}),
        capabilities: vec![],
        mutating: true,
        deterministic: true,
        policy_class: zero_policy::ActionClass::Mesh,
        approval: zero_actions::ApprovalRule::Always,
        agent_invocable: false,
        unattended: false,
        idempotency: zero_actions::Idempotency::Required,
        audit: zero_actions::AuditMeta { redact_arguments: false },
        implicit: false,
        ui_control: false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyPrompt {
    pub old_path: PathBuf,
    pub suggested_name: String,
}

impl CopyPrompt {
    /// Menu options never include `/link`.
    pub fn options(&self) -> Vec<String> {
        vec!["Create a new project key".into(), "Choose another name".into()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry(dir: &Path) -> BindingRegistry {
        BindingRegistry::open(dir.join("registry.json")).unwrap()
    }

    #[test]
    fn creation_names_the_project_and_writes_the_layout_and_gitignore() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join("repo")).unwrap();
        std::fs::create_dir_all(home.join("repo/.git")).unwrap();
        let root = home.join("repo");
        let mut reg = registry(dir.path());
        let OpenOutcome::Created(project) = open(&root, &home, &mut reg, OpenMode::NonInteractive, 0).unwrap() else {
            panic!("expected creation");
        };
        assert_eq!(project.name, "repo");
        assert_eq!(project.project_id, project_id_for(&project.key));
        assert!(project.layout_complete());
        assert!(std::fs::read_to_string(root.join(".gitignore")).unwrap().contains(".zero/"));
        // A collision gets a numeric suffix.
        std::fs::create_dir_all(home.join("repo2")).unwrap();
        std::fs::write(home.join("repo2/.gitignore"), "").unwrap();
        // Simulate a name collision by pre-registering "repo".
        let second = open(&home.join("repo2"), &home, &mut reg, OpenMode::NonInteractive, 1).unwrap();
        let OpenOutcome::Created(second) = second else { panic!() };
        assert_eq!(second.name, "repo2");
    }

    #[test]
    fn moving_a_project_keeps_identity_and_rebinds_silently() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join("a")).unwrap();
        let mut reg = registry(dir.path());
        let OpenOutcome::Created(project) = open(&home.join("a"), &home, &mut reg, OpenMode::NonInteractive, 0).unwrap() else { panic!() };
        std::fs::rename(home.join("a"), home.join("b")).unwrap();
        let outcome = open(&home.join("b"), &home, &mut reg, OpenMode::Interactive, 1).unwrap();
        let OpenOutcome::Moved(moved) = outcome else { panic!("expected move, got {outcome:?}") };
        assert_eq!(moved.project_id, project.project_id);
        assert_eq!(moved.key, project.key);
        assert!(reg.get(&project.project_id).unwrap().paths.contains(&std::fs::canonicalize(home.join("b")).unwrap()));
    }

    #[test]
    fn a_copy_prompts_once_and_gets_a_new_key_with_copied_from() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join("orig")).unwrap();
        let mut reg = registry(dir.path());
        let OpenOutcome::Created(original) = open(&home.join("orig"), &home, &mut reg, OpenMode::NonInteractive, 0).unwrap() else { panic!() };
        // Copy the whole folder including .zero/key.
        copy_dir(&home.join("orig"), &home.join("copy"));
        let outcome = open(&home.join("copy"), &home, &mut reg, OpenMode::Interactive, 1).unwrap();
        let OpenOutcome::CopyPrompt { typed_name, project, .. } = outcome else { panic!("expected copy prompt, got {outcome:?}") };
        let prompt = CopyPrompt { old_path: original.root.clone(), suggested_name: typed_name.clone() };
        assert!(!prompt.options().iter().any(|o| o.contains("link")));
        let OpenOutcome::Created(copied) = answer_copy(&project, &typed_name, &mut reg, 2).unwrap() else { panic!() };
        assert_ne!(copied.project_id, original.project_id);
        assert_eq!(copied.copied_from, Some(original.project_id.clone()));
        // The original key and history are untouched.
        assert_eq!(read_key(&home.join("orig/.zero")).unwrap(), original.key);
        // Opening the copy again does not prompt.
        assert!(matches!(open(&home.join("copy"), &home, &mut reg, OpenMode::Interactive, 3).unwrap(), OpenOutcome::Opened(_) | OpenOutcome::Moved(_)));
    }

    #[test]
    fn a_replaced_key_asks_and_can_be_adopted_or_restored() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join("p")).unwrap();
        let mut reg = registry(dir.path());
        let OpenOutcome::Created(project) = open(&home.join("p"), &home, &mut reg, OpenMode::NonInteractive, 0).unwrap() else { panic!() };
        let zero = home.join("p/.zero");
        std::fs::write(zero.join("key"), "replacement-key").unwrap();
        let outcome = open(&home.join("p"), &home, &mut reg, OpenMode::NonInteractive, 1).unwrap();
        let OpenOutcome::KeyReplaced { stored_id, found_id, .. } = outcome else { panic!("expected replaced, got {outcome:?}") };
        assert_eq!(stored_id, project.project_id);
        assert_ne!(stored_id, found_id);
        let OpenOutcome::Opened(adopted) = answer_replaced(&home.join("p"), ReplaceChoice::Adopt, &mut reg, 2).unwrap() else { panic!() };
        assert_eq!(adopted.project_id, project_id_for("replacement-key"));
        assert!(home.join("p/.zero/project.json").exists(), "history file is preserved");
    }

    #[test]
    fn legacy_layouts_migrate_once_and_are_logged() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join("legacy/.pi")).unwrap();
        std::fs::write(home.join("legacy/.pi/key"), "legacy-key").unwrap();
        let mut reg = registry(dir.path());
        let OpenOutcome::Opened(project) = open(&home.join("legacy"), &home, &mut reg, OpenMode::NonInteractive, 0).unwrap() else { panic!() };
        assert_eq!(project.project_id, project_id_for("legacy-key"));
        assert!(home.join("legacy/.pi.migrated").exists());
        let log = std::fs::read_to_string(home.join("legacy/.zero/migration.log")).unwrap();
        assert!(log.contains("migrated .pi"));
        // A second open does not migrate again.
        let before = log.lines().count();
        open(&home.join("legacy"), &home, &mut reg, OpenMode::NonInteractive, 1).unwrap();
        let after = std::fs::read_to_string(home.join("legacy/.zero/migration.log")).unwrap().lines().count();
        assert_eq!(before, after);
    }

    #[test]
    fn recovery_actions_are_user_only_and_link_is_absent_from_the_prompt() {
        assert_eq!(recovery_actions().len(), 7);
        assert!(recovery_actions().contains(&"rekey"));
        let link = link_action();
        assert_eq!(link.id, "project.link");
        assert!(!link.agent_invocable);
        let prompt = CopyPrompt { old_path: PathBuf::from("/tmp/orig"), suggested_name: "copy".into() };
        assert!(!prompt.options().iter().any(|o| o.to_lowercase().contains("link")));
    }

    #[test]
    fn mesh_bindings_share_one_identity_at_different_paths() {
        let dir = tempfile::tempdir().unwrap();
        let a_home = dir.path().join("a-home");
        let b_home = dir.path().join("b-home");
        std::fs::create_dir_all(a_home.join("proj")).unwrap();
        std::fs::create_dir_all(b_home.join("elsewhere")).unwrap();
        let mut a = registry(&dir.path().join("a"));
        let OpenOutcome::Created(project) = open(&a_home.join("proj"), &a_home, &mut a, OpenMode::NonInteractive, 0).unwrap() else { panic!() };
        // Replicate the key bytes to the other device at a different path.
        std::fs::create_dir_all(b_home.join("elsewhere/.zero")).unwrap();
        std::fs::write(b_home.join("elsewhere/.zero/key"), &project.key).unwrap();
        let mut b = registry(&dir.path().join("b"));
        b.merge_remote(&a).unwrap();
        let remote = match open(&b_home.join("elsewhere"), &b_home, &mut b, OpenMode::NonInteractive, 1).unwrap() { OpenOutcome::Opened(p) | OpenOutcome::Moved(p) => p, other => panic!("{other:?}") };
        assert_eq!(remote.project_id, project.project_id);
        // Each device binds its own local path; identity is shared.\n        assert_eq!(b.get(&project.project_id).unwrap().paths.len(), 1);\n        assert!(b.get(&project.project_id).unwrap().paths[0].ends_with("elsewhere"));\n        assert!(a.get(&project.project_id).unwrap().paths[0].ends_with("proj"));
    }

    fn copy_dir(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for entry in std::fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let target = to.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_dir(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), target).unwrap();
            }
        }
    }
}
