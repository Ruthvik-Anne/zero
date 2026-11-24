//! Migration framework (FND-04): every store is versioned, a backup precedes a
//! migration, and a downgrade is refused rather than attempted.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VersionedDoc {
    pub version: u32,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Copy)]
pub struct Step {
    pub from: u32,
    pub to: u32,
    pub name: &'static str,
}

/// One migration step with its transform. Applied in ascending `from` order.
pub struct Migration {
    pub step: Step,
    pub apply: fn(&mut serde_json::Value) -> Result<()>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    pub from: u32,
    pub to: u32,
    pub backup: Option<PathBuf>,
    pub applied: Vec<String>,
}

/// Migrate a JSON document store to `target`.
///
/// - `current > target` is refused as a downgrade.
/// - Before any change, the file is copied to `<name>.v<current>.backup`.
/// - Each step must chain exactly from the previous version, otherwise the
///   registry is inconsistent and the call fails before touching the file.
pub fn migrate_file(
    path: impl AsRef<Path>,
    target: u32,
    steps: &[Migration],
) -> Result<MigrationReport> {
    let path = path.as_ref().to_path_buf();
    let text = std::fs::read_to_string(&path)?;
    let mut doc: VersionedDoc = serde_json::from_str(&text)?;
    let from = doc.version;

    if from == target {
        return Ok(MigrationReport { from, to: target, backup: None, applied: Vec::new() });
    }
    if from > target {
        return Err(ZeroError::new(
            ErrorCode::SchemaVersion,
            format!(
                "{} is version {from}; this build targets {target} and refuses to downgrade",
                path.display()
            ),
        ));
    }

    // Validate the chain before writing anything.
    let mut chain = Vec::new();
    let mut cursor = from;
    while cursor < target {
        let step = steps.iter().find(|s| s.step.from == cursor).ok_or_else(|| {
            ZeroError::new(
                ErrorCode::MigrationFailed,
                format!("no migration step from version {cursor}"),
            )
        })?;
        if step.step.to != cursor + 1 {
            return Err(ZeroError::new(
                ErrorCode::MigrationFailed,
                format!("step {} does not advance by one", step.step.name),
            ));
        }
        chain.push((step.step, step.apply));
        cursor = step.step.to;
    }

    let backup = path.with_file_name(format!(
        "{}.v{from}.backup",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("store")
    ));
    std::fs::copy(&path, &backup)?;
    let backup_file = std::fs::OpenOptions::new().write(true).open(&backup)?;
    backup_file.sync_all()?;

    let mut applied = Vec::new();
    for (step, apply) in chain {
        apply(&mut doc.payload)?;
        doc.version = step.to;
        // Write the intermediate state atomically so a crash leaves a valid
        // earlier version, never a half-migrated one.
        write_atomic(&path, &serde_json::to_vec_pretty(&doc)?)?;
        applied.push(step.name.to_string());
    }

    Ok(MigrationReport { from, to: doc.version, backup: Some(backup), applied })
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Load a versioned document without migrating.
pub fn load(path: impl AsRef<Path>) -> Result<VersionedDoc> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v1_to_v2(payload: &mut serde_json::Value) -> Result<()> {
        // rename "name" -> "title"
        let obj = payload.as_object_mut().expect("object");
        if let Some(v) = obj.remove("name") {
            obj.insert("title".into(), v);
        }
        Ok(())
    }

    fn v2_to_v3(payload: &mut serde_json::Value) -> Result<()> {
        payload.as_object_mut().expect("object").insert("schema".into(), "current".into());
        Ok(())
    }

    fn steps() -> Vec<Migration> {
        vec![
            Migration { step: Step { from: 1, to: 2, name: "rename-name" }, apply: v1_to_v2 },
            Migration { step: Step { from: 2, to: 3, name: "add-schema" }, apply: v2_to_v3 },
        ]
    }

    fn fixture(version: u32) -> VersionedDoc {
        match version {
            1 => VersionedDoc { version: 1, payload: serde_json::json!({"name":"alpha","n":1}) },
            2 => VersionedDoc { version: 2, payload: serde_json::json!({"title":"alpha","n":1}) },
            3 => VersionedDoc {
                version: 3,
                payload: serde_json::json!({"title":"alpha","n":1,"schema":"current"}),
            },
            _ => unimplemented!(),
        }
    }

    #[test]
    fn fixtures_from_every_prior_version_migrate_and_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        for from in 1..=3u32 {
            let path = dir.path().join(format!("store-{from}.json"));
            std::fs::write(&path, serde_json::to_vec_pretty(&fixture(from)).unwrap()).unwrap();
            let report = migrate_file(&path, 3, &steps()).unwrap();
            assert_eq!(report.from, from);
            assert_eq!(report.to, 3);
            let migrated = load(&path).unwrap();
            assert_eq!(migrated, fixture(3), "v{from} must round-trip to the canonical v3 fixture");
            if from < 3 {
                let backup = report.backup.expect("backup before migrate");
                let original = load(&backup).unwrap();
                assert_eq!(original, fixture(from), "backup must hold the original bytes");
            }
        }
    }

    #[test]
    fn downgrade_is_refused_and_the_file_is_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.json");
        let before = serde_json::to_vec_pretty(&fixture(3)).unwrap();
        std::fs::write(&path, &before).unwrap();
        let err = migrate_file(&path, 2, &steps()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::SchemaVersion);
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn missing_step_fails_before_writing_or_backing_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.json");
        let before = serde_json::to_vec_pretty(&fixture(1)).unwrap();
        std::fs::write(&path, &before).unwrap();
        let err = migrate_file(&path, 3, &steps()[1..]).unwrap_err();
        assert_eq!(err.code(), ErrorCode::MigrationFailed);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(std::fs::read_dir(dir.path()).unwrap().all(|e| {
            !e.unwrap().file_name().to_string_lossy().contains("backup")
        }));
    }

    #[test]
    fn same_version_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&fixture(2)).unwrap()).unwrap();
        let report = migrate_file(&path, 2, &steps()).unwrap();
        assert!(report.backup.is_none());
        assert!(report.applied.is_empty());
    }
}
