//! Per-OS data, config, cache, and state paths from one table (FND-03).
//!
//! The table is normative: `docs/data-directories.md` is compared to
//! [`render_table`] by a test, and each platform resolves from the same function.

use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    Windows,
    MacOs,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathKind {
    Data,
    Config,
    Cache,
    State,
}

impl PathKind {
    pub const ALL: [PathKind; 4] = [PathKind::Data, PathKind::Config, PathKind::Cache, PathKind::State];
}

#[derive(Debug, Clone, Default)]
pub struct Env {
    pub local_app_data: Option<String>,
    pub app_data: Option<String>,
    pub home: Option<String>,
    pub xdg_data_home: Option<String>,
    pub xdg_config_home: Option<String>,
    pub xdg_cache_home: Option<String>,
    pub xdg_state_home: Option<String>,
}

impl Env {
    /// Read the real process environment.
    pub fn from_process() -> Self {
        let get = |k: &str| std::env::var(k).ok();
        Self {
            local_app_data: get("LOCALAPPDATA"),
            app_data: get("APPDATA"),
            home: get("HOME").or_else(|| get("USERPROFILE")),
            xdg_data_home: get("XDG_DATA_HOME"),
            xdg_config_home: get("XDG_CONFIG_HOME"),
            xdg_cache_home: get("XDG_CACHE_HOME"),
            xdg_state_home: get("XDG_STATE_HOME"),
        }
    }

    /// Deterministic environment for a platform, used by tests and docs.
    pub fn fixture_for(platform: Platform) -> Self {
        match platform {
            Platform::Windows => Env {
                local_app_data: Some(r"C:\Users\example\AppData\Local".into()),
                app_data: Some(r"C:\Users\example\AppData\Roaming".into()),
                home: Some(r"C:\Users\example".into()),
                ..Env::default()
            },
            Platform::MacOs => Env {
                home: Some("/Users/example".into()),
                ..Env::default()
            },
            Platform::Linux => Env {
                home: Some("/home/example".into()),
                ..Env::default()
            },
        }
    }
}

/// Which platform this build targets.
pub const fn current_platform() -> Platform {
    #[cfg(target_os = "windows")]
    {
        Platform::Windows
    }
    #[cfg(target_os = "macos")]
    {
        Platform::MacOs
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        Platform::Linux
    }
}

/// The single resolution function for all four kinds on all platforms.
///
/// Paths are built with the target platform's separator explicitly, never with
/// `PathBuf::join`, so the table renders identically on every host and the
/// generated documentation is stable.
pub fn resolve(platform: Platform, kind: PathKind, env: &Env) -> PathBuf {
    fn join(base: &str, parts: &[&str], separator: char) -> PathBuf {
        let mut out = base.trim_end_matches(['\\', '/']).to_string();
        for part in parts {
            out.push(separator);
            out.push_str(part);
        }
        PathBuf::from(out)
    }
    match platform {
        Platform::Windows => {
            let base = match kind {
                PathKind::Config => env.app_data.clone(),
                _ => env.local_app_data.clone(),
            }
            .or_else(|| env.home.clone())
            .unwrap_or_else(|| r"C:\Users\example".into());
            let leaf = match kind {
                PathKind::Data => "data",
                PathKind::Config => "config",
                PathKind::Cache => "cache",
                PathKind::State => "state",
            };
            join(&base, &["Zero", leaf], '\\')
        }
        Platform::MacOs => {
            let home = env.home.clone().unwrap_or_else(|| "/Users/example".into());
            match kind {
                PathKind::Data => join(&home, &["Library", "Application Support", "Zero", "data"], '/'),
                PathKind::Config => join(&home, &["Library", "Application Support", "Zero", "config"], '/'),
                PathKind::Cache => join(&home, &["Library", "Caches", "Zero"], '/'),
                PathKind::State => join(&home, &["Library", "Application Support", "Zero", "state"], '/'),
            }
        }
        Platform::Linux => {
            let home = env.home.clone().unwrap_or_else(|| "/home/example".into());
            let pick = |explicit: &Option<String>, fallback: &[&str]| match explicit {
                Some(v) if !v.is_empty() => join(v, &["zero"], '/'),
                _ => join(&home, fallback, '/'),
            };
            match kind {
                PathKind::Data => pick(&env.xdg_data_home, &[".local", "share", "zero"]),
                PathKind::Config => pick(&env.xdg_config_home, &[".config", "zero"]),
                PathKind::Cache => pick(&env.xdg_cache_home, &[".cache", "zero"]),
                PathKind::State => pick(&env.xdg_state_home, &[".local", "state", "zero"]),
            }
        }
    }
}

/// The normative table rendered as rows: platform, kind, path.
pub fn table_rows(env: &Env) -> Vec<(Platform, PathKind, PathBuf)> {
    let mut rows = Vec::new();
    for platform in [Platform::Windows, Platform::MacOs, Platform::Linux] {
        for kind in PathKind::ALL {
            rows.push((platform, kind, resolve(platform, kind, env)));
        }
    }
    rows
}

/// Markdown table body used by `docs/data-directories.md`.
pub fn render_table() -> String {
    let env = Env::fixture_for(Platform::Windows);
    let mac = Env::fixture_for(Platform::MacOs);
    let linux = Env::fixture_for(Platform::Linux);
    let mut out = String::from("| Platform | Kind | Path |\n|---|---|---|\n");
    for platform in [Platform::Windows, Platform::MacOs, Platform::Linux] {
        let e = match platform {
            Platform::Windows => &env,
            Platform::MacOs => &mac,
            Platform::Linux => &linux,
        };
        for kind in PathKind::ALL {
            out.push_str(&format!(
                "| {} | {} | `{}` |\n",
                platform_name(platform),
                kind_name(kind),
                resolve(platform, kind, e).display()
            ));
        }
    }
    out
}

fn platform_name(p: Platform) -> &'static str {
    match p {
        Platform::Windows => "Windows",
        Platform::MacOs => "macOS",
        Platform::Linux => "Linux",
    }
}

fn kind_name(k: PathKind) -> &'static str {
    match k {
        PathKind::Data => "data",
        PathKind::Config => "config",
        PathKind::Cache => "cache",
        PathKind::State => "state",
    }
}

/// Resolve for the current process.
pub fn current(kind: PathKind) -> PathBuf {
    resolve(current_platform(), kind, &Env::from_process())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_platform_resolves_every_kind() {
        let cases = [
            (Platform::Windows, PathKind::Data, r"C:\Users\example\AppData\Local\Zero\data"),
            (Platform::Windows, PathKind::Config, r"C:\Users\example\AppData\Roaming\Zero\config"),
            (Platform::Windows, PathKind::Cache, r"C:\Users\example\AppData\Local\Zero\cache"),
            (Platform::Windows, PathKind::State, r"C:\Users\example\AppData\Local\Zero\state"),
            (Platform::MacOs, PathKind::Data, "/Users/example/Library/Application Support/Zero/data"),
            (Platform::MacOs, PathKind::Config, "/Users/example/Library/Application Support/Zero/config"),
            (Platform::MacOs, PathKind::Cache, "/Users/example/Library/Caches/Zero"),
            (Platform::MacOs, PathKind::State, "/Users/example/Library/Application Support/Zero/state"),
            (Platform::Linux, PathKind::Data, "/home/example/.local/share/zero"),
            (Platform::Linux, PathKind::Config, "/home/example/.config/zero"),
            (Platform::Linux, PathKind::Cache, "/home/example/.cache/zero"),
            (Platform::Linux, PathKind::State, "/home/example/.local/state/zero"),
        ];
        for (platform, kind, expected) in cases {
            let env = Env::fixture_for(platform);
            assert_eq!(resolve(platform, kind, &env), PathBuf::from(expected), "{platform:?}/{kind:?}");
        }
    }

    #[test]
    fn xdg_overrides_win_on_linux() {
        let env = Env {
            home: Some("/home/example".into()),
            xdg_data_home: Some("/xdg/data".into()),
            xdg_config_home: Some("/xdg/config".into()),
            xdg_cache_home: Some("/xdg/cache".into()),
            xdg_state_home: Some("/xdg/state".into()),
            ..Env::default()
        };
        assert_eq!(resolve(Platform::Linux, PathKind::Data, &env), PathBuf::from("/xdg/data/zero"));
        assert_eq!(resolve(Platform::Linux, PathKind::Config, &env), PathBuf::from("/xdg/config/zero"));
        assert_eq!(resolve(Platform::Linux, PathKind::Cache, &env), PathBuf::from("/xdg/cache/zero"));
        assert_eq!(resolve(Platform::Linux, PathKind::State, &env), PathBuf::from("/xdg/state/zero"));
    }

    #[test]
    fn docs_table_matches_the_code() {
        let doc = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/data-directories.md"),
        )
        .expect("docs/data-directories.md must exist");
        let rendered = render_table();
        for line in rendered.lines().skip(2) {
            assert!(doc.contains(line), "docs table is missing row: {line}");
        }
        let rows = rendered.lines().filter(|l| l.starts_with("| ") && !l.contains("Platform")).count();
        assert_eq!(rows, 12, "all four kinds on all three platforms");
    }

    #[test]
    fn current_platform_maps_a_real_home() {
        let env = Env::from_process();
        let p = resolve(current_platform(), PathKind::Data, &env);
        assert!(p.is_absolute(), "resolved path must be absolute: {p:?}");
    }
}
