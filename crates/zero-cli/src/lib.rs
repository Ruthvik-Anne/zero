//! `zero-cli` — see `architecture.md` section 5 for the module contract.
//!
//! The library target exposes the release packaging surface (T-INST-01), the
//! signed atomic update surface (T-INST-04), the service unit and lifecycle
//! surface (T-INST-05), the kernel bootstrap surface (T-INST-06), the uninstall
//! surface (T-INST-07), and the Unix (T-INST-03) and Windows (T-INST-02)
//! installer script seams so the installer, the update path, release tooling,
//! and uninstall share one implementation of the installation layout.

pub mod bootstrap;
pub mod packaging;
pub mod service;
pub mod uninstall;
pub mod unix_install;
pub mod update;
pub mod windows_install;

pub use bootstrap::{
    bootstrap, bootstrap_with_cache, component_file_name, default_plan, probe_kernel, BinDirProbe,
    BootstrapComponent, BootstrapEnv, BootstrapError, BootstrapErrorKind, BootstrapFailure,
    BootstrapKind, BootstrapPlan, BootstrapReport, BootstrapResult, Cache, Downloader, FsCache,
    KernelProbe, KernelStatus, BOOTSTRAP_SCHEMA_VERSION, DEFAULT_CACHE_DIR,
    MAX_BOOTSTRAP_COMPONENTS, MAX_BOOTSTRAP_FIELD_BYTES, MAX_CACHE_DIR_BYTES, MAX_COMPONENT_BYTES,
    MAX_URL_BYTES, PLACEHOLDER_MANIFEST_VERSION, PLACEHOLDER_SHA256,
};
pub use packaging::{
    artifact_name, embedded_public_key, executable_name, load_signed, save_signed,
    sbom_from_cargo_lock, sign_manifest, verify_embedded, verify_sbom, verify_signed, Artifact,
    PackagingError, PackagingErrorKind, ReleaseManifest, SbomComponent, SignedRelease, CHANNELS,
    EMBEDDED_KEY_B64, LICENCE_UNKNOWN, MANIFEST_SCHEMA_VERSION, MAX_ARTIFACTS, MAX_FIELD_BYTES,
    MAX_MANIFEST_BYTES, MAX_SBOM_COMPONENTS, SUPPORTED_TARGETS,
};
pub use service::{
    default_unit_path, lifecycle, manage, platform_for_current_os, platform_for_os, render_unit,
    unit_file_name, LifecycleReport, RestartPolicy, ServiceError, ServiceErrorKind, ServiceManager,
    ServicePlatform, ServiceReport, ServiceResult, ServiceSpec, ServiceStatus, LAUNCHD_LABEL,
    LAUNCHD_PLIST, MAX_SERVICE_ARGS, MAX_SERVICE_ARG_BYTES, MAX_SERVICE_ENV_ENTRIES,
    MAX_SERVICE_ENV_NAME_BYTES, MAX_SERVICE_ENV_VALUE_BYTES, MAX_SERVICE_PATH_BYTES,
    MAX_SERVICE_USER_BYTES, SERVICE_DISPLAY_NAME, SERVICE_NAME, SYSTEMD_UNIT, WINDOWS_CONFIG,
};
pub use uninstall::{
    plan_uninstall, preview, request_confirmation, uninstall, Confirmation, UninstallPlan,
    UninstallReport, UninstallScope, CONFIRMATION_TTL_MS, MAX_PATH_ENTRY_BYTES,
    MAX_SERVICE_NAME_BYTES, MAX_UNINSTALL_PATH_BYTES,
};
pub use unix_install::{
    install_command, script_path, validate_script, UnixInstallError, UnixInstallErrorKind,
    REQUIRED_FLAGS, SCRIPT_RELATIVE_PATH,
};
pub use update::{
    apply_update, apply_update_with, compare_versions, current_version, rollback, verify_update,
    verify_update_with_key, ApplyOptions, DiskProbe, HealthCheck, NoHealthCheck, NoSwapHook,
    RollbackState, SwapHook, UnrestrictedDisk, UpdateArtifact, UpdateError, UpdateErrorKind,
    UpdatePayload, UpdatePolicy, UpdateReport, VerifiedUpdate, BACKUP_DIR_PREFIX, BACKUP_MANIFEST,
    DISK_HEADROOM_BYTES, MAX_BACKUP_MANIFEST_BYTES, MAX_PATH_BYTES, MAX_PATH_DEPTH,
    MAX_UPDATE_BYTES, MAX_UPDATE_FILES, MAX_UPDATE_FILE_BYTES, STAGING_MARKER,
    UPDATE_SCHEMA_VERSION, VERSION_FILE,
};
pub use windows_install::{
    install_command as windows_install_command, script_path as windows_script_path,
    validate_script as windows_validate_script, WindowsInstallError, WindowsInstallErrorKind,
    REQUIRED_PARAMETERS as WINDOWS_REQUIRED_PARAMETERS,
    SCRIPT_RELATIVE_PATH as WINDOWS_SCRIPT_RELATIVE_PATH,
};
