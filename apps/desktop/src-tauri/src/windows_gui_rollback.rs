//! Retain version-bound signed Windows installers and a private finite readiness
//! receipt. Existing installations have no predecessor signature envelope, so
//! they get explicit repair guidance rather than an unverified automatic downgrade.
#![cfg_attr(not(windows), allow(dead_code))]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::Manager;
const INVALID: &str = "Не удалось проверить восстановление Windows. Профиль не изменён; используйте подписанный установщик foxVPN.";
const MAX_INSTALLER: usize = 256 * 1024 * 1024;
const DEADLINE_SECONDS: u64 = 270;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Prepared,
    Waiting,
    Ready,
    Failed,
    Acknowledged,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Package {
    schema: u8,
    version: String,
    signature: String,
    sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: u8,
    id: String,
    prior_version: String,
    version: String,
    target: PathBuf,
    approved: bool,
    prior_cached: bool,
    prior_sha256: Option<String>,
    sha256: String,
    phase: Phase,
    created: u64,
    deadline: u64,
}
#[derive(Clone, Serialize)]
pub struct Status {
    pub pending: bool,
    pub restored: bool,
    pub failed: bool,
    pub prior_version: Option<String>,
    pub recovery_id: Option<String>,
    pub guidance: Option<String>,
}
impl Status {
    fn empty() -> Self {
        Self {
            pending: false,
            restored: false,
            failed: false,
            prior_version: None,
            recovery_id: None,
            guidance: None,
        }
    }
}
pub struct Prepared {
    root: PathBuf,
    id: String,
    _lock: File,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn version(value: &str) -> Result<semver::Version, String> {
    let v = semver::Version::parse(value).map_err(|_| INVALID)?;
    if !v.pre.is_empty() || !v.build.is_empty() || v.to_string() != value {
        return Err(INVALID.into());
    }
    Ok(v)
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(crate) fn verify_package(
    bytes: &[u8],
    signature: &str,
    expected_version: &str,
) -> Result<(), String> {
    use base64::Engine;
    version(expected_version)?;
    if bytes.len() < 64
        || bytes.len() > MAX_INSTALLER
        || !bytes.starts_with(b"MZ")
        || signature.len() > 4096
    {
        return Err(INVALID.into());
    }
    let config: serde_json::Value =
        serde_json::from_str(include_str!("../tauri.windows.conf.json")).map_err(|_| INVALID)?;
    if config["plugins"]["updater"]["requireSignedVersion"] != true {
        return Err(INVALID.into());
    }
    let decode = |s: &str| -> Result<String, String> {
        String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(s.trim())
                .map_err(|_| INVALID)?,
        )
        .map_err(|_| INVALID.into())
    };
    let key = minisign_verify::PublicKey::decode(&decode(
        config["plugins"]["updater"]["pubkey"]
            .as_str()
            .ok_or(INVALID)?,
    )?)
    .map_err(|_| INVALID)?;
    let sig = minisign_verify::Signature::decode(&decode(signature)?).map_err(|_| INVALID)?;
    key.verify(bytes, &sig, false).map_err(|_| INVALID)?;
    let fields: Vec<_> = sig
        .trusted_comment()
        .split('\t')
        .filter_map(|v| v.strip_prefix("version:"))
        .collect();
    let filenames: Vec<_> = sig
        .trusted_comment()
        .split('\t')
        .filter_map(|v| v.strip_prefix("file:"))
        .collect();
    let expected_file = format!("foxVPN_{expected_version}_x64-setup.exe");
    if fields.as_slice() != [expected_version] || filenames.as_slice() != [expected_file.as_str()] {
        return Err(INVALID.into());
    }
    Ok(())
}
fn root(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_config_dir()
        .map_err(|_| INVALID)?
        .join("windows-gui-recovery"))
}
fn plain(path: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|_| INVALID)?;
    if meta.file_type().is_symlink() {
        return Err(INVALID.into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        for p in path.ancestors() {
            if fs::symlink_metadata(p)
                .map_err(|_| INVALID)?
                .file_attributes()
                & 0x400
                != 0
            {
                return Err(INVALID.into());
            }
        }
    }
    Ok(())
}
fn directory(path: &Path) -> Result<(), String> {
    #[cfg_attr(not(windows), allow(unused_variables))]
    let created = !path.exists();
    if created {
        fs::create_dir(path).map_err(|_| INVALID)?;
    }
    plain(path)?;
    if !fs::metadata(path).map_err(|_| INVALID)?.is_dir() {
        return Err(INVALID.into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let m = fs::metadata(path).map_err(|_| INVALID)?;
        if m.uid() != unsafe { libc::getuid() } {
            return Err(INVALID.into());
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| INVALID)?;
    }
    #[cfg(windows)]
    {
        if created {
            private_windows::initialize(path)?;
        } else {
            private_windows::protect(path)?;
        }
    }
    Ok(())
}
fn read_bytes(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    plain(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1).custom_flags(0x00200000);
        private_windows::check(path)?;
    }
    let file = options.open(path).map_err(|_| INVALID)?;
    let meta = file.metadata().map_err(|_| INVALID)?;
    if !meta.is_file() || meta.len() > maximum as u64 {
        return Err(INVALID.into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != unsafe { libc::getuid() } || meta.mode() & 0o077 != 0 {
            return Err(INVALID.into());
        }
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| INVALID)?;
    if bytes.len() > maximum {
        return Err(INVALID.into());
    }
    Ok(bytes)
}
fn atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    directory(path.parent().ok_or(INVALID)?)?;
    if path.exists() {
        plain(path)?;
    }
    let temp = path.with_file_name(format!("write-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(&temp).map_err(|_| INVALID)?;
        #[cfg(windows)]
        {
            private_windows::initialize(&temp)?;
        }
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| INVALID)?;
        drop(file);
        #[cfg(windows)]
        {
            private_windows::replace(&temp, path)?;
        }
        #[cfg(not(windows))]
        {
            fs::rename(&temp, path).map_err(|_| INVALID)?;
            File::open(path.parent().ok_or(INVALID)?)
                .and_then(|f| f.sync_all())
                .map_err(|_| INVALID)?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
fn lock(root: &Path) -> Result<File, String> {
    directory(root)?;
    let path = root.join("operation.lock");
    #[cfg_attr(not(windows), allow(unused_variables))]
    let created = !path.exists();
    if !created {
        plain(&path)?;
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(3).custom_flags(0x00200000);
    }
    let file = options.open(&path).map_err(|_| INVALID)?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        if created {
            private_windows::initialize(&path)?;
        } else {
            private_windows::check(&path)?;
        }
        let mut operation = windows_sys::Win32::System::IO::OVERLAPPED::default();
        if unsafe {
            windows_sys::Win32::Storage::FileSystem::LockFileEx(
                file.as_raw_handle(),
                3,
                0,
                1,
                0,
                &mut operation,
            )
        } == 0
        {
            return Err("Восстановлением Windows управляет другое окно foxVPN.".into());
        }
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("Восстановлением Windows управляет другое окно foxVPN.".into());
        }
    }
    Ok(file)
}
fn package_dir(root: &Path, v: &str) -> Result<PathBuf, String> {
    version(v)?;
    Ok(root.join(format!("v{v}")))
}
fn cache(root: &Path, bytes: &[u8], signature: &str, v: &str) -> Result<String, String> {
    verify_package(bytes, signature, v)?;
    directory(root)?;
    let dir = package_dir(root, v)?;
    if !dir.exists() {
        let entries = fs::read_dir(root)
            .map_err(|_| INVALID)?
            .take(17)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| INVALID)?;
        if entries.len() > 16 {
            return Err("Каталог установщиков Windows требует ручной проверки.".into());
        }
        let mut count = 0;
        for entry in entries {
            if entry.file_type().map_err(|_| INVALID)?.is_dir() {
                count += 1;
            }
        }
        if count >= 2 {
            return Err("Сохранены незавершённые установщики Windows. Завершите ремонт перед новым обновлением.".into());
        }
    }
    directory(&dir)?;
    let sha256 = digest(bytes);
    if dir.join("package.json").exists() {
        let existing = load_package(root, v)?;
        if existing.sha256 != sha256 || existing.signature != signature {
            return Err(INVALID.into());
        }
        return Ok(sha256);
    }
    let package = Package {
        schema: 1,
        version: v.into(),
        signature: signature.into(),
        sha256: sha256.clone(),
    };
    atomic(&dir.join("installer.exe"), bytes)?;
    atomic(
        &dir.join("package.json"),
        &serde_json::to_vec(&package).map_err(|_| INVALID)?,
    )?;
    Ok(sha256)
}
fn remove_known_package(root: &Path, v: &str) -> Result<(), String> {
    let dir = package_dir(root, v)?;
    if !dir.exists() {
        return Ok(());
    }
    plain(&dir)?;
    for name in ["installer.exe", "package.json"] {
        let path = dir.join(name);
        if path.exists() {
            plain(&path)?;
            fs::remove_file(&path).map_err(|_| INVALID)?;
        }
    }
    // Unexpected files are preserved and cause an explicit error, never recursive removal.
    fs::remove_dir(&dir).map_err(|_| INVALID.into())
}
fn load_package(root: &Path, v: &str) -> Result<Package, String> {
    let dir = package_dir(root, v)?;
    plain(&dir)?;
    let package: Package = serde_json::from_slice(&read_bytes(&dir.join("package.json"), 8192)?)
        .map_err(|_| INVALID)?;
    let bytes = read_bytes(&dir.join("installer.exe"), MAX_INSTALLER)?;
    if package.schema != 1 || package.version != v || digest(&bytes) != package.sha256 {
        return Err(INVALID.into());
    }
    verify_package(&bytes, &package.signature, v)?;
    Ok(package)
}
fn validate(r: &Receipt) -> Result<(), String> {
    let hash = |s: &str| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    };
    if r.schema != 1
        || uuid::Uuid::parse_str(&r.id).is_err()
        || version(&r.prior_version)? >= version(&r.version)?
        || !r.target.is_absolute()
        || r.target
            .file_name()
            .is_none_or(|s| s != "smart-vpn-desktop.exe")
        || !hash(&r.sha256)
        || r.prior_cached != r.prior_sha256.is_some()
        || r.prior_sha256.as_ref().is_some_and(|h| !hash(h))
        || r.created > now() + 5
        || r.deadline < r.created
        || r.deadline > r.created.saturating_add(DEADLINE_SECONDS)
    {
        return Err(INVALID.into());
    }
    Ok(())
}
fn read_receipt(root: &Path) -> Result<Option<Receipt>, String> {
    let path = root.join("receipt.json");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(INVALID.into()),
        Ok(_) => {}
    }
    let r: Receipt = serde_json::from_slice(&read_bytes(&path, 16384)?).map_err(|_| INVALID)?;
    validate(&r)?;
    Ok(Some(r))
}
fn write_receipt(root: &Path, receipt: &Receipt) -> Result<(), String> {
    validate(receipt)?;
    let bytes = serde_json::to_vec(receipt).map_err(|_| INVALID)?;
    if bytes.len() > 16384 {
        return Err(INVALID.into());
    }
    atomic(&root.join("receipt.json"), &bytes)
}
fn ensure_target(r: &Receipt, target: &Path) -> Result<(), String> {
    if !r
        .target
        .to_string_lossy()
        .eq_ignore_ascii_case(&target.to_string_lossy())
    {
        return Err(INVALID.into());
    }
    plain(target)
}
fn guidance(r: &Receipt) -> String {
    if r.prior_cached && r.approved {
        format!("Предыдущий установщик foxVPN {} сохранён с исходной подписью. Автоматический запуск старой версии отключён до проверки Windows. Для ремонта используйте подписанный установщик {} и сохраните профиль; повторное подключение VPN требует вашего действия.", r.prior_version, r.version)
    } else {
        format!("Автоматический возврат Windows недоступен: исходный подписанный установщик предыдущей версии {} не сохранён или согласие не дано. Для ремонта повторно установите подписанную foxVPN {} из официального выпуска. Не удаляйте пользовательский профиль.", r.prior_version, r.version)
    }
}
fn prepare_at(
    root: &Path,
    target: &Path,
    current: &str,
    bytes: &[u8],
    signature: &str,
    next: &str,
    approved: bool,
) -> Result<Prepared, String> {
    if version(current)? >= version(next)? {
        return Err(INVALID.into());
    }
    let operation_lock = lock(root)?;
    plain(target)?;
    if let Some(r) = read_receipt(root)? {
        ensure_target(&r, target)?;
        if matches!(r.phase, Phase::Prepared | Phase::Waiting | Phase::Failed) {
            return Err("Завершите восстановление предыдущего обновления Windows.".into());
        }
        if current == r.version {
            remove_known_package(root, &r.prior_version)?;
        } else if current == r.prior_version && r.phase == Phase::Acknowledged {
            remove_known_package(root, &r.version)?;
        } else {
            return Err(INVALID.into());
        }
    }
    let prior = if package_dir(root, current)?.join("package.json").exists() {
        Some(load_package(root, current)?)
    } else {
        None
    };
    let sha256 = cache(root, bytes, signature, next)?;
    let created = now();
    let r = Receipt {
        schema: 1,
        id: uuid::Uuid::new_v4().to_string(),
        prior_version: current.into(),
        version: next.into(),
        target: target.to_owned(),
        approved,
        prior_cached: prior.is_some(),
        prior_sha256: prior.map(|p| p.sha256),
        sha256,
        phase: Phase::Prepared,
        created,
        deadline: created + DEADLINE_SECONDS,
    };
    write_receipt(root, &r)?;
    Ok(Prepared {
        root: root.to_owned(),
        id: r.id,
        _lock: operation_lock,
    })
}
pub fn prepare(
    app: &tauri::AppHandle,
    bytes: &[u8],
    signature: &str,
    next: &str,
    approved: bool,
) -> Result<Prepared, String> {
    prepare_at(
        &root(app)?,
        &std::env::current_exe().map_err(|_| INVALID)?,
        &app.package_info().version.to_string(),
        bytes,
        signature,
        next,
        approved,
    )
}
impl Prepared {
    pub fn arm(&self) -> Result<(), String> {
        let mut r = read_receipt(&self.root)?.ok_or(INVALID)?;
        if r.id != self.id || r.phase != Phase::Prepared {
            return Err(INVALID.into());
        }
        r.phase = Phase::Waiting;
        write_receipt(&self.root, &r)
    }
    pub fn abort(&self) {
        if let Ok(Some(mut r)) = read_receipt(&self.root) {
            if r.id == self.id && matches!(r.phase, Phase::Prepared | Phase::Waiting) {
                r.phase = Phase::Failed;
                let _ = write_receipt(&self.root, &r);
            }
        }
    }
}
fn status_at(root: &Path, target: &Path, current: &str, startup: bool) -> Result<Status, String> {
    let Some(mut r) = read_receipt(root)? else {
        return Ok(Status::empty());
    };
    ensure_target(&r, target)?;
    if current != r.version && current != r.prior_version {
        return Err(INVALID.into());
    }
    if matches!(r.phase, Phase::Prepared | Phase::Waiting)
        && (now() > r.deadline || (startup && current == r.prior_version))
    {
        r.phase = Phase::Failed;
        write_receipt(root, &r)?;
    }
    if r.phase == Phase::Failed && r.prior_cached {
        let prior = load_package(root, &r.prior_version)?;
        if r.prior_sha256.as_deref() != Some(&prior.sha256) {
            return Err(INVALID.into());
        }
    }
    Ok(Status {
        pending: matches!(r.phase, Phase::Prepared | Phase::Waiting),
        restored: false,
        failed: r.phase == Phase::Failed,
        prior_version: Some(r.prior_version.clone()),
        recovery_id: Some(r.id.clone()),
        guidance: if r.phase == Phase::Failed {
            Some(guidance(&r))
        } else {
            None
        },
    })
}
pub fn status(app: &tauri::AppHandle) -> Result<Status, String> {
    let root = root(app)?;
    let _lock = lock(&root)?;
    status_at(
        &root,
        &std::env::current_exe().map_err(|_| INVALID)?,
        &app.package_info().version.to_string(),
        false,
    )
}
pub fn startup(app: &tauri::AppHandle) -> Result<Status, String> {
    let root = root(app)?;
    let _lock = lock(&root)?;
    status_at(
        &root,
        &std::env::current_exe().map_err(|_| INVALID)?,
        &app.package_info().version.to_string(),
        true,
    )
}
pub fn confirm_app_readiness(app: &tauri::AppHandle) -> Result<(), String> {
    let root = root(app)?;
    let _lock = lock(&root)?;
    let Some(mut r) = read_receipt(&root)? else {
        return Ok(());
    };
    ensure_target(&r, &std::env::current_exe().map_err(|_| INVALID)?)?;
    if matches!(r.phase, Phase::Prepared | Phase::Waiting)
        && app.package_info().version.to_string() == r.version
        && now() <= r.deadline
    {
        let p = load_package(&root, &r.version)?;
        if p.sha256 != r.sha256 {
            return Err(INVALID.into());
        }
        r.phase = Phase::Ready;
        write_receipt(&root, &r)?;
    }
    Ok(())
}
pub fn acknowledge(app: &tauri::AppHandle, id: &str, approved: bool) -> Result<(), String> {
    if !approved {
        return Err("Продолжение после ремонта Windows требует вашего согласия.".into());
    }
    let root = root(app)?;
    let _lock = lock(&root)?;
    let mut r = read_receipt(&root)?.ok_or(INVALID)?;
    ensure_target(&r, &std::env::current_exe().map_err(|_| INVALID)?)?;
    let current = app.package_info().version.to_string();
    if r.id != id
        || !matches!(r.phase, Phase::Failed)
        || (current != r.version && current != r.prior_version)
    {
        return Err(INVALID.into());
    }
    r.phase = Phase::Acknowledged;
    write_receipt(&root, &r)
}
#[cfg(windows)]
#[path = "windows_gui_private.rs"]
mod private_windows;

#[cfg(test)]
mod tests {
    use super::*;
    fn receipt(target: PathBuf) -> Receipt {
        Receipt {
            schema: 1,
            id: uuid::Uuid::new_v4().to_string(),
            prior_version: "0.1.25".into(),
            version: "0.1.26".into(),
            target,
            approved: false,
            prior_cached: false,
            prior_sha256: None,
            sha256: "a".repeat(64),
            phase: Phase::Waiting,
            created: now(),
            deadline: now() + DEADLINE_SECONDS,
        }
    }
    #[test]
    fn expired_readiness_gives_repair_guidance_and_never_reports_rollback() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("smart-vpn-desktop.exe");
        fs::write(&target, b"public fixture").unwrap();
        let root = temp.path().join("recovery");
        directory(&root).unwrap();
        let mut r = receipt(target.clone());
        r.created = now() - DEADLINE_SECONDS - 1;
        r.deadline = now() - 1;
        write_receipt(&root, &r).unwrap();
        let result = status_at(&root, &target, "0.1.26", true).unwrap();
        assert!(result.failed);
        assert!(!result.pending && !result.restored);
        assert!(result.guidance.unwrap().contains("не сохранён"));
        assert_eq!(fs::read(target).unwrap(), b"public fixture");
    }
    #[test]
    fn receipt_rejects_target_change_unbounded_deadline_and_newer_predecessor() {
        let mut r = receipt(std::env::temp_dir().join("smart-vpn-desktop.exe"));
        r.prior_version = "0.1.27".into();
        assert!(validate(&r).is_err());
        r.prior_version = "0.1.25".into();
        r.deadline = r.created + DEADLINE_SECONDS + 1;
        assert!(validate(&r).is_err());
        r.deadline = r.created + DEADLINE_SECONDS;
        r.target = std::env::temp_dir().join("cmd.exe");
        assert!(validate(&r).is_err());
    }
    #[test]
    fn store_rejects_symlinked_receipts_and_parallel_owners() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("recovery");
        let held = lock(&root).unwrap();
        assert!(lock(&root).is_err());
        drop(held);
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/passwd", root.join("receipt.json")).unwrap();
            assert!(read_receipt(&root).is_err());
        }
    }
    #[test]
    #[ignore = "Requires an original signed Windows release installer"]
    fn signed_cache_retains_original_envelope_and_rejects_payload_version_tampering() {
        let artifact =
            std::env::var("FOXVPN_TEST_WINDOWS_UPDATE_ARTIFACT").expect("signed artifact path");
        let v =
            std::env::var("FOXVPN_TEST_WINDOWS_UPDATE_VERSION").expect("signed artifact version");
        let bytes = fs::read(&artifact).unwrap();
        let signature = fs::read_to_string(format!("{artifact}.sig")).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("recovery");
        let target = temp.path().join("smart-vpn-desktop.exe");
        fs::write(&target, b"unchanged GUI fixture").unwrap();
        let profile = temp.path().join("profile.enc");
        fs::write(&profile, b"unchanged encrypted profile fixture").unwrap();
        let current = if v == "0.1.26" { "0.1.25" } else { "0.1.0" };
        let prepared = prepare_at(&root, &target, current, &bytes, &signature, &v, true).unwrap();
        let receipt = read_receipt(&root).unwrap().unwrap();
        assert!(!receipt.prior_cached);
        assert!(receipt.prior_sha256.is_none());
        prepared.arm().unwrap();
        drop(prepared);
        let waiting = status_at(&root, &target, &v, true).unwrap();
        assert!(waiting.pending && !waiting.failed && !waiting.restored);
        assert_eq!(
            fs::read(&profile).unwrap(),
            b"unchanged encrypted profile fixture"
        );
        let p = load_package(&root, &v).unwrap();
        assert_eq!(p.signature, signature);
        assert_eq!(p.sha256, digest(&bytes));
        let mut changed = bytes.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(verify_package(&changed, &signature, &v).is_err());
        assert!(verify_package(&bytes, &signature, "999.0.0").is_err());
        atomic(
            &package_dir(&root, &v).unwrap().join("installer.exe"),
            &changed,
        )
        .unwrap();
        assert!(load_package(&root, &v).is_err());
    }
    #[test]
    #[ignore = "Requires two original signed Windows release installers"]
    fn captured_predecessor_envelope_is_pinned_and_foreign_cache_changes_are_rejected() {
        let before =
            std::env::var("FOXVPN_TEST_WINDOWS_UPDATE_ARTIFACT").expect("prior signed artifact");
        let current =
            std::env::var("FOXVPN_TEST_WINDOWS_UPDATE_VERSION").expect("prior signed version");
        let after = std::env::var("FOXVPN_TEST_WINDOWS_UPDATE_NEXT_ARTIFACT")
            .expect("next signed artifact");
        let next =
            std::env::var("FOXVPN_TEST_WINDOWS_UPDATE_NEXT_VERSION").expect("next signed version");
        let old_bytes = fs::read(&before).unwrap();
        let old_sig = fs::read_to_string(format!("{before}.sig")).unwrap();
        let new_bytes = fs::read(&after).unwrap();
        let new_sig = fs::read_to_string(format!("{after}.sig")).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("recovery");
        let target = temp.path().join("smart-vpn-desktop.exe");
        fs::write(&target, b"unchanged GUI").unwrap();
        cache(&root, &old_bytes, &old_sig, &current).unwrap();
        let prepared =
            prepare_at(&root, &target, &current, &new_bytes, &new_sig, &next, true).unwrap();
        let receipt = read_receipt(&root).unwrap().unwrap();
        assert!(receipt.prior_cached);
        assert_eq!(receipt.prior_sha256, Some(digest(&old_bytes)));
        prepared.arm().unwrap();
        drop(prepared);
        let mut receipt = read_receipt(&root).unwrap().unwrap();
        receipt.phase = Phase::Failed;
        write_receipt(&root, &receipt).unwrap();
        assert!(status_at(&root, &target, &next, true)
            .unwrap()
            .guidance
            .unwrap()
            .contains(&current));
        let mut changed = old_bytes;
        let last = changed.len() - 1;
        changed[last] ^= 1;
        atomic(
            &package_dir(&root, &current).unwrap().join("installer.exe"),
            &changed,
        )
        .unwrap();
        assert!(status_at(&root, &target, &next, true).is_err());
        assert_eq!(fs::read(target).unwrap(), b"unchanged GUI");
    }
}
