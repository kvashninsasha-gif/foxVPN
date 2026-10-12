//! GUI-only recovery. The helper's signed version floor and component slots are never written here.
//! The private receipt pins both sealed bundles before replacement. A separate, bounded watchdog
//! restores only that captured predecessor after explicit updater consent and missing UI readiness.
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::Manager;
const INVALID: &str =
    "Не удалось проверить журнал возврата приложения. Используйте проверенный установочный архив.";
const READINESS_SECONDS: u64 = 90;
const INSTALL_SECONDS: u64 = 180;
const MAX_LAUNCHES: u8 = 2;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Prepared,
    Waiting,
    Ready,
    Restoring,
    Restored,
    Failed,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: u8,
    id: String,
    target: PathBuf,
    staged: PathBuf,
    backup: PathBuf,
    prior_version: String,
    version: String,
    prior_hash: String,
    hash: String,
    approved: bool,
    phase: Phase,
    created: u64,
    deadline: u64,
    pid: Option<u32>,
    installer_pid: u32,
    launches: u8,
}
#[derive(Serialize)]
pub struct Status {
    pub pending: bool,
    pub restored: bool,
    pub failed: bool,
    pub prior_version: Option<String>,
    pub recovery_id: Option<String>,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn private_file(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path).map_err(|_| INVALID)?;
    let m = file.metadata().map_err(|_| INVALID)?;
    if !m.is_file()
        || m.uid() != unsafe { libc::getuid() }
        || m.mode() & 0o077 != 0
        || m.len() > 16384
    {
        return Err(INVALID.into());
    }
    Ok(file)
}
fn parent_safe(path: &Path) -> Result<&Path, String> {
    let parent = path.parent().ok_or(INVALID)?;
    let m = fs::symlink_metadata(parent).map_err(|_| INVALID)?;
    if !m.is_dir() || m.uid() != unsafe { libc::getuid() } || m.mode() & 0o022 != 0 {
        return Err(INVALID.into());
    }
    Ok(parent)
}
fn lock(path: &Path, nonblocking: bool) -> Result<File, String> {
    parent_safe(path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| INVALID)?;
    let m = file.metadata().map_err(|_| INVALID)?;
    if !m.is_file() || m.uid() != unsafe { libc::getuid() } || m.mode() & 0o077 != 0 {
        return Err(INVALID.into());
    }
    let flags = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&file), flags) } != 0 {
        return Err(INVALID.into());
    }
    Ok(file)
}
fn receipt_lock(path: &Path) -> Result<File, String> {
    lock(&path.with_extension("lock"), false)
}
fn exists(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(INVALID.into()),
    }
}
fn read(path: &Path) -> Result<Option<Receipt>, String> {
    if !exists(path)? {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    private_file(path)?
        .take(16385)
        .read_to_end(&mut bytes)
        .map_err(|_| INVALID)?;
    let r: Receipt = serde_json::from_slice(&bytes).map_err(|_| INVALID)?;
    validate(&r)?;
    Ok(Some(r))
}
fn validate(r: &Receipt) -> Result<(), String> {
    let parent = r.target.parent().ok_or(INVALID)?;
    let normal = |p: &Path| {
        p.is_absolute()
            && p.components().all(|c| {
                matches!(
                    c,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
    };
    if r.schema != 1
        || uuid::Uuid::parse_str(&r.id).is_err()
        || !r.approved
        || !normal(&r.target)
        || !normal(&r.staged)
        || !normal(&r.backup)
        || r.target.extension().is_none_or(|v| v != "app")
        || r.backup.parent() != Some(parent)
        || r.backup
            .file_name()
            .is_none_or(|v| v != format!(".foxVPN-previous-{}.app", r.id).as_str())
        || r.staged.file_name().is_none_or(|v| v != "foxVPN.app")
        || r.staged.parent().and_then(Path::parent) != Some(parent)
        || r.staged
            .parent()
            .and_then(Path::file_name)
            .is_none_or(|v| !v.to_string_lossy().starts_with(".foxVPN-update-"))
        || r.launches > MAX_LAUNCHES
        || r.pid.is_some_and(|p| p < 2 || p > i32::MAX as u32)
        || r.installer_pid < 2
        || r.installer_pid > i32::MAX as u32
        || [r.prior_hash.as_str(), r.hash.as_str()]
            .iter()
            .any(|s| s.len() != 40 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
        || semver::Version::parse(&r.prior_version).is_err()
        || semver::Version::parse(&r.version).is_err()
        || semver::Version::parse(&r.prior_version).unwrap() < semver::Version::new(0, 1, 28)
        || semver::Version::parse(&r.prior_version).unwrap()
            >= semver::Version::parse(&r.version).unwrap()
        || r.created > now() + 5
        || r.deadline < r.created
        || r.deadline > r.created + INSTALL_SECONDS + READINESS_SECONDS
    {
        return Err(INVALID.into());
    }
    Ok(())
}
fn write(path: &Path, r: &Receipt) -> Result<(), String> {
    validate(r)?;
    let parent = parent_safe(path)?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".gui-recovery-")
        .tempfile_in(parent)
        .map_err(|_| INVALID)?;
    tmp.write_all(&serde_json::to_vec(r).map_err(|_| INVALID)?)
        .and_then(|_| tmp.as_file().sync_all())
        .map_err(|_| INVALID)?;
    tmp.persist(path).map_err(|_| INVALID)?;
    File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(|_| INVALID)?;
    Ok(())
}
fn sealed(path: &Path, version: &str, hash: &str) -> Result<(), String> {
    crate::update_install::verify_bundle(path, version)?;
    if smart_vpn_engine::component_update::macos::bundle_hash(path)? != hash {
        return Err(INVALID.into());
    }
    Ok(())
}
fn journal(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_config_dir()
        .map_err(|_| INVALID)?
        .join("gui-update-recovery.json"))
}

pub struct Installation {
    path: PathBuf,
    receipt: Receipt,
}
impl Installation {
    pub fn prepare(
        path: PathBuf,
        target: &Path,
        staged: &Path,
        version: &str,
        approved: bool,
    ) -> Result<Self, String> {
        if !approved {
            return Err("Автоматический возврат приложения требует отдельного согласия.".into());
        }
        let _lock = receipt_lock(&path)?;
        if read(&path)?
            .is_some_and(|r| matches!(r.phase, Phase::Prepared | Phase::Waiting | Phase::Restoring))
        {
            return Err("Сначала завершите проверку предыдущего обновления.".into());
        }
        let prior_version = crate::update_install::bundle_version(target)?;
        if prior_version != env!("CARGO_PKG_VERSION") {
            return Err(
                "Метаданные установленной app не совпадают с выполняющимся клиентом.".into(),
            );
        }
        crate::update_install::verify_bundle(target, &prior_version)?;
        if smart_vpn_engine::component_update::macos::bundle_hash(target)?
            != smart_vpn_engine::network_helper::self_hash()?
        {
            return Err(INVALID.into());
        }
        let id = uuid::Uuid::new_v4().to_string();
        let r = Receipt {
            schema: 1,
            backup: target.with_file_name(format!(".foxVPN-previous-{id}.app")),
            id,
            target: target.to_owned(),
            staged: staged.to_owned(),
            prior_version,
            version: version.into(),
            prior_hash: smart_vpn_engine::component_update::macos::bundle_hash(target)?,
            hash: smart_vpn_engine::component_update::macos::bundle_hash(staged)?,
            approved,
            phase: Phase::Prepared,
            created: now(),
            deadline: now() + INSTALL_SECONDS,
            pid: None,
            installer_pid: std::process::id(),
            launches: 0,
        };
        write(&path, &r)?;
        if let Err(e) = spawn(&path) {
            let mut failed = r.clone();
            failed.phase = Phase::Failed;
            let _ = write(&path, &failed);
            return Err(e);
        }
        Ok(Self { path, receipt: r })
    }
    pub fn backup(&self) -> &Path {
        &self.receipt.backup
    }
    pub fn installed(&self) -> Result<(), String> {
        let _lock = receipt_lock(&self.path)?;
        let mut r = read(&self.path)?.ok_or(INVALID)?;
        if r.id != self.receipt.id {
            return Err(INVALID.into());
        }
        // A new GUI can confirm readiness before the installing process finishes this write.
        if r.phase == Phase::Prepared {
            r.phase = Phase::Waiting;
            r.deadline = now() + READINESS_SECONDS;
            write(&self.path, &r)?;
        }
        Ok(())
    }
    pub fn failed(&self) {
        if let Ok(_lock) = receipt_lock(&self.path) {
            if let Ok(Some(mut r)) = read(&self.path) {
                if r.id == self.receipt.id {
                    r.phase = Phase::Failed;
                    let _ = write(&self.path, &r);
                }
            }
        }
    }
}
fn spawn(path: &Path) -> Result<(), String> {
    Command::new(std::env::current_exe().map_err(|_| INVALID)?)
        .arg("--foxvpn-gui-watchdog")
        .arg(path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|_| "Не удалось запустить контроль нового приложения.".into())
}
pub fn journal_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    journal(app)
}
pub fn startup(app: &tauri::AppHandle) -> Result<Status, String> {
    status_inner(app, true)
}
pub fn readiness_confirmed(app: &tauri::AppHandle) -> Result<bool, String> {
    let path = journal(app)?;
    if !exists(&path)? {
        return Ok(true);
    }
    let _lock = receipt_lock(&path)?;
    Ok(read(&path)?.is_some_and(|r| r.phase == Phase::Ready))
}
pub fn status(app: &tauri::AppHandle) -> Result<Status, String> {
    status_inner(app, false)
}
fn status_inner(app: &tauri::AppHandle, resume: bool) -> Result<Status, String> {
    let path = journal(app)?;
    if !exists(&path)? {
        return Ok(Status {
            pending: false,
            restored: false,
            failed: false,
            prior_version: None,
            recovery_id: None,
        });
    }
    let _lock = receipt_lock(&path)?;
    let Some(mut r) = read(&path)? else {
        return Err(INVALID.into());
    };
    let exe = std::env::current_exe().map_err(|_| INVALID)?;
    if crate::update_install::app_path(&exe)? != r.target {
        return Err(INVALID.into());
    }
    let current = smart_vpn_engine::network_helper::self_hash()?;
    let pending = matches!(r.phase, Phase::Prepared | Phase::Waiting | Phase::Restoring);
    if pending && current != r.hash && current != r.prior_hash {
        return Err(INVALID.into());
    }
    if pending && resume {
        r.pid = if current == r.hash {
            Some(std::process::id())
        } else {
            None
        };
        write(&path, &r)?;
        spawn(&path)?;
    }
    Ok(Status {
        pending,
        restored: r.phase == Phase::Restored,
        failed: r.phase == Phase::Failed,
        prior_version: Some(r.prior_version),
        recovery_id: Some(r.id),
    })
}
pub fn confirm_app_readiness(app: tauri::AppHandle) -> Result<(), String> {
    let path = journal(&app)?;
    if !exists(&path)? {
        return Ok(());
    }
    let _lock = receipt_lock(&path)?;
    let Some(mut r) = read(&path)? else {
        return Ok(());
    };
    if !matches!(r.phase, Phase::Prepared | Phase::Waiting) {
        return Ok(());
    }
    if crate::update_install::app_path(&std::env::current_exe().map_err(|_| INVALID)?)? != r.target
        || app.package_info().version.to_string() != r.version
        || smart_vpn_engine::network_helper::self_hash()? != r.hash
    {
        return Err(INVALID.into());
    }
    sealed(&r.target, &r.version, &r.hash)?;
    r.phase = Phase::Ready;
    r.pid = None;
    write(&path, &r)
}

pub fn acknowledge(app: tauri::AppHandle, recovery_id: &str, approved: bool) -> Result<(), String> {
    if !approved {
        return Err("Подтверждение результата возврата требует вашего согласия.".into());
    }
    acknowledge_receipt(&journal(&app)?, recovery_id, approved)
}
fn acknowledge_receipt(path: &Path, recovery_id: &str, approved: bool) -> Result<(), String> {
    if !approved {
        return Err("Подтверждение результата возврата требует вашего согласия.".into());
    }
    let _lock = receipt_lock(path)?;
    let r = read(path)?.ok_or(INVALID)?;
    if r.id != recovery_id || !matches!(r.phase, Phase::Restored | Phase::Failed) {
        return Err("Результат обновления изменился. Проверьте состояние заново.".into());
    }
    fs::remove_file(path).map_err(|_| INVALID)?;
    File::open(parent_safe(path)?)
        .and_then(|f| f.sync_all())
        .map_err(|_| INVALID)?;
    Ok(())
}
fn suppress_failed_version(path: &Path, version: &str) -> Result<(), String> {
    let preferences = path.parent().ok_or(INVALID)?.join("updates.json");
    let mut value: serde_json::Value = if exists(&preferences)? {
        let mut bytes = Vec::new();
        private_file(&preferences)?
            .take(8193)
            .read_to_end(&mut bytes)
            .map_err(|_| INVALID)?;
        if bytes.len() > 8192 {
            return Err(INVALID.into());
        }
        serde_json::from_slice(&bytes).map_err(|_| INVALID)?
    } else {
        serde_json::json!({"auto_check":true})
    };
    let fields = value.as_object_mut().ok_or(INVALID)?;
    fields.insert("skipped_version".into(), version.into());
    fields.insert("pending_version".into(), serde_json::Value::Null);
    let parent = parent_safe(&preferences)?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".gui-preferences-")
        .tempfile_in(parent)
        .map_err(|_| INVALID)?;
    tmp.write_all(&serde_json::to_vec(&value).map_err(|_| INVALID)?)
        .and_then(|_| tmp.as_file().sync_all())
        .map_err(|_| INVALID)?;
    tmp.persist(&preferences).map_err(|_| INVALID)?;
    File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(|_| INVALID)?;
    Ok(())
}

/// Call before Vault/Tauri initialization. Never opens a GUI or touches network settings.
pub fn run_watchdog_if_requested() -> bool {
    if std::env::args().nth(1).as_deref() != Some("--foxvpn-gui-watchdog") {
        return false;
    }
    let result = std::env::args_os()
        .nth(2)
        .ok_or_else(|| INVALID.to_string())
        .and_then(|p| watchdog(Path::new(&p)));
    std::process::exit(if result.is_ok() { 0 } else { 1 });
}
fn process_hash(pid: u32) -> Result<String, String> {
    unsafe extern "C" {
        fn fox_process_hash(pid: u32, owner: u32, out: *mut libc::c_char) -> i32;
    }
    let mut hash = [0i8; 41];
    if unsafe { fox_process_hash(pid, libc::getuid(), hash.as_mut_ptr()) } != 1 {
        return Err(INVALID.into());
    }
    Ok(unsafe { std::ffi::CStr::from_ptr(hash.as_ptr()) }
        .to_string_lossy()
        .into_owned())
}
fn running_gui_pids(r: &Receipt, expected_hash: &str) -> Result<Vec<u32>, String> {
    unsafe extern "C" {
        fn proc_listpids(
            kind: u32,
            info: u32,
            buffer: *mut libc::c_void,
            size: libc::c_int,
        ) -> libc::c_int;
        fn proc_pidpath(pid: libc::c_int, buffer: *mut libc::c_void, size: u32) -> libc::c_int;
    }
    let mut pids = [0i32; 4096];
    let size = std::mem::size_of_val(&pids);
    // PROC_UID_ONLY=4; the kernel filters process ownership.
    let bytes = unsafe { proc_listpids(4, libc::getuid(), pids.as_mut_ptr().cast(), size as i32) };
    if bytes <= 0 || bytes as usize >= size {
        return Err(INVALID.into());
    }
    let mut result = Vec::new();
    use std::os::unix::ffi::OsStrExt;
    for pid in pids
        .into_iter()
        .take(bytes as usize / std::mem::size_of::<i32>())
    {
        if pid < 2 || pid as u32 == r.installer_pid || pid as u32 == std::process::id() {
            continue;
        }
        let mut path = [0u8; 4096];
        if unsafe { proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) } <= 0 {
            continue;
        }
        let len = path.iter().position(|b| *b == 0).ok_or(INVALID)?;
        if Path::new(std::ffi::OsStr::from_bytes(&path[..len]))
            == r.target.join("Contents/MacOS/smart-vpn-desktop")
        {
            if process_hash(pid as u32)? != expected_hash {
                return Err(INVALID.into());
            }
            result.push(pid as u32);
            if result.len() > 8 {
                return Err(INVALID.into());
            }
        }
    }
    Ok(result)
}
fn terminate_gui(pid: u32, target: &Path, expected_hash: &str) -> Result<(), String> {
    // A recycled PID cannot authorize killing an unrelated process.
    if pid == std::process::id() || pid < 2 || pid > i32::MAX as u32 {
        return Err(INVALID.into());
    }
    let mut path = [0u8; 4096];
    unsafe extern "C" {
        fn proc_pidpath(pid: libc::c_int, buffer: *mut libc::c_void, size: u32) -> libc::c_int;
    }
    let len = unsafe { proc_pidpath(pid as i32, path.as_mut_ptr().cast(), path.len() as u32) };
    if len <= 0 {
        return Ok(());
    }
    let len = path.iter().position(|b| *b == 0).ok_or(INVALID)?;
    use std::os::unix::ffi::OsStrExt;
    if Path::new(std::ffi::OsStr::from_bytes(&path[..len]))
        != target.join("Contents/MacOS/smart-vpn-desktop")
    {
        return Err(INVALID.into());
    }
    if process_hash(pid)? != expected_hash {
        return Err(INVALID.into());
    }
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    for _ in 0..20 {
        if unsafe { libc::kill(pid as i32, 0) } != 0 {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // Do not force-kill a GUI that may be saving a profile. A manual recovery is safer.
    Err("Приложение не завершилось безопасно; автоматический возврат остановлен.".into())
}
fn restore(path: &Path, r: &mut Receipt) -> Result<(), String> {
    if r.phase == Phase::Restoring && sealed(&r.target, &r.prior_version, &r.prior_hash).is_ok() {
        r.phase = Phase::Restored;
        r.pid = None;
        return write(path, r);
    }
    let previous = if sealed(&r.backup, &r.prior_version, &r.prior_hash).is_ok() {
        r.backup.clone()
    } else {
        sealed(&r.staged, &r.prior_version, &r.prior_hash)?;
        r.staged.clone()
    };
    sealed(&r.target, &r.version, &r.hash)?;
    let mut pids = running_gui_pids(r, &r.hash)?;
    if let Some(pid) = r.pid {
        if !pids.contains(&pid) {
            pids.push(pid);
        }
    }
    for pid in pids {
        terminate_gui(pid, &r.target, &r.hash)?;
    }

    r.phase = Phase::Restoring;
    write(path, r)?;
    // Recheck after process shutdown and the durable checkpoint, directly before exchange.
    sealed(&r.target, &r.version, &r.hash)?;
    sealed(&previous, &r.prior_version, &r.prior_hash)?;
    crate::update_install::exchange_bundles(&r.target, &previous)?;
    r.phase = Phase::Restored;
    r.pid = None;
    write(path, r)
}
fn watchdog(path: &Path) -> Result<(), String> {
    let _monitor = match lock(&path.with_extension("watchdog.lock"), true) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    let started = now();
    loop {
        let _lock = receipt_lock(path)?;
        let Some(mut r) = read(path)? else {
            return Ok(());
        };
        if !matches!(r.phase, Phase::Prepared | Phase::Waiting | Phase::Restoring) {
            return Ok(());
        }
        let own = smart_vpn_engine::network_helper::self_hash()?;
        if own != r.prior_hash && own != r.hash {
            return Err(INVALID.into());
        }
        if crate::update_install::app_path(&std::env::current_exe().map_err(|_| INVALID)?)?
            != r.target
        {
            return Err(INVALID.into());
        }
        if r.phase == Phase::Prepared && sealed(&r.target, &r.version, &r.hash).is_ok() {
            r.phase = Phase::Waiting;
            r.deadline = now() + READINESS_SECONDS;
            write(path, &r)?;
        }
        if now() >= r.deadline
            || now().saturating_sub(started) >= INSTALL_SECONDS + READINESS_SECONDS
        {
            if r.phase != Phase::Restoring
                && sealed(&r.target, &r.prior_version, &r.prior_hash).is_ok()
            {
                r.phase = Phase::Failed;
                write(path, &r)?;
                return Ok(());
            }
            if let Err(e) = restore(path, &mut r) {
                r.phase = Phase::Failed;
                write(path, &r)?;
                return Err(e);
            }
            // Suppress this failed version for automatic offers; manual checks remain available.
            if suppress_failed_version(path, &r.version).is_err() {
                r.phase = Phase::Failed;
                write(path, &r)?;
                return Err(INVALID.into());
            }
            if !running_gui_pids(&r, &r.prior_hash)?.is_empty() {
                return Ok(());
            }
            while r.launches < MAX_LAUNCHES {
                r.launches += 1;
                write(path, &r)?;
                if Command::new("/usr/bin/open")
                    .arg("-n")
                    .arg(&r.target)
                    .status()
                    .is_ok_and(|s| s.success())
                {
                    return Ok(());
                }
            }
            r.phase = Phase::Failed;
            write(path, &r)?;
            return Err("Прежняя копия возвращена, но её запуск не подтверждён.".into());
        }
        drop(_lock);
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(root: &Path) -> Receipt {
        let id = uuid::Uuid::new_v4().to_string();
        Receipt {
            schema: 1,
            target: root.join("foxVPN.app"),
            staged: root.join(".foxVPN-update-fixture/foxVPN.app"),
            backup: root.join(format!(".foxVPN-previous-{id}.app")),
            id,
            prior_version: "0.1.28".into(),
            version: "0.1.29".into(),
            prior_hash: "a".repeat(40),
            hash: "b".repeat(40),
            approved: true,
            phase: Phase::Waiting,
            created: now(),
            deadline: now(),
            pid: None,
            installer_pid: std::process::id(),
            launches: 0,
        }
    }
    #[test]
    fn explicit_consent_paths_versions_and_bounded_attempts_required() {
        let root = tempfile::tempdir().unwrap();
        let good = sample(root.path());
        validate(&good).unwrap();
        for change in 0..8 {
            let mut r = good.clone();
            match change {
                0 => r.approved = false,
                1 => r.launches = MAX_LAUNCHES + 1,
                2 => r.prior_version = r.version.clone(),
                3 => r.backup = root.path().join("unrelated.app"),
                4 => r.staged = root.path().join("elsewhere/foxVPN.app"),
                5 => r.hash = "bad".into(),
                6 => r.deadline = r.created + INSTALL_SECONDS + READINESS_SECONDS + 1,
                _ => r.prior_version = "0.1.27".into(),
            }
            assert!(validate(&r).is_err());
        }
    }
    #[test]
    fn private_durable_receipt_rejects_tampering_and_links() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("receipt.json");
        let r = sample(root.path());
        write(&path, &r).unwrap();
        assert_eq!(read(&path).unwrap().unwrap().phase, Phase::Waiting);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(&path).is_err());
        fs::remove_file(&path).unwrap();
        let other = root.path().join("other");
        fs::write(&other, b"preserved").unwrap();
        std::os::unix::fs::symlink(&other, &path).unwrap();
        assert!(read(&path).is_err());
        assert_eq!(fs::read(&other).unwrap(), b"preserved");
    }
    #[test]
    fn damaged_receipt_is_never_treated_as_missing() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("receipt.json");
        write(&path, &sample(root.path())).unwrap();
        fs::write(&path, b"broken").unwrap();
        assert!(read(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"broken");
    }
    fn bundle(path: &Path, version: &str) -> String {
        fs::create_dir_all(path.join("Contents/MacOS")).unwrap();
        fs::create_dir_all(path.join("Contents/Resources")).unwrap();
        assert!(Command::new("/usr/bin/lipo")
            .args(["/usr/bin/true", "-thin", "arm64e", "-output"])
            .arg(path.join("Contents/MacOS/smart-vpn-desktop"))
            .output()
            .unwrap()
            .status
            .success());
        let info = format!(
            r#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>ru.smartvpn.router</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleExecutable</key><string>smart-vpn-desktop</string><key>CFBundleVersion</key><string>{version}</string><key>CFBundleShortVersionString</key><string>{version}</string></dict></plist>"#
        );
        fs::write(path.join("Contents/Info.plist"), info).unwrap();
        for name in [
            "core/sing-box",
            "network/foxvpn-helper",
            "network/foxvpn-network-core",
            "network/network-version.json",
            "network/component-version.json",
        ] {
            let file = path.join("Contents/Resources").join(name);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, version).unwrap();
        }
        assert!(Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--timestamp=none"])
            .arg(path)
            .output()
            .unwrap()
            .status
            .success());
        crate::update_install::verify_bundle(path, version).unwrap();
        smart_vpn_engine::component_update::macos::bundle_hash(path).unwrap()
    }
    #[test]
    fn only_pinned_sealed_predecessor_restored_atomically_and_not_twice() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("receipt.json");
        let mut r = sample(root.path());
        r.hash = bundle(&r.target, &r.version);
        r.prior_hash = bundle(&r.backup, &r.prior_version);
        write(&path, &r).unwrap();
        restore(&path, &mut r).unwrap();
        assert_eq!(r.phase, Phase::Restored);
        sealed(&r.target, &r.prior_version, &r.prior_hash).unwrap();
        sealed(&r.backup, &r.version, &r.hash).unwrap();
        assert!(restore(&path, &mut r).is_err());
        sealed(&r.target, &r.prior_version, &r.prior_hash).unwrap();
    }
    #[test]
    fn altered_predecessor_or_replaced_target_never_swapped() {
        for change_target in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("receipt.json");
            let mut r = sample(root.path());
            r.hash = bundle(&r.target, &r.version);
            r.prior_hash = bundle(&r.backup, &r.prior_version);
            write(&path, &r).unwrap();
            let changed = if change_target { &r.target } else { &r.backup };
            fs::write(
                changed.join("Contents/Resources/core/sing-box"),
                b"tampered",
            )
            .unwrap();
            assert!(restore(&path, &mut r).is_err());
            assert_eq!(
                crate::update_install::bundle_version(&r.target).unwrap(),
                r.version
            );
        }
    }
    #[test]
    fn crash_after_exchange_finishes_receipt_without_second_exchange() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("receipt.json");
        let mut r = sample(root.path());
        r.hash = bundle(&r.target, &r.version);
        r.prior_hash = bundle(&r.backup, &r.prior_version);
        r.phase = Phase::Restoring;
        write(&path, &r).unwrap();
        crate::update_install::exchange_bundles(&r.target, &r.backup).unwrap();
        restore(&path, &mut r).unwrap();
        assert_eq!(read(&path).unwrap().unwrap().phase, Phase::Restored);
        sealed(&r.target, &r.prior_version, &r.prior_hash).unwrap();
    }
    #[test]
    fn subprocess_swap_worker() {
        let Ok(path) = std::env::var("FOXVPN_GUI_RECOVERY_TEST_RECEIPT") else {
            return;
        };
        let r = read(Path::new(&path)).unwrap().unwrap();
        if std::env::var("FOXVPN_GUI_RECOVERY_TEST_AFTER_SWAP").as_deref() == Ok("1") {
            crate::update_install::exchange_bundles(&r.target, &r.backup).unwrap();
        }
        // Abrupt child exit deliberately skips receipt finalization and destructors.
        std::process::exit(73);
    }
    #[test]
    fn interrupted_process_before_and_after_exchange_recovers_from_durable_receipt() {
        for after in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("receipt.json");
            let mut r = sample(root.path());
            r.hash = bundle(&r.target, &r.version);
            r.prior_hash = bundle(&r.backup, &r.prior_version);
            r.phase = Phase::Restoring;
            write(&path, &r).unwrap();
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "mac_gui_rollback::tests::subprocess_swap_worker",
                    "--nocapture",
                ])
                .env("FOXVPN_GUI_RECOVERY_TEST_RECEIPT", &path)
                .env(
                    "FOXVPN_GUI_RECOVERY_TEST_AFTER_SWAP",
                    if after { "1" } else { "0" },
                )
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(73),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            let mut durable = read(&path).unwrap().unwrap();
            restore(&path, &mut durable).unwrap();
            assert_eq!(durable.phase, Phase::Restored);
            sealed(&durable.target, &durable.prior_version, &durable.prior_hash).unwrap();
            sealed(&durable.backup, &durable.version, &durable.hash).unwrap();
        }
    }
    #[test]
    fn acknowledgement_requires_consent_exact_id_and_terminal_result() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("receipt.json");
        let mut r = sample(root.path());
        write(&path, &r).unwrap();
        assert!(acknowledge_receipt(&path, &r.id, false).is_err());
        assert!(acknowledge_receipt(&path, &r.id, true).is_err());
        r.phase = Phase::Restored;
        write(&path, &r).unwrap();
        assert!(acknowledge_receipt(&path, "stale-id", true).is_err());
        assert!(path.exists());
        acknowledge_receipt(&path, &r.id, true).unwrap();
        assert!(!path.exists());
    }
    #[test]
    fn failed_version_suppression_preserves_preferences_and_rejects_broken_data() {
        let root = tempfile::tempdir().unwrap();
        let receipt = root.path().join("receipt.json");
        let prefs = root.path().join("updates.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&prefs)
            .unwrap();
        file.write_all(br#"{"auto_check":false,"skipped_version":"0.1.26","pending_version":"0.1.28","other_setting":123}"#).unwrap();
        drop(file);
        suppress_failed_version(&receipt, "0.1.28").unwrap();
        let value: serde_json::Value = serde_json::from_slice(&fs::read(&prefs).unwrap()).unwrap();
        assert_eq!(value["auto_check"], false);
        assert_eq!(value["skipped_version"], "0.1.28");
        assert!(value["pending_version"].is_null());
        assert_eq!(value["other_setting"], 123);
        fs::write(&prefs, b"broken").unwrap();
        assert!(suppress_failed_version(&receipt, "0.1.29").is_err());
        assert_eq!(fs::read(&prefs).unwrap(), b"broken");
    }
    #[test]
    fn sealed_archive_staged_and_synced_before_atomic_install_keeps_original() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("installed.app");
        let source = root.path().join("source/foxVPN.app");
        let hash = bundle(&source, "0.1.28");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("original-app-marker"), b"original-app-marker").unwrap();
        let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut archive = tar::Builder::new(gzip);
        archive.append_dir_all("foxVPN.app", &source).unwrap();
        let bytes = archive.into_inner().unwrap().finish().unwrap();
        let backup = crate::update_install::prepare(&bytes, &target, "0.1.28")
            .unwrap()
            .commit()
            .unwrap();
        sealed(&target, "0.1.28", &hash).unwrap();
        assert_eq!(
            fs::read(backup.join("original-app-marker")).unwrap(),
            b"original-app-marker"
        );
    }
    #[test]
    fn package_type_and_thin_arm64_executable_required_even_for_valid_signature() {
        for mode in ["package", "build-version", "intel", "universal", "dylib"] {
            let root = tempfile::tempdir().unwrap();
            let app = root.path().join("foxVPN.app");
            bundle(&app, "0.1.28");
            match mode {
                "package" | "build-version" => {
                    let path = app.join("Contents/Info.plist");
                    let mut info = plist::Value::from_file(&path).unwrap();
                    let (key, value) = if mode == "package" {
                        ("CFBundlePackageType", "BNDL")
                    } else {
                        ("CFBundleVersion", "0.1.27")
                    };
                    info.as_dictionary_mut()
                        .unwrap()
                        .insert(key.into(), plist::Value::String(value.into()));
                    info.to_file_xml(path).unwrap();
                }
                "intel" => {
                    assert!(Command::new("/usr/bin/lipo")
                        .args(["/usr/bin/true", "-thin", "x86_64", "-output"])
                        .arg(app.join("Contents/MacOS/smart-vpn-desktop"))
                        .output()
                        .unwrap()
                        .status
                        .success());
                }
                "universal" => {
                    fs::copy(
                        "/usr/bin/true",
                        app.join("Contents/MacOS/smart-vpn-desktop"),
                    )
                    .unwrap();
                }
                _ => {
                    let source = root.path().join("library.c");
                    fs::write(&source, b"int foxvpn_fixture(void) { return 0; }\n").unwrap();
                    assert!(Command::new("/usr/bin/xcrun")
                        .args(["clang", "-arch", "arm64", "-dynamiclib"])
                        .arg(&source)
                        .arg("-o")
                        .arg(app.join("Contents/MacOS/smart-vpn-desktop"))
                        .output()
                        .unwrap()
                        .status
                        .success());
                }
            }
            assert!(Command::new("/usr/bin/codesign")
                .args(["--force", "--sign", "-", "--timestamp=none"])
                .arg(&app)
                .output()
                .unwrap()
                .status
                .success());
            assert!(
                crate::update_install::verify_bundle(&app, "0.1.28").is_err(),
                "{mode}"
            );
        }
    }
}
