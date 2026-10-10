//! Root-owned component slots. Only the fixed slot is exchanged; IPC cannot
//! choose an executable, destination, launchd label, signing key or script.
use super::*;
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Cursor, Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::{Component, Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

const LABEL: &str = "system/ru.smartvpn.router.network";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transaction {
    backup: String,
    nonce: String,
    version: String,
    sha256: String,
}
impl Transaction {
    fn validate(&self) -> Result<(), String> {
        let id = self
            .backup
            .strip_prefix("component-backup-")
            .ok_or(INVALID)?;
        uuid::Uuid::parse_str(id).map_err(|_| INVALID)?;
        uuid::Uuid::parse_str(&self.nonce).map_err(|_| INVALID)?;
        release_version(&self.version)?;
        if !digest_valid(&self.sha256) {
            return Err(INVALID.into());
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
struct Ready {
    nonce: String,
    sha256: String,
    pid: u32,
}
pub struct Store {
    root: PathBuf,
    file_uid: u32,
    uploads: PathBuf,
}
pub struct Lock(File);
struct ProbeChild(std::process::Child);
impl Drop for ProbeChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
pub struct Prepared {
    backup: PathBuf,
    binding: Binding,
    cleanup: bool,
}
impl Drop for Prepared {
    fn drop(&mut self) {
        if self.cleanup {
            let _ = fs::remove_dir_all(&self.backup);
        }
    }
}

fn owned(path: &Path, uid: u32, directory: bool) -> Result<(), String> {
    let m = fs::symlink_metadata(path).map_err(|_| INVALID)?;
    if m.uid() != uid
        || m.mode() & 0o022 != 0
        || (if directory { !m.is_dir() } else { !m.is_file() })
    {
        return Err(INVALID.into());
    }
    Ok(())
}
fn read_json<T: serde::de::DeserializeOwned>(path: &Path, uid: u32) -> Result<T, String> {
    owned(path, uid, false)?;
    let bytes = fs::read(path).map_err(|_| INVALID)?;
    if bytes.len() > 8192 {
        return Err(INVALID.into());
    }
    serde_json::from_slice(&bytes).map_err(|_| INVALID.into())
}
fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let temp = path.with_file_name(format!(".component-json-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&temp)
            .map_err(|_| INVALID)?;
        file.set_permissions(fs::Permissions::from_mode(0o644))
            .map_err(|_| INVALID)?;
        file.write_all(&serde_json::to_vec(value).map_err(|_| INVALID)?)
            .and_then(|_| file.sync_all())
            .map_err(|_| INVALID)?;
        fs::rename(&temp, path).map_err(|_| INVALID)?;
        File::open(path.parent().ok_or(INVALID)?)
            .and_then(|f| f.sync_all())
            .map_err(|_| INVALID.into())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
fn exchange(a: &Path, b: &Path) -> Result<(), String> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    unsafe extern "C" {
        fn renamex_np(a: *const libc::c_char, b: *const libc::c_char, flags: u32) -> i32;
    }
    let a = CString::new(a.as_os_str().as_bytes()).map_err(|_| INVALID)?;
    let b = CString::new(b.as_os_str().as_bytes()).map_err(|_| INVALID)?;
    if unsafe { renamex_np(a.as_ptr(), b.as_ptr(), 2) } != 0 {
        return Err(INVALID.into());
    }
    Ok(())
}
pub fn public_binding() -> Result<Binding, String> {
    owned(Path::new(BASE), 0, true)?;
    owned(Path::new(SLOT), 0, true)?;
    let b: Binding = read_json(&Path::new(SLOT).join("binding.json"), 0)?;
    b.validate()?;
    Ok(b)
}
impl Store {
    pub fn system() -> Result<Self, String> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(INVALID.into());
        }
        let store = Self {
            root: PathBuf::from(BASE),
            file_uid: 0,
            uploads: PathBuf::from(UPLOADS),
        };
        owned(&store.root, 0, true)?;
        Ok(store)
    }
    fn slot(&self) -> PathBuf {
        self.root.join("component")
    }
    fn binding_at(&self, slot: &Path) -> Result<Binding, String> {
        owned(slot, self.file_uid, true)?;
        let b: Binding = read_json(&slot.join("binding.json"), self.file_uid)?;
        b.validate()?;
        Ok(b)
    }
    pub fn binding(&self) -> Result<Binding, String> {
        self.binding_at(&self.slot())
    }
    pub fn lock(&self) -> Result<Lock, String> {
        let path = self.root.join("update.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|_| INVALID)?;
        owned(&path, self.file_uid, false)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("Сетевой компонент завершает предыдущее обновление. Повторите проверку через несколько секунд.".into());
        }
        Ok(Lock(file))
    }
    fn transaction(&self) -> Result<Option<Transaction>, String> {
        let path = self.root.join("transaction.json");
        if !path.exists() {
            return Ok(None);
        }
        let t: Transaction = read_json(&path, self.file_uid)?;
        t.validate()?;
        Ok(Some(t))
    }
    fn floor(&self) -> Result<Floor, String> {
        read_json(&self.root.join("floor.json"), self.file_uid)
    }
    pub fn validate_slot(&self) -> Result<Binding, String> {
        let b = self.binding()?;
        if b.version != env!("CARGO_PKG_VERSION") {
            return Err(INVALID.into());
        }
        for name in ["helper", "core", "network-version.json"] {
            owned(&self.slot().join(name), self.file_uid, false)?;
        }
        let info: serde_json::Value =
            read_json(&self.slot().join("network-version.json"), self.file_uid)?;
        if format!(
            "{:x}",
            Sha256::digest(fs::read(self.slot().join("core")).map_err(|_| INVALID)?)
        ) != info["binary_sha256"].as_str().unwrap_or("")
        {
            return Err(INVALID.into());
        }
        release_version(&self.floor()?.version)?;
        Ok(b)
    }
    pub fn prepare(
        &self,
        request: &InstallRequest,
        peer_hash: &str,
    ) -> Result<Option<Prepared>, String> {
        if request.archive.len() > 4096 {
            return Err(INVALID.into());
        }
        let old = self.binding()?;
        if !old.accepts(peer_hash, old.owner) {
            return Err(INVALID.into());
        }
        let input = Path::new(&request.archive);
        let allowed = self.uploads.join(old.owner.to_string());
        let name = input.file_name().and_then(|s| s.to_str()).ok_or(INVALID)?;
        if input.parent() != Some(allowed.as_path())
            || name.len() > 128
            || !name.starts_with("foxvpn-update-")
            || !name.ends_with(".tar.gz")
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
        {
            return Err(INVALID.into());
        }
        owned(&allowed, old.owner, true)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&request.archive)
            .map_err(|_| INVALID)?;
        let stat = file.metadata().map_err(|_| INVALID)?;
        if !stat.is_file() || stat.uid() != old.owner || stat.len() > MAX_ARCHIVE {
            return Err(INVALID.into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_ARCHIVE + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| INVALID)?;
        let digest = verify_archive(&bytes, &request.signature, &request.version)?;
        check_version(&self.floor()?, &request.version, &digest)?;
        // Retry after a lost reply/app replacement failure. Never replace an
        // already active version with different bytes, even with a valid key.
        if old.version == request.version && old.archive_sha256 == digest {
            return Ok(None);
        }
        if release_version(&request.version)? <= release_version(&old.version)?
            || self.transaction()?.is_some()
        {
            return Err(INVALID.into());
        }
        let unpack = tempfile::Builder::new()
            .prefix(".component-unpack-")
            .tempdir_in(&self.root)
            .map_err(|_| INVALID)?;
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(Cursor::new(bytes)));
        let mut expanded = 0u64;
        let mut names = BTreeSet::new();
        for item in archive.entries().map_err(|_| INVALID)? {
            let mut entry = item.map_err(|_| INVALID)?;
            expanded = expanded.saturating_add(entry.size());
            let path = entry.path().map_err(|_| INVALID)?.into_owned();
            let mut parts = path.components();
            if expanded > 512 * 1024 * 1024
                || names.len() > 16384
                || !matches!(parts.next(), Some(Component::Normal(s)) if s == "foxVPN.app")
                || parts.any(|p| !matches!(p, Component::Normal(_)))
                || !matches!(
                    entry.header().entry_type(),
                    tar::EntryType::Regular | tar::EntryType::Directory
                )
                || !names.insert(path.to_string_lossy().to_lowercase())
                || !entry.unpack_in(unpack.path()).map_err(|_| INVALID)?
            {
                return Err(INVALID.into());
            }
            let target = unpack.path().join(path);
            fs::set_permissions(
                &target,
                fs::Permissions::from_mode(if target.is_dir() {
                    0o755
                } else {
                    entry.header().mode().map_err(|_| INVALID)? & 0o755
                }),
            )
            .map_err(|_| INVALID)?;
        }
        let app = unpack.path().join("foxVPN.app");
        let info = plist::Value::from_file(app.join("Contents/Info.plist")).map_err(|_| INVALID)?;
        let info = info.as_dictionary().ok_or(INVALID)?;
        for (key, expected) in [
            ("CFBundleIdentifier", "ru.smartvpn.router"),
            ("CFBundleExecutable", "smart-vpn-desktop"),
            ("CFBundleShortVersionString", request.version.as_str()),
        ] {
            if info.get(key).and_then(plist::Value::as_string) != Some(expected) {
                return Err(INVALID.into());
            }
        }
        let output = Command::new("/usr/bin/codesign")
            .args(["--verify", "--deep", "--strict"])
            .arg(&app)
            .output()
            .map_err(|_| INVALID)?;
        if !output.status.success() {
            return Err(INVALID.into());
        }
        let resources = app.join("Contents/Resources/network");
        let component: serde_json::Value = serde_json::from_slice(
            &fs::read(resources.join("component-version.json")).map_err(|_| INVALID)?,
        )
        .map_err(|_| INVALID)?;
        if component["protocol"] != crate::network_helper::PROTOCOL
            || component["version"] != request.version
        {
            return Err(INVALID.into());
        }
        let core = fs::read(resources.join("foxvpn-network-core")).map_err(|_| INVALID)?;
        let helper = fs::read(resources.join("foxvpn-helper")).map_err(|_| INVALID)?;
        for binary in [&core, &helper] {
            if !binary.starts_with(&[0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0, 0, 1]) {
                return Err(INVALID.into());
            }
        }
        // Check the helper's compiled version, not just archive metadata.
        let log_path = unpack.path().join("helper-version.out");
        let log = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&log_path)
            .map_err(|_| INVALID)?;
        let mut child = ProbeChild(
            Command::new(resources.join("foxvpn-helper"))
                .arg("--component-version")
                .stdin(std::process::Stdio::null())
                .stdout(log)
                .stderr(std::process::Stdio::null())
                .spawn()
                .map_err(|_| INVALID)?,
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = child.0.try_wait().map_err(|_| INVALID)? {
                if !status.success() {
                    return Err(INVALID.into());
                }
                break;
            }
            if Instant::now() >= deadline
                || fs::metadata(&log_path).map_err(|_| INVALID)?.len() > 8192
            {
                let _ = child.0.kill();
                let _ = child.0.wait();
                return Err(INVALID.into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if fs::metadata(&log_path).map_err(|_| INVALID)?.len() > 8192 {
            return Err(INVALID.into());
        }
        let actual: serde_json::Value =
            serde_json::from_slice(&fs::read(&log_path).map_err(|_| INVALID)?)
                .map_err(|_| INVALID)?;
        if actual["version"] != request.version
            || actual["protocol"] != crate::network_helper::PROTOCOL
        {
            return Err(INVALID.into());
        }
        let meta: serde_json::Value = serde_json::from_slice(
            &fs::read(resources.join("network-version.json")).map_err(|_| INVALID)?,
        )
        .map_err(|_| INVALID)?;
        if format!("{:x}", Sha256::digest(&core)) != meta["binary_sha256"].as_str().unwrap_or("") {
            return Err(INVALID.into());
        }
        let current = bundle_hash(&app)?;
        let binding = Binding {
            protocol: crate::network_helper::PROTOCOL,
            version: request.version.clone(),
            owner: old.owner,
            current,
            previous: Some(peer_hash.to_owned()),
            archive_sha256: digest,
        };
        binding.validate()?;
        let backup = self
            .root
            .join(format!("component-backup-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&backup).map_err(|_| INVALID)?;
        fs::set_permissions(&backup, fs::Permissions::from_mode(0o755)).map_err(|_| INVALID)?;
        let prepared = Prepared {
            backup,
            binding,
            cleanup: true,
        };
        for (from, to) in [
            ("foxvpn-helper", "helper"),
            ("foxvpn-network-core", "core"),
            ("network-version.json", "network-version.json"),
        ] {
            fs::copy(resources.join(from), prepared.backup.join(to)).map_err(|_| INVALID)?;
            fs::set_permissions(
                prepared.backup.join(to),
                fs::Permissions::from_mode(if to.ends_with(".json") { 0o644 } else { 0o755 }),
            )
            .map_err(|_| INVALID)?;
            File::open(prepared.backup.join(to))
                .and_then(|f| f.sync_all())
                .map_err(|_| INVALID)?;
        }
        write_json(&prepared.backup.join("binding.json"), &prepared.binding)?;
        Ok(Some(prepared))
    }
    /// Caller holds update.lock and has already confirmed VPN/DNS/PF stopped.
    pub fn commit(&self, mut prepared: Prepared) -> Result<(), String> {
        let t = Transaction {
            backup: prepared
                .backup
                .file_name()
                .ok_or(INVALID)?
                .to_str()
                .ok_or(INVALID)?
                .into(),
            nonce: uuid::Uuid::new_v4().to_string(),
            version: prepared.binding.version.clone(),
            sha256: prepared.binding.archive_sha256.clone(),
        };
        t.validate()?;
        write_json(&self.root.join("transaction.json"), &t)?;
        // Separate watchdog survives exec/crash. The old signed helper is used
        // and receives only a fixed mode flag, never a caller-supplied command.
        let result = (|| {
            let _watchdog = Command::new(self.slot().join("helper"))
                .arg("--component-watchdog")
                .stdin(std::process::Stdio::null())
                .spawn()
                .map_err(|_| INVALID)?;
            write_json(
                &self.root.join("floor.json"),
                &Floor {
                    version: t.version.clone(),
                    sha256: t.sha256.clone(),
                },
            )?;
            owned(&self.slot(), self.file_uid, true)?;
            owned(&prepared.backup, self.file_uid, true)?;
            exchange(&self.slot(), &prepared.backup)
        })();
        if let Err(error) = result {
            let _ = fs::remove_file(self.root.join("transaction.json"));
            return Err(error);
        }
        prepared.cleanup = false; // this path is now the known-good backup
        File::open(&self.root)
            .and_then(|f| f.sync_all())
            .map_err(|_| INVALID)?;
        Ok(())
    }
    pub fn ready(&self) -> Result<(), String> {
        if let Some(t) = self.transaction()? {
            let b = self.binding()?;
            if b.archive_sha256 == t.sha256 && b.version == t.version {
                write_json(
                    &self.root.join("ready.json"),
                    &Ready {
                        nonce: t.nonce,
                        sha256: t.sha256,
                        pid: std::process::id(),
                    },
                )?;
            }
            let _watchdog = Command::new(self.slot().join("helper"))
                .arg("--component-watchdog")
                .stdin(std::process::Stdio::null())
                .spawn()
                .map_err(|_| INVALID)?;
        }
        Ok(())
    }
    pub fn finalize(&self, current_peer: bool) -> Result<(), String> {
        if !current_peer {
            return Err(INVALID.into());
        }
        let _lock = self.lock()?;
        if let Some(t) = self.transaction()? {
            let mut b = self.binding()?;
            if b.archive_sha256 != t.sha256 || b.version != t.version {
                return Err(INVALID.into());
            }
            b.previous = None;
            write_json(&self.slot().join("binding.json"), &b)?;
            let backup = self.root.join(&t.backup);
            if backup.exists() {
                owned(&backup, self.file_uid, true)?;
                fs::remove_dir_all(backup).map_err(|_| INVALID)?;
            }
            fs::remove_file(self.root.join("transaction.json")).map_err(|_| INVALID)?;
            let _ = fs::remove_file(self.root.join("ready.json"));
        }
        Ok(())
    }
    /// Called only by the fixed root watchdog entry. No supplied destinations.
    pub fn watchdog(&self) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let _lock = loop {
            match self.lock() {
                Ok(lock) => break lock,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100))
                }
                Err(error) => return Err(error),
            }
        };
        let Some(t) = self.transaction()? else {
            return Ok(());
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if self
                .transaction()?
                .is_none_or(|current| current.nonce != t.nonce)
            {
                return Ok(());
            }
            if let Ok(ready) = read_json::<Ready>(&self.root.join("ready.json"), self.file_uid) {
                if ready.nonce == t.nonce
                    && ready.sha256 == t.sha256
                    && ready.pid > 1
                    && ready.pid <= i32::MAX as u32
                    && unsafe { libc::kill(ready.pid as i32, 0) } == 0
                {
                    std::thread::sleep(Duration::from_secs(1));
                    if unsafe { libc::kill(ready.pid as i32, 0) } == 0 {
                        return Ok(());
                    }
                }
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let changed = self.restore(&t)?;
        if changed {
            let result = Command::new("/bin/launchctl")
                .args(["kickstart", "-k", LABEL])
                .status()
                .map_err(|_| INVALID)?;
            if !result.success() {
                return Err(INVALID.into());
            }
        }
        Ok(())
    }
    fn restore(&self, t: &Transaction) -> Result<bool, String> {
        t.validate()?;
        let backup = self.root.join(&t.backup);
        let current = self.binding()?;
        if !backup.exists() && current.archive_sha256 != t.sha256 {
            fs::remove_file(self.root.join("transaction.json")).map_err(|_| INVALID)?;
            let _ = fs::remove_file(self.root.join("ready.json"));
            return Ok(false);
        }
        let other = self.binding_at(&backup)?;
        if other.owner != current.owner {
            return Err(INVALID.into());
        }
        let mut changed = false;
        if current.archive_sha256 == t.sha256 && other.archive_sha256 != t.sha256 {
            exchange(&self.slot(), &backup)?;
            File::open(&self.root)
                .and_then(|f| f.sync_all())
                .map_err(|_| INVALID)?;
            changed = true;
        } else if other.archive_sha256 != t.sha256 {
            return Err(INVALID.into());
        }
        fs::remove_dir_all(backup).map_err(|_| INVALID)?;
        fs::remove_file(self.root.join("transaction.json")).map_err(|_| INVALID)?;
        let _ = fs::remove_file(self.root.join("ready.json"));
        Ok(changed)
    }
}
pub fn bundle_hash(app: &Path) -> Result<String, String> {
    use std::{
        ffi::{CStr, CString},
        os::unix::ffi::OsStrExt,
    };
    unsafe extern "C" {
        fn fox_bundle_hash(path: *const libc::c_char, out: *mut libc::c_char) -> i32;
    }
    let path = CString::new(app.as_os_str().as_bytes()).map_err(|_| INVALID)?;
    let mut hash = [0i8; 41];
    if unsafe { fox_bundle_hash(path.as_ptr(), hash.as_mut_ptr()) } != 1 {
        return Err(INVALID.into());
    }
    let hash = unsafe { CStr::from_ptr(hash.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    if !hash_valid(&hash) {
        return Err(INVALID.into());
    }
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding(version: &str, c: char) -> Binding {
        Binding {
            protocol: crate::network_helper::PROTOCOL,
            version: version.into(),
            owner: 501,
            current: c.to_string().repeat(40),
            previous: None,
            archive_sha256: c.to_string().repeat(64),
        }
    }
    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store {
            root: dir.path().to_owned(),
            file_uid: unsafe { libc::getuid() },
            uploads: dir.path().join("uploads"),
        };
        fs::create_dir(store.slot()).unwrap();
        write_json(&store.slot().join("binding.json"), &binding("0.1.23", 'a')).unwrap();
        write_json(
            &store.root.join("floor.json"),
            &Floor {
                version: "0.1.23".into(),
                sha256: "a".repeat(64),
            },
        )
        .unwrap();
        (dir, store)
    }
    fn transaction(store: &Store) -> Transaction {
        let t = Transaction {
            backup: format!("component-backup-{}", uuid::Uuid::new_v4()),
            nonce: uuid::Uuid::new_v4().to_string(),
            version: "0.1.24".into(),
            sha256: "b".repeat(64),
        };
        fs::create_dir(store.root.join(&t.backup)).unwrap();
        let mut b = binding("0.1.24", 'b');
        b.previous = Some("a".repeat(40));
        write_json(&store.root.join(&t.backup).join("binding.json"), &b).unwrap();
        write_json(&store.root.join("transaction.json"), &t).unwrap();
        write_json(
            &store.root.join("floor.json"),
            &Floor {
                version: "0.1.24".into(),
                sha256: t.sha256.clone(),
            },
        )
        .unwrap();
        t
    }
    #[test]
    fn failures_before_and_after_exchange_restore_the_old_slot_without_lowering_floor() {
        for exchanged in [false, true] {
            let (_dir, store) = store();
            let t = transaction(&store);
            if exchanged {
                exchange(&store.slot(), &store.root.join(&t.backup)).unwrap();
            }
            assert_eq!(store.restore(&t).unwrap(), exchanged);
            assert_eq!(store.binding().unwrap().version, "0.1.23");
            assert_eq!(store.floor().unwrap().version, "0.1.24");
            assert!(check_version(&store.floor().unwrap(), "0.1.23", &"a".repeat(64)).is_err());
            assert!(check_version(&store.floor().unwrap(), "0.1.24", &"b".repeat(64)).is_ok());
            assert!(store.transaction().unwrap().is_none());
        }
    }
    #[test]
    fn only_the_new_application_can_finalize_the_transition() {
        let (_dir, store) = store();
        let t = transaction(&store);
        exchange(&store.slot(), &store.root.join(&t.backup)).unwrap();
        assert!(store.finalize(false).is_err());
        assert!(store.binding().unwrap().previous.is_some());
        store.finalize(true).unwrap();
        assert!(store.binding().unwrap().previous.is_none());
        assert!(store.transaction().unwrap().is_none());
        assert!(!store.root.join(&t.backup).exists());
        store.finalize(true).unwrap();
    }
    #[test]
    fn corrupt_transaction_paths_other_owners_and_symlinks_are_rejected() {
        let (_dir, store) = store();
        let mut t = transaction(&store);
        t.backup = "../component".into();
        assert!(store.restore(&t).is_err());
        let t = store.transaction().unwrap().unwrap();
        let mut b = binding("0.1.24", 'b');
        b.owner = 502;
        write_json(&store.root.join(&t.backup).join("binding.json"), &b).unwrap();
        assert!(store.restore(&t).is_err());
        let path = store.slot().join("binding.json");
        let real = path.with_extension("real");
        fs::rename(&path, &real).unwrap();
        std::os::unix::fs::symlink(&real, &path).unwrap();
        assert!(store.binding().is_err());
    }
    #[test]
    fn writable_state_and_concurrent_component_operations_fail_closed() {
        let (_dir, store) = store();
        let lock = store.lock().unwrap();
        assert!(store.lock().is_err());
        drop(lock);
        assert!(store.lock().is_ok());
        fs::set_permissions(
            store.slot().join("binding.json"),
            fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(store.binding().is_err());
    }
    #[test]
    fn cleanup_is_retryable_after_a_crash_between_backup_removal_and_journal_removal() {
        let (_dir, store) = store();
        let t = transaction(&store);
        exchange(&store.slot(), &store.root.join(&t.backup)).unwrap();
        fs::remove_dir_all(store.root.join(&t.backup)).unwrap();
        store.finalize(true).unwrap();
        assert!(store.transaction().unwrap().is_none());
        let (_dir, store) = super::tests::store();
        let t = transaction(&store);
        fs::remove_dir_all(store.root.join(&t.backup)).unwrap();
        assert!(!store.restore(&t).unwrap());
        assert!(store.transaction().unwrap().is_none());
    }
    #[test]
    #[ignore = "Run with FOXVPN_COMPONENT_TEST_ARCHIVE for a signed release newer than 0.1.23; temp files only"]
    fn actual_signed_bundle_is_prepared_without_changing_system_component() {
        let archive = std::env::var("FOXVPN_COMPONENT_TEST_ARCHIVE").unwrap();
        let version = std::env::var("FOXVPN_COMPONENT_TEST_VERSION").unwrap();
        let (_dir, store) = store();
        let mut old = binding("0.1.23", 'a');
        old.owner = unsafe { libc::getuid() };
        write_json(&store.slot().join("binding.json"), &old).unwrap();
        let dropbox = store.uploads.join(old.owner.to_string());
        fs::create_dir_all(&dropbox).unwrap();
        fs::set_permissions(&dropbox, fs::Permissions::from_mode(0o700)).unwrap();
        let input = dropbox.join("foxvpn-update-fixture.tar.gz");
        fs::copy(&archive, &input).unwrap();
        let request = InstallRequest {
            archive: input.to_str().unwrap().into(),
            signature: fs::read_to_string(format!("{archive}.sig")).unwrap(),
            version: version.clone(),
        };
        let slot = store.prepare(&request, &old.current).unwrap().unwrap();
        assert_eq!(slot.binding.version, version);
        assert_eq!(slot.binding.owner, old.owner);
        assert_eq!(slot.binding.previous.as_deref(), Some(old.current.as_str()));
        assert!(slot.backup.join("helper").is_file());
        assert!(slot.backup.join("core").is_file());
        assert_eq!(store.binding().unwrap().version, "0.1.23");
        assert_eq!(store.floor().unwrap().version, "0.1.23");
        let mut wrong = request.clone();
        wrong.archive = archive;
        assert!(store.prepare(&wrong, &old.current).is_err());
        let mut wrong = request;
        wrong.version = "999.0.0".into();
        assert!(store.prepare(&wrong, &old.current).is_err());
    }
}
