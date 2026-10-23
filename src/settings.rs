use crate::{
    routing::{Mode, Rule},
    servers::Server,
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub windows_excluded_apps: Vec<crate::app_routes::Application>,
    pub excluded_apps: Vec<crate::app_routes::Application>,
    pub mode: Mode,
    pub tun: bool,
    pub kill_switch: bool,
    pub proxy_acknowledged: bool,
    pub windows_proxy_auto: Option<bool>,
    pub proxy_port: u16,
    pub dns_protection: bool,
    pub dns_provider: String,
    pub dns_transport: String,
    pub auto_connect: bool,
    pub start_minimized: bool,
    pub restore: bool,
    pub health_interval: u64,
    pub auto_metrics: bool,
    pub metric_interval: u64,
    pub failover: bool,
    pub favorites_only: bool,
    pub strategy: String,
    pub subscription_interval: u64,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            excluded_apps: vec![],
            windows_excluded_apps: vec![],
            mode: Mode::Smart,
            tun: true,
            kill_switch: true,
            proxy_acknowledged: false,
            windows_proxy_auto: None,
            proxy_port: 2080,
            dns_protection: true,
            dns_provider: "cloudflare".into(),
            dns_transport: "https".into(),
            auto_connect: false,
            start_minimized: false,
            restore: true,
            health_interval: 30,
            auto_metrics: true,
            metric_interval: 600,
            failover: true,
            favorites_only: false,
            strategy: "balanced".into(),
            subscription_interval: 21600,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<(), String> {
        crate::app_routes::validate(&self.excluded_apps)?;
        crate::app_routes::validate_windows(&self.windows_excluded_apps)?;
        if !(60..=3600).contains(&self.metric_interval) {
            return Err(crate::text("metric_interval_invalid").into());
        }
        if self.proxy_port < 1024 {
            return Err(crate::text("proxy_port_invalid").into());
        }
        if !(10..=3600).contains(&self.health_interval) {
            return Err(crate::text("message_285").into());
        }
        if !["cloudflare", "google", "quad9"].contains(&self.dns_provider.as_str()) {
            return Err(crate::text("message_286").into());
        }
        if !["https", "tls", "local"].contains(&self.dns_transport.as_str()) {
            return Err(crate::text("message_287").into());
        }
        if self.dns_protection && self.dns_transport == "local" {
            return Err(crate::text("message_288").into());
        }
        if !["balanced", "latency", "speed", "stability", "random"]
            .contains(&self.strategy.as_str())
        {
            return Err(crate::text("message_289").into());
        }
        if ![0, 3600, 21600, 43200, 86400].contains(&self.subscription_interval) {
            return Err(crate::text("message_290").into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    pub updated_at: Option<u64>,
    pub server_count: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Profile {
    pub version: u32,
    pub servers: Vec<Server>,
    pub selected: Option<String>,
    pub rules: Vec<Rule>,
    pub settings: Settings,
    pub subscriptions: Vec<Subscription>,
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            version: 1,
            servers: vec![],
            selected: None,
            rules: vec![],
            settings: Settings::default(),
            subscriptions: vec![],
        }
    }
}
impl Profile {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err(crate::text("message_291").into());
        }
        if self.servers.len() > 5000 || self.rules.len() > 5000 {
            return Err(crate::text("message_292").into());
        }
        self.settings.validate()?;
        crate::routing::validate(&self.rules)?;
        let mut ids = std::collections::HashSet::new();
        for s in &self.servers {
            let check = Server::parse(&s.uri()?)?;
            if check.uuid != s.uuid
                || check.address != s.address
                || check.port != s.port
                || check.transport != s.transport
                || check.security != s.security
            {
                return Err(crate::text("message_293").into());
            }
            if !ids.insert(&s.id) {
                return Err(crate::text("message_294").into());
            }
        }
        if let Some(id) = &self.selected {
            if !ids.contains(id) {
                return Err(crate::text("message_295").into());
            }
        }
        for sub in &self.subscriptions {
            crate::subscriptions::validate_url(&sub.url)?;
        }
        Ok(())
    }
}
/// All persisted user configuration participates in freshness checks. Only
/// observations updated in the background are excluded, and must be merged
/// from the latest profile when applying/restoring a configuration.
pub fn configuration_digest(profile: &Profile) -> Result<String, String> {
    let mut stable = profile.clone();
    for server in &mut stable.servers {
        server.latency_ms = None;
        server.download_mbps = None;
        server.status.clear();
        server.successes = 0;
        server.failures = 0;
        server.last_error = None;
    }
    for subscription in &mut stable.subscriptions {
        subscription.updated_at = None;
        subscription.server_count = 0;
    }
    let bytes = serde_json::to_vec(&stable).map_err(|_| crate::text("message_302"))?;
    use sha2::{Digest, Sha256};
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;
use zeroize::Zeroizing;

// One successful OS credential read per Vault/session. Failed or denied reads
// remain retryable. The mutex also prevents concurrent first saves creating
// different master keys. Never serialize this cache or expose it over IPC.
#[derive(Default)]
struct SessionKey(std::sync::Mutex<Option<Zeroizing<[u8; 32]>>>);
impl SessionKey {
    fn get(
        &self,
        read: impl FnOnce() -> Result<Zeroizing<[u8; 32]>, String>,
    ) -> Result<Zeroizing<[u8; 32]>, String> {
        let mut cached = self.0.lock().map_err(|_| crate::text("message_296"))?;
        if cached.is_none() {
            *cached = Some(read()?);
        }
        Ok(Zeroizing::new(**cached.as_ref().unwrap()))
    }
}
const MAX_PRIVATE_PLAIN: usize = 32 * 1024 * 1024;
const MAX_PRIVATE_FILE: u64 = MAX_PRIVATE_PLAIN as u64 + 32;
fn check_private_file(metadata: &std::fs::Metadata, max_size: u64) -> Result<(), String> {
    if !metadata.is_file() || metadata.len() > max_size {
        return Err("Неверный тип или размер защищённых данных".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o600 {
            return Err("Защищённые данные имеют неверного владельца или права доступа".into());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("Защищённые данные заменены ссылкой".into());
        }
    }
    Ok(())
}
fn check_private_parent(path: &std::path::Path) -> Result<(), String> {
    let parent = path.parent().ok_or("Нет каталога защищённых данных")?;
    let metadata = match std::fs::symlink_metadata(parent) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("Не удалось проверить каталог защищённых данных".into()),
    };
    if !metadata.is_dir() {
        return Err("Каталог защищённых данных отсутствует или заменён ссылкой".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            return Err(
                "Каталог защищённых данных имеет неверного владельца или права доступа".into(),
            );
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("Каталог защищённых данных заменён ссылкой".into());
        }
    }
    Ok(())
}
fn read_private_file(path: &std::path::Path) -> Result<Option<Vec<u8>>, String> {
    check_private_parent(path)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("Не удалось открыть защищённые данные".into()),
    };
    check_private_file(
        &file
            .metadata()
            .map_err(|_| "Не удалось проверить защищённые данные")?,
        MAX_PRIVATE_FILE,
    )?;
    use std::io::Read;
    let mut bytes = Vec::new();
    file.take(MAX_PRIVATE_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Не удалось прочитать защищённые данные")?;
    if bytes.len() as u64 > MAX_PRIVATE_FILE {
        return Err("Защищённые данные превышают допустимый размер".into());
    }
    Ok(Some(bytes))
}
pub struct ConfigurationLock {
    file: std::fs::File,
    path: std::path::PathBuf,
}
impl ConfigurationLock {
    fn validate_current(&self) -> Result<(), String> {
        check_private_parent(&self.path)?;
        let opened = self
            .file
            .metadata()
            .map_err(|_| "Не удалось проверить блокировку настроек")?;
        let current = std::fs::symlink_metadata(&self.path)
            .map_err(|_| "Блокировка настроек исчезла или была заменена")?;
        check_private_file(&opened, 0)?;
        check_private_file(&current, 0)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if opened.dev() != current.dev() || opened.ino() != current.ino() {
                return Err("Блокировка настроек была заменена. Изменения не сохранялись".into());
            }
        }
        // Windows lock handles are opened without delete sharing: replacing the
        // locked pathname is denied by the kernel until this lease is dropped.
        Ok(())
    }
}
impl Drop for ConfigurationLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe {
                libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            let mut overlapped = unsafe { std::mem::zeroed() };
            unsafe {
                windows_sys::Win32::Storage::FileSystem::UnlockFileEx(
                    self.file.as_raw_handle(),
                    0,
                    1,
                    0,
                    &mut overlapped,
                );
            }
        }
    }
}
pub struct Vault {
    service: String,
    path: std::path::PathBuf,
    key: SessionKey,
}
impl Vault {
    pub fn new(service: &str) -> Self {
        #[cfg(target_os = "macos")]
        let base = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_default()
            .join("Library/Application Support");
        #[cfg(windows)]
        let base = std::env::var_os("APPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_default();
        #[cfg(not(any(target_os = "macos", windows)))]
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::env::var_os("HOME")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_default()
                    .join(".local/share")
            });
        Self {
            service: service.into(),
            path: base.join(service).join("profile.enc"),
            key: SessionKey::default(),
        }
    }
    /// Test-only private storage with a caller-owned temporary path and public
    /// fixture key. Exercises production encryption/atomic writes, not Keychain.
    #[cfg(feature = "test-support")]
    pub fn test_fixture(path: std::path::PathBuf, key: [u8; 32]) -> Self {
        Self {
            service: "foxvpn-public-test-fixture".into(),
            path,
            key: SessionKey(std::sync::Mutex::new(Some(Zeroizing::new(key)))),
        }
    }
    fn key(&self, create: bool) -> Result<Zeroizing<[u8; 32]>, String> {
        self.key.get(|| self.read_key(create))
    }
    fn read_key(&self, create: bool) -> Result<Zeroizing<[u8; 32]>, String> {
        let e = keyring::Entry::new(&self.service, "master-key")
            .map_err(|_| crate::text("message_296"))?;
        match e.get_password() {
            Ok(value) => {
                let value = Zeroizing::new(value);
                let bytes = Zeroizing::new(
                    STANDARD
                        .decode(value.as_bytes())
                        .map_err(|_| crate::text("message_297"))?,
                );
                let key: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| crate::text("message_297"))?;
                Ok(Zeroizing::new(key))
            }
            Err(keyring::Error::NoEntry) if create => {
                let mut key = Zeroizing::new([0u8; 32]);
                rand::rngs::OsRng.fill_bytes(key.as_mut());
                let encoded = Zeroizing::new(STANDARD.encode(key.as_ref()));
                e.set_password(&encoded)
                    .map_err(|_| crate::text("message_298"))?;
                Ok(key)
            }
            Err(_) => Err(crate::text("message_299").into()),
        }
    }
    pub fn load(&self) -> Result<Profile, String> {
        let Some(data) = read_private_file(&self.path)? else {
            return Ok(Profile::default());
        };
        if data.len() < 32 || &data[..4] != b"SVP1" {
            return Err(crate::text("message_301").into());
        }
        let plain = Zeroizing::new(decrypt_profile(&*self.key(false)?, &data)?);
        serde_json::from_slice(&plain).map_err(|_| crate::text("message_301").into())
    }
    pub fn lock_configuration(&self) -> Result<ConfigurationLock, String> {
        let path = self.path.with_file_name("configuration.lock");
        let parent = path.parent().ok_or("Нет каталога настроек")?;
        std::fs::create_dir_all(parent).map_err(|_| "Не удалось создать каталог настроек")?;
        check_private_parent(&path)?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x00200000).share_mode(0x1 | 0x2);
        }
        let file = options
            .open(&path)
            .map_err(|_| "Не удалось получить блокировку настроек")?;
        let meta = file
            .metadata()
            .map_err(|_| "Не удалось проверить блокировку")?;
        check_private_file(&meta, 0)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err("Настройки изменяет другое окно foxVPN. Дождитесь завершения".into());
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            let mut overlapped = unsafe { std::mem::zeroed() };
            if unsafe {
                windows_sys::Win32::Storage::FileSystem::LockFileEx(
                    file.as_raw_handle(),
                    3,
                    0,
                    1,
                    0,
                    &mut overlapped,
                )
            } == 0
            {
                return Err("Настройки изменяет другое окно foxVPN. Дождитесь завершения".into());
            }
        }
        let lock = ConfigurationLock { file, path };
        lock.validate_current()?;
        Ok(lock)
    }
    fn setup_recovery_path(&self) -> std::path::PathBuf {
        self.path.with_file_name("setup-recovery.enc")
    }
    pub fn save_setup_recovery(
        &self,
        record: &crate::setup_recovery::Record,
    ) -> Result<(), String> {
        record.validate()?;
        let plain = Zeroizing::new(
            serde_json::to_vec(record).map_err(|_| "Не удалось подготовить журнал настройки")?,
        );
        if plain.len() > MAX_PRIVATE_PLAIN {
            return Err("Журнал настройки превышает допустимый размер".into());
        }
        use aes_gcm::aead::Payload;
        let key = self.key(true)?;
        let cipher =
            Aes256Gcm::new_from_slice(&*key).map_err(|_| "Не удалось защитить журнал настройки")?;
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: b"foxVPN/setup-recovery/v1",
                },
            )
            .map_err(|_| "Не удалось защитить журнал настройки")?;
        let mut bytes = b"SVR1".to_vec();
        bytes.extend_from_slice(&nonce);
        bytes.extend(encrypted);
        atomic_private_write(&self.setup_recovery_path(), &bytes)
    }
    pub fn load_setup_recovery(&self) -> Result<Option<crate::setup_recovery::Record>, String> {
        let Some(bytes) = read_private_file(&self.setup_recovery_path())? else {
            return Ok(None);
        };
        if bytes.len() < 32 || bytes.len() as u64 > MAX_PRIVATE_FILE || &bytes[..4] != b"SVR1" {
            return Err("Журнал настройки не прошёл проверку".into());
        }
        use aes_gcm::aead::Payload;
        let key = self.key(false)?;
        let cipher = Aes256Gcm::new_from_slice(&*key)
            .map_err(|_| "Не удалось прочитать журнал настройки")?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&bytes[4..16]),
                    Payload {
                        msg: &bytes[16..],
                        aad: b"foxVPN/setup-recovery/v1",
                    },
                )
                .map_err(|_| "Журнал настройки не прошёл проверку целостности")?,
        );
        let record: crate::setup_recovery::Record =
            serde_json::from_slice(&plain).map_err(|_| "Журнал настройки повреждён")?;
        record.validate()?;
        Ok(Some(record))
    }
    pub fn clear_setup_recovery(&self) -> Result<(), String> {
        let path = self.setup_recovery_path();
        match std::fs::remove_file(&path) {
            Ok(()) => sync_parent(&path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err("Не удалось завершить журнал настройки".into()),
        }
    }
    pub fn save(&self, p: &Profile) -> Result<(), String> {
        let lock = self.lock_configuration()?;
        self.save_locked(p, &lock)
    }
    pub fn save_locked(&self, p: &Profile, lock: &ConfigurationLock) -> Result<(), String> {
        if lock.path != self.path.with_file_name("configuration.lock") {
            return Err("Блокировка относится к другому профилю".into());
        }
        lock.validate_current()?;
        p.validate()?;
        let plain = Zeroizing::new(serde_json::to_vec(p).map_err(|_| crate::text("message_302"))?);
        if plain.len() > MAX_PRIVATE_PLAIN {
            return Err("Профиль превышает допустимый размер".into());
        }
        let data = encrypt_profile(&*self.key(true)?, &plain)?;
        lock.validate_current()?;
        atomic_private_write(&self.path, &data)
    }
}

fn sync_parent(path: &std::path::Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        std::fs::File::open(path.parent().ok_or("Нет каталога защищённых данных")?)
            .and_then(|f| f.sync_all())
            .map_err(|_| "Не удалось подтвердить запись защищённых данных")?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
fn atomic_private_write(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    let dir = path.parent().ok_or(crate::text("message_303"))?;
    std::fs::create_dir_all(dir).map_err(|_| crate::text("message_304"))?;
    check_private_parent(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| crate::text("message_305"))?;
    }
    let temp = dir.join(format!("private-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .map_err(|_| crate::text("message_306"))?;
        file.write_all(data)
            .and_then(|_| file.sync_all())
            .map_err(|_| crate::text("message_306"))?;
        drop(file);
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            #[link(name = "kernel32")]
            unsafe extern "system" {
                fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
            }
            let source: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
            let target: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            if unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), 1 | 8) } == 0 {
                return Err(crate::text("message_302").into());
            }
        }
        #[cfg(not(windows))]
        std::fs::rename(&temp, path).map_err(|_| crate::text("message_302"))?;
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}

#[cfg(test)]
mod session_key_tests {
    use super::SessionKey;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use zeroize::Zeroizing;

    #[test]
    fn concurrent_operations_read_os_credential_once() {
        let cache = Arc::new(SessionKey::default());
        let reads = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            for _ in 0..16 {
                let cache = Arc::clone(&cache);
                let reads = Arc::clone(&reads);
                scope.spawn(move || {
                    for _ in 0..10 {
                        let key = cache
                            .get(|| {
                                reads.fetch_add(1, Ordering::SeqCst);
                                Ok(Zeroizing::new([42; 32]))
                            })
                            .unwrap();
                        assert_eq!(*key, [42; 32]);
                    }
                });
            }
        });
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn denial_is_retryable_and_never_replaces_an_existing_key() {
        let cache = SessionKey::default();
        assert!(cache.get(|| Err("denied".into())).is_err());
        assert_eq!(*cache.get(|| Ok(Zeroizing::new([7; 32]))).unwrap(), [7; 32]);
        assert_eq!(
            *cache.get(|| panic!("must not read the OS again")).unwrap(),
            [7; 32]
        );
    }
}
pub fn encrypt_profile(key: &[u8; 32], plain: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| crate::text("message_308"))?;
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce), plain)
        .map_err(|_| crate::text("message_309"))?;
    let mut data = b"SVP1".to_vec();
    data.extend_from_slice(&nonce);
    data.extend(encrypted);
    Ok(data)
}
pub fn decrypt_profile(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 32 || &data[..4] != b"SVP1" {
        return Err(crate::text("message_301").into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| crate::text("message_308"))?;
    cipher
        .decrypt(Nonce::from_slice(&data[4..16]), &data[16..])
        .map_err(|_| crate::text("message_310").into())
}

/// A legacy profile is never silently downgraded to an unprotected local proxy.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionPlan {
    NeedsServer,
    NeedsProxyConsent,
    Ready,
}
pub fn connection_plan(profile: &Profile) -> ConnectionPlan {
    if !profile
        .servers
        .iter()
        .any(|server| Some(&server.id) == profile.selected.as_ref())
    {
        return ConnectionPlan::NeedsServer;
    }
    if profile.settings.tun
        || profile.settings.kill_switch
        || !profile.settings.proxy_acknowledged
        || (cfg!(windows) && profile.settings.windows_proxy_auto.is_none())
    {
        return ConnectionPlan::NeedsProxyConsent;
    }
    ConnectionPlan::Ready
}
/// The installed, authenticated helper supplies the protected TUN capability.
pub fn connection_plan_with_helper(profile: &Profile, helper_available: bool) -> ConnectionPlan {
    let plan = connection_plan(profile);
    if plan != ConnectionPlan::NeedsServer && profile.settings.tun && helper_available {
        ConnectionPlan::Ready
    } else {
        plan
    }
}
pub fn prepare_proxy(profile: &Profile, expected_selected: &str) -> Result<Profile, String> {
    if profile.selected.as_deref() != Some(expected_selected)
        || !profile
            .servers
            .iter()
            .any(|server| server.id == expected_selected)
    {
        return Err(crate::text("proxy_server_changed").into());
    }
    let mut next = profile.clone();
    next.settings.tun = false;
    next.settings.kill_switch = false;
    next.settings.proxy_acknowledged = true;
    if cfg!(windows) && next.settings.windows_proxy_auto.is_none() {
        next.settings.windows_proxy_auto = Some(false);
    }
    next.validate()?;
    Ok(next)
}
