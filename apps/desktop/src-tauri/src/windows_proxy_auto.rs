//! A separate unprivileged process owns the proxy lease. Parent pipe closure
//! restores the original configuration, including after forced parent death.
use serde::{Deserialize, Serialize};
use smart_vpn_engine::windows_proxy::Configuration;
use std::path::Path;

#[derive(Serialize, Deserialize)]
struct Journal {
    before: Configuration,
    applied: Configuration,
}
trait Backend {
    fn read(&self) -> Result<Configuration, String>;
    fn write(&self, config: &Configuration) -> Result<(), String>;
}
fn recover(backend: &impl Backend, path: &Path) -> Result<(), String> {
    let journal: Journal = match std::fs::read(path) {
        Ok(bytes) if bytes.len() <= 100_000 => serde_json::from_slice(&bytes)
            .map_err(|_| "Повреждён файл восстановления прокси Windows")?,
        Ok(_) => return Err("Повреждён файл восстановления прокси Windows".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("Не удалось прочитать файл восстановления прокси Windows".into()),
    };
    let current = backend.read()?;
    // Never overwrite a concurrent user/third-party change. Keep every unrelated
    // setting, including PAC URL and bypass list, in the equality check.
    if current == journal.applied {
        backend.write(&journal.before)?;
        if backend.read()? != journal.before {
            return Err("Не удалось подтвердить восстановление прокси Windows".into());
        }
    }
    std::fs::remove_file(path)
        .map_err(|_| "Не удалось завершить восстановление прокси Windows".into())
}
fn acquire(backend: &impl Backend, path: &Path, port: u16) -> Result<(), String> {
    if port < 1024 {
        return Err("Некорректный порт прокси".into());
    }
    recover(backend, path)?;
    let mut before = backend.read()?;
    // Migration from manual foxVPN setup: restoring the same enabled loopback
    // would strand the browser when this core stops. This behavior is disclosed
    // in the explicit consent dialog; retain the address and all other values.
    if before.flags & 2 != 0
        && smart_vpn_engine::windows_proxy::matches_server(&before.server, port)
    {
        before.flags = (before.flags & !2) | 1;
    }
    let journal = Journal {
        applied: before.managed(port),
        before,
    };
    // Durable journal precedes the OS mutation. create_new also prevents silently
    // replacing an unresolved recovery record. Caller holds the user-session lock.
    use std::io::Write;
    let bytes = serde_json::to_vec(&journal).map_err(|_| "Не удалось подготовить прокси")?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "Не удалось сохранить прежние настройки прокси Windows")?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "Не удалось сохранить прежние настройки прокси Windows")?;
    drop(file);
    if let Err(error) = backend.write(&journal.applied) {
        recover(backend, path)?;
        return Err(error);
    }
    if backend.read()? != journal.applied {
        recover(backend, path)?;
        return Err("Windows не подтвердила настройку прокси".into());
    }
    Ok(())
}

#[cfg(windows)]
struct Windows;
#[cfg(windows)]
impl Backend for Windows {
    fn read(&self) -> Result<Configuration, String> {
        smart_vpn_engine::windows_proxy::configuration()
    }
    fn write(&self, config: &Configuration) -> Result<(), String> {
        smart_vpn_engine::windows_proxy::set_configuration(config)
    }
}
#[cfg(windows)]
fn path() -> Result<std::path::PathBuf, String> {
    let base = std::env::var_os("APPDATA")
        .filter(|v| !v.is_empty())
        .ok_or("Не найден каталог данных Windows")?;
    let dir = std::path::PathBuf::from(base).join("ru.smartvpn.router");
    std::fs::create_dir_all(&dir)
        .map_err(|_| "Не удалось открыть каталог восстановления прокси")?;
    Ok(dir.join("windows-proxy-session.json"))
}
#[cfg(windows)]
struct Lock(windows_sys::Win32::Foundation::HANDLE);
#[cfg(windows)]
impl Lock {
    fn acquire(path: &Path) -> Result<Self, String> {
        use windows_sys::Win32::{Foundation::*, System::Threading::*};
        let hash = path
            .to_string_lossy()
            .to_lowercase()
            .encode_utf16()
            .fold(0xcbf29ce484222325u64, |h, c| {
                (h ^ u64::from(c)).wrapping_mul(0x100000001b3)
            });
        let name: Vec<u16> = format!("Global\\foxVPN-Proxy-{hash:016x}")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err("Не удалось защитить настройки прокси Windows".into());
        }
        let result = unsafe { WaitForSingleObject(handle, 0) };
        if result != WAIT_OBJECT_0 && result != WAIT_ABANDONED {
            unsafe {
                CloseHandle(handle);
            }
            return Err("Другая сессия foxVPN управляет прокси Windows".into());
        }
        Ok(Self(handle))
    }
}
#[cfg(windows)]
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::System::Threading::ReleaseMutex(self.0);
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}
#[cfg(windows)]
pub fn guardian() -> Result<(), String> {
    use std::io::{BufRead, Read, Write};
    let path = path()?;
    let _lock = Lock::acquire(&path)?;
    let mut input = std::io::stdin().lock();
    let mut line = String::new();
    Read::by_ref(&mut input)
        .take(128)
        .read_line(&mut line)
        .map_err(|_| "Не удалось прочитать запрос прокси")?;
    let port: Option<u16> =
        serde_json::from_str(&line).map_err(|_| "Некорректный запрос прокси")?;
    if let Some(port) = port {
        acquire(&Windows, &path, port)?;
    } else {
        recover(&Windows, &path)?;
    }
    struct Restore<'a>(&'a Path);
    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            let _ = recover(&Windows, self.0);
        }
    }
    let _restore = port.map(|_| Restore(&path));
    println!("FOXVPN_PROXY_READY");
    std::io::stdout()
        .flush()
        .map_err(|_| "Не удалось подтвердить настройку прокси")?;
    if port.is_some() {
        // No other child inherits this pipe. EOF is reliable on parent death;
        // it does not depend on PID polling or PID reuse.
        let mut end = [0u8; 1];
        let _ = input.read(&mut end);
        recover(&Windows, &path)?;
    }
    Ok(())
}
#[cfg(windows)]
pub struct Session {
    child: std::process::Child,
    recover_on_failure: bool,
}
#[cfg(windows)]
impl Session {
    fn spawn(port: Option<u16>) -> Result<Self, String> {
        use std::{
            io::{BufRead, Write},
            os::windows::process::CommandExt,
            process::Stdio,
        };
        let exe = std::env::current_exe().map_err(|_| "Не найден процесс foxVPN")?;
        let mut command = std::process::Command::new(exe);
        #[cfg(not(test))]
        command.arg("--foxvpn-proxy-guardian");
        #[cfg(test)]
        command.args([
            "--exact",
            "windows_proxy_auto::tests::guardian_probe",
            "--ignored",
            "--nocapture",
        ]);
        let mut child = command
            .creation_flags(0x08000000)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "Не удалось запустить восстановление прокси Windows")?;
        let request = format!(
            "{}\n",
            serde_json::to_string(&port).map_err(|_| "Некорректный запрос прокси")?
        );
        let written = child
            .stdin
            .as_mut()
            .ok_or("Нет канала восстановления прокси")?
            .write_all(request.as_bytes());
        if written.is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Не удалось передать запрос прокси".into());
        }
        let stdout = child.stdout.take().ok_or("Нет ответа компонента прокси")?;
        let (send, recv) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            let mut ready = false;
            for _ in 0..10 {
                let mut line = String::new();
                if !matches!(reader.read_line(&mut line), Ok(n) if n > 0) {
                    break;
                }
                if line.trim().ends_with("FOXVPN_PROXY_READY") {
                    ready = true;
                    break;
                }
            }
            let _ = send.send(ready);
            let _ = std::io::copy(&mut reader, &mut std::io::sink());
        });
        if recv.recv_timeout(std::time::Duration::from_secs(10)) != Ok(true) {
            drop(child.stdin.take());
            let _ = child.kill();
            let _ = child.wait();
            // A timed-out child may have applied the settings. Its durable record
            // is recovered by the next recovery/start attempt under the same lock.
            if port.is_some() {
                let _ = Self::recover();
            }
            return Err("Не удалось настроить прокси Windows; подключение остановлено".into());
        }
        Ok(Self {
            child,
            recover_on_failure: port.is_some(),
        })
    }
    pub fn start(port: u16) -> Result<Self, String> {
        Self::spawn(Some(port))
    }
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
    pub fn recover() -> Result<(), String> {
        let mut process = Self::spawn(None)?;
        process.stop()
    }
    pub fn stop(&mut self) -> Result<(), String> {
        drop(self.child.stdin.take());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    if status.success() {
                        return Ok(());
                    }
                    if self.recover_on_failure {
                        self.recover_on_failure = false;
                        return Self::recover();
                    }
                    return Err(
                        "Не удалось восстановить прокси Windows; проверьте параметры сети".into(),
                    );
                }
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(50))
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    if self.recover_on_failure {
                        self.recover_on_failure = false;
                        return Self::recover();
                    }
                    return Err(
                        "Восстановление прокси Windows не завершено; проверьте параметры сети"
                            .into(),
                    );
                }
            }
        }
    }
}
#[cfg(windows)]
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    struct Fake(RefCell<Configuration>);
    impl Backend for Fake {
        fn read(&self) -> Result<Configuration, String> {
            Ok(self.0.borrow().clone())
        }
        fn write(&self, c: &Configuration) -> Result<(), String> {
            *self.0.borrow_mut() = c.clone();
            Ok(())
        }
    }
    fn before() -> Configuration {
        Configuration {
            flags: 13,
            server: "old.example:8080".into(),
            bypass: "localhost;<local>".into(),
            auto_url: "https://example.invalid/proxy.pac".into(),
        }
    }
    fn fixture() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("foxvpn-proxy-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        dir.join("journal.json")
    }
    #[test]
    fn restores_flags_pac_bypass_and_server_after_normal_or_abandoned_lease() {
        let f = Fake(RefCell::new(before()));
        let p = fixture();
        acquire(&f, &p, 2080).unwrap();
        assert_eq!(f.read().unwrap().flags, 3);
        assert_eq!(f.read().unwrap().server, "127.0.0.1:2080");
        recover(&f, &p).unwrap();
        assert_eq!(f.read().unwrap(), before());
        acquire(&f, &p, 2000).unwrap(); // journal simulates killed guardian
        acquire(&f, &p, 2081).unwrap();
        recover(&f, &p).unwrap();
        assert_eq!(f.read().unwrap(), before());
        std::fs::remove_dir(p.parent().unwrap()).unwrap();
    }
    #[test]
    fn preserves_external_proxy_changes_including_only_bypass_change() {
        let f = Fake(RefCell::new(before()));
        let p = fixture();
        acquire(&f, &p, 2080).unwrap();
        f.0.borrow_mut().bypass = "user-change".into();
        let changed = f.read().unwrap();
        recover(&f, &p).unwrap();
        assert_eq!(f.read().unwrap(), changed);
        assert!(!p.exists());
        std::fs::remove_dir(p.parent().unwrap()).unwrap();
    }
    #[test]
    fn corrupt_journal_blocks_mutation() {
        let f = Fake(RefCell::new(before()));
        let p = fixture();
        std::fs::write(&p, "corrupt").unwrap();
        assert!(acquire(&f, &p, 2080).is_err());
        assert_eq!(f.read().unwrap(), before());
        std::fs::remove_file(&p).unwrap();
        std::fs::remove_dir(p.parent().unwrap()).unwrap();
    }
    #[test]
    fn notification_failure_after_apply_rolls_back_original_configuration() {
        struct Fault(Fake, std::cell::Cell<bool>);
        impl Backend for Fault {
            fn read(&self) -> Result<Configuration, String> {
                self.0.read()
            }
            fn write(&self, c: &Configuration) -> Result<(), String> {
                self.0.write(c)?;
                if self.1.replace(false) {
                    Err("notification failed".into())
                } else {
                    Ok(())
                }
            }
        }
        let f = Fault(Fake(RefCell::new(before())), std::cell::Cell::new(true));
        let p = fixture();
        assert!(acquire(&f, &p, 2080).is_err());
        assert_eq!(f.read().unwrap(), before());
        assert!(!p.exists());
        std::fs::remove_dir(p.parent().unwrap()).unwrap();
    }
    #[test]
    fn journal_write_failure_does_not_change_windows() {
        let f = Fake(RefCell::new(before()));
        let p = fixture();
        let missing = p.parent().unwrap().join("missing/journal.json");
        assert!(acquire(&f, &missing, 2080).is_err());
        assert_eq!(f.read().unwrap(), before());
        std::fs::remove_dir(p.parent().unwrap()).unwrap();
    }
    #[test]
    fn previously_manual_foxvpn_proxy_is_disabled_on_disconnect() {
        let mut config = before().managed(2080);
        config.flags = 11;
        let f = Fake(RefCell::new(config.clone()));
        let p = fixture();
        acquire(&f, &p, 2080).unwrap();
        recover(&f, &p).unwrap();
        config.flags = 9;
        assert_eq!(f.read().unwrap(), config);
        std::fs::remove_dir(p.parent().unwrap()).unwrap();
    }
    #[cfg(windows)]
    #[test]
    #[ignore = "subprocess entry point, invoked only by the explicit Windows proxy test"]
    fn guardian_probe() {
        guardian().unwrap();
    }
    #[cfg(windows)]
    #[test]
    #[ignore = "subprocess entry point, killed by the explicit Windows proxy test"]
    fn parent_probe() {
        use std::io::Write;
        assert_eq!(
            std::env::var("FOXVPN_TEST_ALLOW_SYSTEM_PROXY").as_deref(),
            Ok("1")
        );
        let _session = Session::start(2080).unwrap();
        println!("FOXVPN_TEST_PARENT_READY");
        std::io::stdout().flush().unwrap();
        loop {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    #[cfg(windows)]
    #[test]
    #[ignore = "changes disposable runner proxy; requires FOXVPN_TEST_ALLOW_SYSTEM_PROXY=1"]
    fn windows_real_proxy_restore_and_parent_death() {
        use std::{
            io::BufRead,
            process::{Command, Stdio},
            time::{Duration, Instant},
        };
        assert_eq!(
            std::env::var("FOXVPN_TEST_ALLOW_SYSTEM_PROXY").as_deref(),
            Ok("1")
        );
        let original = Windows.read().unwrap();
        let temp =
            std::env::temp_dir().join(format!("foxvpn-native-proxy-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&temp).unwrap();
        struct Cleanup(
            Configuration,
            std::path::PathBuf,
            Option<std::ffi::OsString>,
        );
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = Windows.write(&self.0);
                match self.2.take() {
                    Some(v) => std::env::set_var("APPDATA", v),
                    None => std::env::remove_var("APPDATA"),
                }
                let _ = std::fs::remove_dir_all(&self.1);
            }
        }
        let _cleanup = Cleanup(original.clone(), temp.clone(), std::env::var_os("APPDATA"));
        std::env::set_var("APPDATA", &temp);
        let mut session = Session::start(2080).unwrap();
        assert_eq!(Windows.read().unwrap(), original.managed(2080));
        session.stop().unwrap();
        assert_eq!(Windows.read().unwrap(), original);
        let mut session = Session::start(2080).unwrap();
        let mut external = Windows.read().unwrap();
        external.server = "127.0.0.1:2081".into();
        Windows.write(&external).unwrap();
        session.stop().unwrap();
        assert_eq!(Windows.read().unwrap(), external);
        Windows.write(&original).unwrap();
        let mut parent = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows_proxy_auto::tests::parent_probe",
                "--ignored",
                "--nocapture",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = parent.stdout.take().unwrap();
        let (send, recv) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let found = std::io::BufReader::new(stdout)
                .lines()
                .take(10)
                .any(|s| s.is_ok_and(|s| s.ends_with("FOXVPN_TEST_PARENT_READY")));
            let _ = send.send(found);
        });
        if recv.recv_timeout(Duration::from_secs(15)) != Ok(true) {
            let _ = parent.kill();
            let _ = parent.wait();
            panic!("proxy parent did not start");
        }
        assert_eq!(Windows.read().unwrap(), original.managed(2080));
        parent.kill().unwrap();
        parent.wait().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while (Windows.read().unwrap() != original || path().unwrap().exists())
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(Windows.read().unwrap(), original);
        assert!(!path().unwrap().exists());
    }
}
