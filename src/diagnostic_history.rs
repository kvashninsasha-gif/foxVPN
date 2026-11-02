//! Bounded, typed history. Never accepts URLs, profile identifiers or raw logs.
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
const LIMIT: usize = 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Code {
    Started,
    Stopped,
    StartFailed,
    DnsFailed,
    HttpsFailed,
    ProxyHttpsFailed,
    SystemHttpsFailed,
    CoreExited,
    IdentityChannelLost,
    SystemRouteLost,
    NetworkChanged,
    Recovered,
    RestartFailed,
}
impl Code {
    fn text(self) -> &'static str {
        match self {
            Self::Started => "VPN подключён",
            Self::Stopped => "VPN отключён пользователем",
            Self::StartFailed => "Не удалось запустить VPN",
            Self::DnsFailed => "Не удалось настроить системный DNS",
            Self::ProxyHttpsFailed => "HTTPS через локальный прокси не прошёл проверку",
            Self::SystemHttpsFailed => "HTTPS через системный туннель не прошёл проверку",
            Self::HttpsFailed => "Контрольные HTTPS-запросы не прошли",
            Self::CoreExited => "Ядро VPN завершилось",
            Self::IdentityChannelLost => "Служебный канал проверки приложений недоступен",
            Self::SystemRouteLost => "Системный маршрут обходит туннель foxVPN",
            Self::NetworkChanged => "Сеть изменилась; подключение перепроверяется",
            Self::Recovered => "Связь восстановлена",
            Self::RestartFailed => "Повторное подключение не удалось",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    time: u64,
    code: Code,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    owner: u32,
    events: Vec<Event>,
}
pub struct History {
    path: PathBuf,
    uid: u32,
    owner: u32,
    events: Vec<Event>,
    failed: bool,
}
impl History {
    pub fn open(path: PathBuf, uid: u32, owner: u32) -> Self {
        let mut this = Self {
            path,
            uid,
            owner,
            events: vec![],
            failed: false,
        };
        match this.read() {
            Ok(events) => this.events = events,
            Err(_) => this.failed = true,
        }
        this
    }
    #[cfg(unix)]
    fn safe_parent(&self) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let parent = self.path.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
        let m = fs::symlink_metadata(parent)?;
        if !m.is_dir() || m.uid() != self.uid || m.mode() & 0o022 != 0 {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    fn safe_parent(&self) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
    fn read(&self) -> std::io::Result<Vec<Event>> {
        self.safe_parent()?;
        match fs::symlink_metadata(&self.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e),
            Ok(m) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if !m.is_file()
                        || m.uid() != self.uid
                        || m.mode() & 0o077 != 0
                        || m.nlink() != 1
                    {
                        return Err(std::io::ErrorKind::PermissionDenied.into());
                    }
                }
                if m.len() > 32768 {
                    return Err(std::io::ErrorKind::InvalidData.into());
                }
            }
        }
        let mut bytes = vec![];
        fs::File::open(&self.path)?
            .take(32769)
            .read_to_end(&mut bytes)?;
        let envelope: Envelope =
            serde_json::from_slice(&bytes).map_err(|_| std::io::ErrorKind::InvalidData)?;
        if envelope.owner != self.owner {
            return Ok(vec![]);
        }
        let events = envelope.events;
        if events.len() > LIMIT {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        Ok(events)
    }
    fn persist(&self) -> std::io::Result<()> {
        self.safe_parent()?;
        // Refuse unsafe existing targets; the final rename never follows links.
        if self.path.exists() || self.path.is_symlink() {
            self.read()?;
        }
        let parent = self.path.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temp.as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        let bytes = serde_json::to_vec(&Envelope {
            owner: self.owner,
            events: self.events.clone(),
        })?;
        temp.write_all(&bytes)?;
        temp.as_file().sync_all()?;
        temp.persist(&self.path).map_err(|e| e.error)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
    pub fn record(&mut self, code: Code) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if self
            .events
            .last()
            .is_some_and(|e| e.code == code && now.saturating_sub(e.time) < 10)
        {
            return;
        }
        self.events.push(Event { time: now, code });
        if self.events.len() > LIMIT {
            self.events.remove(0);
        }
        self.failed = self.persist().is_err();
    }
    pub fn lines(&self) -> Vec<String> {
        let mut lines: Vec<_> = self
            .events
            .iter()
            .map(|e| format!("История [{}]: {}", e.time, e.code.text()))
            .collect();
        if self.failed {
            lines.push("История: не удалось сохранить или прочитать журнал; текущие сетевые настройки не изменены".into())
        }
        lines
    }
}
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn history_is_scoped_to_the_component_owner() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("history.json");
        let uid = unsafe { libc::geteuid() };
        let mut old = History::open(p.clone(), uid, 501);
        old.record(Code::HttpsFailed);
        let mut next = History::open(p.clone(), uid, 502);
        assert!(next.lines().is_empty());
        next.record(Code::Started);
        assert!(History::open(p, uid, 501).lines().is_empty());
    }
    #[test]
    fn survives_stop_reopen_and_keeps_reason_without_private_strings() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("history.json");
        let uid = unsafe { libc::geteuid() };
        let mut h = History::open(p.clone(), uid, uid);
        h.record(Code::IdentityChannelLost);
        h.record(Code::Recovered);
        h.record(Code::Stopped);
        let text = fs::read_to_string(&p).unwrap();
        assert!(!text.contains("http"));
        assert!(!text.contains("server"));
        let h = History::open(p, uid, uid);
        assert_eq!(h.events.len(), 3);
        assert!(h.lines()[0].contains("проверки приложений"));
        assert!(h.lines()[2].contains("отключён"));
    }
    #[test]
    fn bounded_and_duplicate_failures_do_not_grow_or_disclose_payloads() {
        let d = tempfile::tempdir().unwrap();
        let mut h = History::open(
            d.path().join("history.json"),
            unsafe { libc::geteuid() },
            501,
        );
        h.record(Code::HttpsFailed);
        h.record(Code::HttpsFailed);
        assert_eq!(h.events.len(), 1);
        for _ in 0..100 {
            h.record(Code::Started);
            h.record(Code::Stopped)
        }
        assert_eq!(h.events.len(), LIMIT);
    }
    #[test]
    fn unsafe_or_corrupt_history_does_not_block_network_but_is_visible() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let d = tempfile::tempdir().unwrap();
        let uid = unsafe { libc::geteuid() };
        let p = d.path().join("history.json");
        let other = d.path().join("original");
        fs::write(&other, "preserved").unwrap();
        symlink(&other, &p).unwrap();
        let mut h = History::open(p.clone(), uid, uid);
        h.record(Code::Started);
        assert!(h.failed);
        assert_eq!(fs::read_to_string(&other).unwrap(), "preserved");
        fs::remove_file(&p).unwrap();
        fs::write(&p, b"malformed PRIVATE_URI").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        let h = History::open(p, uid, uid);
        assert!(h.failed);
        assert!(!h.lines().join(" ").contains("PRIVATE_URI"));
    }
}
