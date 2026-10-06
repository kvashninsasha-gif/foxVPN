//! Typed, bounded IPC. The root daemon authenticates the client's macOS audit
//! token against the UID and CDHash installed by the user-approved package.
use crate::{routing::Rule, servers::Server, settings::Settings};
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartRequest {
    pub server: Server,
    #[serde(default)]
    pub reserves: Vec<Server>,
    pub settings: Settings,
    pub rules: Vec<Rule>,
}
#[derive(Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Request {
    Status,
    Start(Box<StartRequest>),
    Stop,
    Logs,
    TestRecovery,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Status {
    pub protocol: u32,
    pub helper_version: String,
    pub core_alive: bool,
    pub dns_active: bool,
    pub running: bool,
    pub wanted: bool,
    pub proxy_port: u16,
    pub api_port: u16,
    pub secret: String,
    pub error: Option<String>,
    pub kill_switch: bool,
    pub interface: String,
    pub active_server_id: Option<String>,
}
pub const PROTOCOL: u32 = 3;
impl Status {
    pub fn compatible(&self) -> bool {
        self.protocol == PROTOCOL && self.helper_version == env!("CARGO_PKG_VERSION")
    }
    pub fn stopped(&self) -> bool {
        self.compatible()
            && !self.running
            && !self.core_alive
            && !self.wanted
            && !self.kill_switch
            && !self.dns_active
    }
    pub fn connection_state(&self) -> &'static str {
        if !self.compatible() {
            "unknown"
        } else if self.running {
            "connected"
        } else if self.wanted {
            "reconnecting"
        } else if self.stopped() {
            "disconnected"
        } else {
            "unknown"
        }
    }
}
/// Installing or updating the package restarts the daemon, so a check that runs
/// immediately afterwards must be allowed to wait instead of reporting an
/// outdated component.
pub const START_WAIT: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(target_os = "macos")]
const PROBE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Result of checking the installed network component.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Probe {
    /// Answers with the expected protocol and version.
    Ready,
    /// The package binds another CDHash/owner, or the daemon speaks an older
    /// protocol or version. Only this state requires reinstalling the component.
    Stale,
    /// The binding is current but the daemon does not answer yet.
    Starting,
    /// No network component is installed.
    Missing,
}
/// Pure decision table, kept separate from the daemon so the difference between
/// "restarting" and "outdated" is covered by tests.
fn classify(installed: bool, mismatch: bool, answer: Option<bool>) -> Probe {
    if !installed {
        Probe::Missing
    } else if mismatch {
        Probe::Stale
    } else {
        match answer {
            Some(true) => Probe::Ready,
            Some(false) => Probe::Stale,
            None => Probe::Starting,
        }
    }
}
#[cfg(target_os = "macos")]
fn probe_status(wait: std::time::Duration) -> (Probe, Option<Status>) {
    if !installed() {
        return (classify(false, false, None), None);
    }
    if binding_mismatch() {
        return (classify(true, true, None), None);
    }
    let deadline = std::time::Instant::now() + wait;
    loop {
        match request_with(&Request::Status, PROBE_READ_TIMEOUT) {
            Ok(response) => {
                let state = classify(true, false, Some(response.status.compatible()));
                return (state, Some(response.status));
            }
            Err(_) if std::time::Instant::now() >= deadline => {
                return (classify(true, false, None), None)
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(300)),
        }
    }
}
#[cfg(not(target_os = "macos"))]
fn probe_status(_: std::time::Duration) -> (Probe, Option<Status>) {
    (classify(false, false, None), None)
}
pub fn probe(wait: std::time::Duration) -> Probe {
    probe_status(wait).0
}
pub fn ready() -> bool {
    probe(std::time::Duration::from_millis(0)) == Probe::Ready
}
#[cfg(target_os = "macos")]
pub fn require_current() -> Result<Status, String> {
    match probe_status(START_WAIT) {
        (Probe::Ready, Some(status)) => Ok(status),
        (Probe::Ready, None) => Err(crate::text("helper_starting").into()),
        (Probe::Stale, _) | (Probe::Missing, _) => Err(crate::text("helper_upgrade").into()),
        (Probe::Starting, _) => Err(crate::text("helper_starting").into()),
    }
}
#[cfg(not(target_os = "macos"))]
pub fn require_current() -> Result<Status, String> {
    Err(crate::text("helper_macos_only").into())
}
/// The installed package binds this app's CDHash and owner UID. A mismatch means
/// a stale component; a matching binding that cannot answer only means the
/// daemon is starting or restarting.
#[cfg(target_os = "macos")]
pub fn binding_mismatch() -> bool {
    let base = std::path::Path::new("/Library/PrivilegedHelperTools/foxVPN");
    let hash = std::fs::read_to_string(base.join("client.cdhash")).ok();
    let owner = std::fs::read_to_string(base.join("client.uid"))
        .ok()
        .and_then(|v| v.trim().parse().ok());
    match self_hash() {
        Ok(mine) => {
            binding_error(hash.as_deref(), owner, &mine, unsafe { libc::getuid() }).is_some()
        }
        Err(_) => false,
    }
}
#[cfg(not(target_os = "macos"))]
pub fn binding_mismatch() -> bool {
    false
}
pub fn installed() -> bool {
    cfg!(target_os = "macos")
        && std::path::Path::new("/Library/PrivilegedHelperTools/ru.smartvpn.router.network")
            .exists()
}
pub fn valid_owner(uid: u32) -> bool {
    uid >= 501 && uid != CORE_UID && uid != u32::MAX && uid != 65534
}
/// A failed CDHash check closes IPC without a response. Diagnose the installed
/// binding first, so migration is not reported as a broken network connection.
pub fn binding_error(
    expected_hash: Option<&str>,
    expected_uid: Option<u32>,
    hash: &str,
    uid: u32,
) -> Option<&'static str> {
    if expected_uid.is_some_and(|owner| owner != uid) {
        Some("helper_owner")
    } else if expected_uid.is_none() || expected_hash != Some(hash) {
        Some("helper_upgrade")
    } else {
        None
    }
}
#[derive(Serialize, Deserialize)]
pub struct Response {
    pub status: Status,
    pub logs: Vec<String>,
    pub error: Option<String>,
}
pub const SOCKET: &str = "/var/run/foxvpn/control.sock";
pub const CORE_UID: u32 = 62077;
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn fox_self_hash(out: *mut std::ffi::c_char) -> i32;
}
#[cfg(target_os = "macos")]
pub fn self_hash() -> Result<String, String> {
    let mut hash = [0i8; 41];
    if unsafe { fox_self_hash(hash.as_mut_ptr()) } != 1 {
        return Err(crate::text("helper_signature").into());
    }
    Ok(unsafe { std::ffi::CStr::from_ptr(hash.as_ptr()) }
        .to_string_lossy()
        .into())
}
#[cfg(target_os = "macos")]
pub fn request(request: &Request) -> Result<Response, String> {
    request_with(request, std::time::Duration::from_secs(40))
}
#[cfg(target_os = "macos")]
fn request_with(request: &Request, read_timeout: std::time::Duration) -> Result<Response, String> {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
    };
    if installed() {
        let base = std::path::Path::new("/Library/PrivilegedHelperTools/foxVPN");
        let hash = std::fs::read_to_string(base.join("client.cdhash")).ok();
        let owner = std::fs::read_to_string(base.join("client.uid"))
            .ok()
            .and_then(|v| v.parse().ok());
        if let Some(key) = binding_error(hash.as_deref(), owner, &self_hash()?, unsafe {
            libc::getuid()
        }) {
            return Err(crate::text(key).into());
        }
    }
    let mut stream = UnixStream::connect(SOCKET).map_err(|_| {
        crate::text(if installed() {
            "helper_ipc"
        } else {
            "helper_needed"
        })
    })?;
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|_| crate::text("helper_ipc"))?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|_| crate::text("helper_ipc"))?;
    let mut bytes = serde_json::to_vec(request).map_err(|_| crate::text("helper_ipc"))?;
    bytes.push(b'\n');
    stream
        .write_all(&bytes)
        .map_err(|_| crate::text("helper_ipc"))?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|_| crate::text("helper_ipc"))?;
    let mut body = Vec::new();
    stream
        .take(2_000_001)
        .read_to_end(&mut body)
        .map_err(|_| crate::text("helper_ipc"))?;
    if body.len() > 2_000_000 {
        return Err(crate::text("helper_ipc").into());
    }
    let response: Response =
        serde_json::from_slice(&body).map_err(|_| crate::text("helper_ipc"))?;
    if let Some(error) = &response.error {
        return Err(error.clone());
    }
    Ok(response)
}
#[cfg(not(target_os = "macos"))]
pub fn request(_: &Request) -> Result<Response, String> {
    Err(crate::text("helper_macos_only").into())
}
#[cfg(target_os = "macos")]
pub fn create_installer(resources: &std::path::Path) -> Result<std::path::PathBuf, String> {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = std::env::temp_dir().join(format!("foxvpn-installer-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&dir).map_err(|_| crate::text("helper_package"))?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
        .map_err(|_| crate::text("helper_package"))?;
    let stage = dir.join("root");
    let tools = stage.join("Library/PrivilegedHelperTools");
    let network = stage.join("Library/PrivilegedHelperTools/foxVPN");
    let daemons = stage.join("Library/LaunchDaemons");
    let scripts = dir.join("scripts");
    for path in [&tools, &network, &daemons, &scripts] {
        fs::create_dir_all(path).map_err(|_| crate::text("helper_package"))?;
    }
    fs::copy(
        resources.join("network/foxvpn-helper"),
        tools.join("ru.smartvpn.router.network"),
    )
    .map_err(|_| crate::text("helper_package"))?;
    fs::copy(
        resources.join("network/foxvpn-network-core"),
        network.join("core"),
    )
    .map_err(|_| crate::text("helper_package"))?;
    fs::copy(
        resources.join("network/network-version.json"),
        network.join("network-version.json"),
    )
    .map_err(|_| crate::text("helper_package"))?;
    fs::write(network.join("client.cdhash"), self_hash()?)
        .map_err(|_| crate::text("helper_package"))?;
    let uid = unsafe { libc::getuid() };
    if !valid_owner(uid) || unsafe { libc::geteuid() } != uid {
        return Err(crate::text("helper_owner").into());
    }
    fs::write(network.join("client.uid"), uid.to_string())
        .map_err(|_| crate::text("helper_package"))?;
    fs::write(
        daemons.join("ru.smartvpn.router.network.plist"),
        include_str!("../macos/network.plist"),
    )
    .map_err(|_| crate::text("helper_package"))?;
    fs::write(
        scripts.join("preinstall"),
        include_str!("../macos/preinstall"),
    )
    .map_err(|_| crate::text("helper_package"))?;
    fs::set_permissions(
        scripts.join("preinstall"),
        fs::Permissions::from_mode(0o755),
    )
    .map_err(|_| crate::text("helper_package"))?;
    fs::write(
        scripts.join("postinstall"),
        include_str!("../macos/postinstall"),
    )
    .map_err(|_| crate::text("helper_package"))?;
    for path in [
        tools.join("ru.smartvpn.router.network"),
        network.join("core"),
        scripts.join("postinstall"),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .map_err(|_| crate::text("helper_package"))?;
    }
    let pkg = dir.join("foxVPN-Network.pkg");
    if !Command::new("/usr/bin/pkgbuild")
        .arg("--root")
        .arg(&stage)
        .arg("--scripts")
        .arg(&scripts)
        .args([
            "--identifier",
            "ru.smartvpn.router.network",
            "--version",
            env!("CARGO_PKG_VERSION"),
            "--install-location",
            "/",
        ])
        .arg(&pkg)
        .output()
        .map_err(|_| crate::text("helper_package"))?
        .status
        .success()
    {
        return Err(crate::text("helper_package").into());
    }
    let _ = fs::remove_dir_all(stage);
    let _ = fs::remove_dir_all(scripts);
    Ok(pkg)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restarting_component_is_not_reported_as_outdated() {
        // Installing the package restarts the daemon; that must only mean "wait".
        assert_eq!(classify(true, false, None), Probe::Starting);
        assert_eq!(classify(true, false, Some(true)), Probe::Ready);
        // A stale binding or an older protocol/version really needs a reinstall.
        assert_eq!(classify(true, true, None), Probe::Stale);
        assert_eq!(classify(true, false, Some(false)), Probe::Stale);
        // A stale binding stays stale even if the daemon still answers.
        assert_eq!(classify(true, true, Some(true)), Probe::Stale);
        assert_eq!(classify(false, false, None), Probe::Missing);
        assert!(START_WAIT >= std::time::Duration::from_secs(5));
    }
    #[test]
    fn binding_error_separates_owner_mismatch_from_stale_hash() {
        assert_eq!(binding_error(Some("aa"), Some(501), "aa", 501), None);
        assert_eq!(
            binding_error(Some("aa"), Some(502), "aa", 501),
            Some("helper_owner")
        );
        assert_eq!(
            binding_error(Some("aa"), Some(501), "bb", 501),
            Some("helper_upgrade")
        );
        assert_eq!(
            binding_error(None, Some(501), "aa", 501),
            Some("helper_upgrade")
        );
        assert_eq!(
            binding_error(Some("aa"), None, "aa", 501),
            Some("helper_upgrade")
        );
    }
}
