//! Typed, bounded IPC. The root daemon authenticates the client's macOS audit
//! token against the UID and CDHash installed by the user-approved package.
use crate::{routing::Rule, servers::Server, settings::Settings};
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartRequest {
    pub server: Server,
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
}
pub const PROTOCOL: u32 = 2;
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
pub fn ready() -> bool {
    request(&Request::Status).is_ok_and(|r| r.status.compatible())
}
pub fn require_current() -> Result<Status, String> {
    let status = request(&Request::Status)?.status;
    if !status.compatible() {
        return Err(crate::text("helper_upgrade").into());
    }
    Ok(status)
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
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
        time::Duration,
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
        .set_read_timeout(Some(Duration::from_secs(40)))
        .map_err(|_| crate::text("helper_ipc"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
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
