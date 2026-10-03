//! Typed, bounded IPC. The root daemon authenticates the client's macOS audit
//! token against the CDHash installed by the user-approved package.
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
pub struct Status {
    pub running: bool,
    pub wanted: bool,
    pub proxy_port: u16,
    pub api_port: u16,
    pub secret: String,
    pub error: Option<String>,
    pub kill_switch: bool,
    pub interface: String,
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
    let mut stream = UnixStream::connect(SOCKET).map_err(|_| crate::text("helper_needed"))?;
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
