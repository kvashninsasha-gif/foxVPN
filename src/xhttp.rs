//! Private Xray transport sidecar for the Windows proxy engine.
//! Routing stays in sing-box. Never exposes an unauthenticated extra proxy.
use crate::servers::Server;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

pub fn configuration(s: &Server, port: u16, password: &str) -> Result<Value, String> {
    let mode = s.params.get("mode").map(String::as_str).unwrap_or("auto");
    if !["auto", "packet-up", "stream-up", "stream-one"].contains(&mode) {
        return Err("Неподдерживаемый режим XHTTP".into());
    }
    if s.params.contains_key("extra") {
        return Err("Расширенные параметры XHTTP extra пока не поддерживаются".into());
    }
    let p = &s.params;
    let mut stream = json!({"network":"xhttp","security":s.security,"xhttpSettings":{
        "mode":mode,"path":p.get("path").map(String::as_str).unwrap_or("/"),
        "host":p.get("host").map(String::as_str).unwrap_or("")}});
    if s.security == "reality" {
        stream["realitySettings"] = json!({"serverName":p.get("sni"),"fingerprint":p.get("fp").map(String::as_str).unwrap_or("chrome"),
            "password":p.get("pbk"),"shortId":p.get("sid").map(String::as_str).unwrap_or(""),"spiderX":p.get("spx").map(String::as_str).unwrap_or("/")});
    } else if s.security == "tls" {
        stream["tlsSettings"] = json!({"serverName":p.get("sni").unwrap_or(&s.address),"fingerprint":p.get("fp").map(String::as_str).unwrap_or("chrome")});
        if let Some(alpn) = p.get("alpn") {
            stream["tlsSettings"]["alpn"] = json!(alpn.split(',').collect::<Vec<_>>());
        }
    }
    Ok(
        json!({"log":{"loglevel":"error"},"inbounds":[{"tag":"fox-private","listen":"127.0.0.1","port":port,"protocol":"socks",
        "settings":{"auth":"password","ip":"127.0.0.1","accounts":[{"user":"foxvpn","pass":password}],"udp":true}}],
        "outbounds":[{"tag":"vpn","protocol":"vless","settings":{"vnext":[{"address":s.address,"port":s.port,"users":[{"id":s.uuid,"encryption":"none"}]}]},"streamSettings":stream}]}),
    )
}

pub fn verify_resource(core: &Path) -> Result<PathBuf, String> {
    let binary = core.with_file_name(if cfg!(windows) { "xray.exe" } else { "xray" });
    let metadata = std::fs::read(binary.with_file_name("xray-version.json"))
        .map_err(|_| "В сборке отсутствует модуль XHTTP")?;
    if metadata.len() > 32768 {
        return Err("Некорректная версия модуля XHTTP".into());
    }
    let info: Value =
        serde_json::from_slice(&metadata).map_err(|_| "Некорректная версия модуля XHTTP")?;
    if info["version"] != "26.11.9" || info["vulnerability_scan"] != "zero-findings" {
        return Err("Обновите проверенную сборку модуля XHTTP".into());
    }
    let bytes = std::fs::read(&binary).map_err(|_| "Модуль XHTTP отсутствует")?;
    if info["binary_sha256"].as_str() != Some(&format!("{:x}", Sha256::digest(&bytes))) {
        return Err("Целостность модуля XHTTP не подтверждена".into());
    }
    Ok(binary)
}

pub struct Sidecar {
    child: Child,
    dir: PathBuf,
    pub port: u16,
    password: String,
    #[cfg(windows)]
    _job: crate::process_lifetime::ProcessJob,
}
impl Sidecar {
    pub fn outbound(&self) -> Value {
        json!({"type":"socks","tag":"vpn","server":"127.0.0.1","server_port":self.port,"version":"5","username":"foxvpn","password":self.password})
    }
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
    pub fn start(core: &Path, s: &Server) -> Result<Self, String> {
        let binary = verify_resource(core)?;
        let reservation = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|_| "Не удалось подготовить XHTTP")?;
        let port = reservation
            .local_addr()
            .map_err(|_| "Не удалось подготовить XHTTP")?
            .port();
        let password = uuid::Uuid::new_v4().to_string();
        let config = configuration(s, port, &password)?;
        let dir = std::env::temp_dir().join(format!("foxvpn-xhttp-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).map_err(|_| "Не удалось подготовить XHTTP")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| "Не удалось защитить XHTTP")?;
        }
        let path = dir.join("config.json");
        let result = (|| {
            std::fs::write(
                &path,
                serde_json::to_vec(&config).map_err(|_| "Некорректная конфигурация XHTTP")?,
            )
            .map_err(|_| "Не удалось подготовить XHTTP")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    .map_err(|_| "Не удалось защитить XHTTP")?;
            }
            let mut check = Command::new(&binary);
            hide(&mut check);
            if !check
                .args(["run", "-test", "-config"])
                .arg(&path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_err(|_| "Не удалось проверить XHTTP")?
                .success()
            {
                return Err("Модуль XHTTP отклонил конфигурацию".into());
            }
            drop(reservation);
            let mut command = Command::new(&binary);
            hide(&mut command);
            #[allow(unused_mut)]
            let mut child = command
                .args(["run", "-config"])
                .arg(&path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| "Не удалось запустить XHTTP")?;
            #[cfg(windows)]
            let job = match crate::process_lifetime::ProcessJob::attach(&child) {
                Ok(v) => v,
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(e);
                }
            };
            let mut instance = Self {
                child,
                dir: dir.clone(),
                port,
                password,
                #[cfg(windows)]
                _job: job,
            };
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if !instance.alive() {
                    return Err("Модуль XHTTP завершился при запуске".into());
                }
                if std::net::TcpStream::connect_timeout(
                    &format!("127.0.0.1:{port}")
                        .parse()
                        .map_err(|_| "Некорректный адрес XHTTP")?,
                    Duration::from_millis(100),
                )
                .is_ok()
                {
                    return Ok(instance);
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err("Модуль XHTTP не подтвердил запуск".into())
        })();
        if result.is_err() {
            let _ = std::fs::remove_dir_all(&dir);
        }
        result
    }
    pub fn stop(&mut self) -> Result<(), String> {
        if self.alive() {
            self.child
                .kill()
                .map_err(|_| "Не удалось остановить XHTTP")?;
        }
        self.child
            .wait()
            .map_err(|_| "Не удалось подтвердить остановку XHTTP")?;
        let _ = std::fs::remove_dir_all(&self.dir);
        Ok(())
    }
}
impl Drop for Sidecar {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
fn hide(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    #[cfg(not(windows))]
    let _ = command;
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "Requires the pinned audited Xray resource"]
    fn actual_xray_configuration_starts_and_reaps_its_authenticated_proxy() {
        let core = std::path::PathBuf::from(
            std::env::var_os("FOXVPN_TEST_XRAY_CORE").expect("fixture core path"),
        );
        let mut server=Server::parse("vless://11111111-1111-4111-8111-111111111111@127.0.0.1:1?type=tcp&security=none#fixture").unwrap();
        server.transport = "xhttp".into();
        let mut sidecar = Sidecar::start(&core, &server).unwrap();
        assert!(sidecar.alive());
        use std::io::{Read, Write};
        let mut socket = std::net::TcpStream::connect(("127.0.0.1", sidecar.port)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket.write_all(&[5, 1, 0]).unwrap();
        let mut answer = [0; 2];
        socket.read_exact(&mut answer).unwrap();
        assert_eq!(
            answer,
            [5, 255],
            "Unauthenticated sidecar must refuse requests"
        );
        assert_eq!(sidecar.outbound()["server"], "127.0.0.1");
        sidecar.stop().unwrap();
        assert!(!sidecar.alive());
    }
    #[test]
    fn xhttp_uses_authenticated_loopback_and_preserves_transport_fields() {
        let mut s=Server::parse("vless://11111111-1111-4111-8111-111111111111@example.com:443?type=tcp&security=none#fixture").unwrap();
        s.transport = "xhttp".into();
        s.params.insert("mode".into(), "packet-up".into());
        s.params.insert("path".into(), "/probe?a=1".into());
        let cfg = configuration(&s, 10001, "test-only-secret").unwrap();
        assert_eq!(cfg["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(cfg["inbounds"][0]["settings"]["auth"], "password");
        assert_eq!(
            cfg["outbounds"][0]["streamSettings"]["xhttpSettings"]["mode"],
            "packet-up"
        );
        assert_eq!(
            cfg["outbounds"][0]["streamSettings"]["xhttpSettings"]["path"],
            "/probe?a=1"
        );
        s.params.insert("mode".into(), "bad-mode".into());
        assert!(configuration(&s, 10001, "unused").is_err());
    }
}
