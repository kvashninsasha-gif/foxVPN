use crate::{
    routing::{normalize, Mode, Rule},
    servers::Server,
    settings::Settings,
};
use serde_json::{json, Value};
use std::{
    io::{BufRead, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
};
use uuid::Uuid;
fn hide_console(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    #[cfg(not(windows))]
    let _ = command;
}
pub fn domain_match(r: &Rule) -> Value {
    let d = normalize(r.domain.strip_prefix("*.").unwrap_or(&r.domain)).unwrap();
    if r.domain.starts_with("*.") {
        json!({"domain_regex":[format!("^.+\\.{}$",d.replace('.',"\\."))]})
    } else {
        json!({"domain":[d]})
    }
}
pub fn outbound(s: &Server) -> Value {
    let mut v = json!({"type":"vless","tag":"vpn","server":s.address,"server_port":s.port,"uuid":s.uuid,"domain_resolver":"bootstrap"});
    let p = &s.params;
    if let Some(f) = p.get("flow").filter(|f| !f.is_empty()) {
        v["flow"] = json!(f)
    }
    if s.security != "none" {
        let mut tls = json!({"enabled":true,"server_name":p.get("sni").unwrap_or(&s.address)});
        if let Some(fp) = p.get("fp") {
            tls["utls"] = json!({"enabled":true,"fingerprint":fp})
        }
        if let Some(alpn) = p.get("alpn") {
            tls["alpn"] = json!(alpn.split(',').collect::<Vec<_>>())
        }
        if s.security == "reality" {
            tls["reality"] = json!({"enabled":true,"public_key":p.get("pbk"),"short_id":p.get("sid").map(String::as_str).unwrap_or("")})
        }
        v["tls"] = tls;
    }
    match s.transport.as_str() {
        "ws" => {
            let mut t =
                json!({"type":"ws","path":p.get("path").map(String::as_str).unwrap_or("/")});
            if let Some(h) = p.get("host") {
                t["headers"] = json!({"Host":h})
            }
            v["transport"] = t
        }
        "grpc" => {
            v["transport"] = json!({"type":"grpc","service_name":p.get("serviceName").map(String::as_str).unwrap_or("")})
        }
        _ => (),
    }
    v
}
pub fn config(
    s: &Server,
    settings: &Settings,
    rules: &[Rule],
    port: u16,
    api_port: u16,
    secret: &str,
) -> Result<Value, String> {
    settings.validate()?;
    crate::routing::validate(rules)?;
    let default = if settings.mode == Mode::Direct {
        "direct"
    } else {
        "vpn"
    };
    let mut route = vec![
        json!({"action":"sniff"}),
        json!({"protocol":"dns","action":"hijack-dns"}),
    ];
    // Infrastructure only: private IP bypass is intentionally absent (could override user rules).
    let mut dns_rules = vec![];
    if matches!(settings.mode, Mode::Smart | Mode::Custom) {
        for r in rules {
            let mut item = domain_match(r);
            item["action"] = json!("route");
            item["outbound"] = json!(r.route);
            route.push(item);
            let mut item = domain_match(r);
            item["action"] = json!("route");
            item["server"] = json!(if r.route == "direct" {
                "dns-direct"
            } else {
                "dns-vpn"
            });
            dns_rules.push(item)
        }
        if settings.mode == Mode::Smart {
            route.push(json!({"domain_suffix":["ru","su","xn--p1ai"],"action":"route","outbound":"direct"}));
            dns_rules.push(json!({"domain_suffix":["ru","su","xn--p1ai"],"action":"route","server":"dns-direct"}));
        }
    }
    let (ip, name) = match settings.dns_provider.as_str() {
        "google" => ("8.8.8.8", "dns.google"),
        "quad9" => ("9.9.9.9", "dns.quad9.net"),
        _ => ("1.1.1.1", "cloudflare-dns.com"),
    };
    let dns_server = |tag: &str, detour: &str| {
        if settings.dns_transport == "local" {
            json!({"type":"local","tag":tag})
        } else {
            let mut v = json!({"type":settings.dns_transport,"tag":tag,"server":ip,"tls":{"server_name":name}});
            if detour != "direct" {
                v["detour"] = json!(detour)
            }
            v
        }
    };
    let bootstrap = if settings.tun {
        json!({"type":"https","tag":"bootstrap","server":ip,"tls":{"server_name":name},"detour":"direct"})
    } else {
        json!({"type":"local","tag":"bootstrap"})
    };
    let mut inbounds =
        vec![json!({"type":"mixed","tag":"proxy-in","listen":"127.0.0.1","listen_port":port})];
    if settings.tun {
        inbounds.push(json!({"type":"tun","tag":"tun-in","address":["172.29.0.1/30","fdfe:dcba:9876::1/126"],"auto_route":true,"strict_route":true,"stack":"mixed"}));
    }
    Ok(
        json!({"log":{"level":"warn","timestamp":true},"dns":{"reverse_mapping":true,"servers":[bootstrap,dns_server("dns-direct","direct"),dns_server("dns-vpn","vpn")],"rules":dns_rules,"final":if default=="direct"{"dns-direct"}else{"dns-vpn"}},"inbounds":inbounds,"outbounds":[outbound(s),{"type":"direct","tag":"direct"}],"route":{"rules":route,"final":default,"auto_detect_interface":true,"default_domain_resolver":"bootstrap"},"experimental":{"clash_api":{"external_controller":format!("127.0.0.1:{api_port}"),"secret":secret,"access_control_allow_origin":[]}}}),
    )
}
pub fn friendly_error(raw: &str) -> String {
    let r = raw.to_lowercase();
    if r.contains("permission") || r.contains("operation not permitted") {
        crate::text("message_265")
    } else if r.contains("refused") {
        crate::text("message_266")
    } else if r.contains("timeout") || r.contains("timed out") {
        crate::text("message_267")
    } else if r.contains("reality") {
        crate::text("message_268")
    } else if r.contains("certificate") || r.contains("tls") {
        crate::text("message_269")
    } else if r.contains("dns") || r.contains("resolve") {
        crate::text("message_270")
    } else if r.contains("address already in use") {
        crate::text("message_271")
    } else {
        crate::text("message_272")
    }
    .into()
}
pub struct CoreProcess {
    pub child: Child,
    pub dir: PathBuf,
    pub proxy_port: u16,
    pub api_port: u16,
    pub secret: String,
    pub logs: Arc<Mutex<Vec<String>>>,
    #[cfg(windows)]
    _job: crate::process_lifetime::ProcessJob,
}
pub fn free_port() -> Result<u16, String> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .map_err(|_| crate::text("message_273").into())
}
impl CoreProcess {
    pub fn start(
        binary: &Path,
        s: &Server,
        settings: &Settings,
        rules: &[Rule],
    ) -> Result<Self, String> {
        Self::start_on_port(binary, s, settings, rules, free_port()?)
    }
    /// Interactive connections keep a stable port; isolated measurements use
    /// `start` so they can run alongside the user's active proxy.
    pub fn start_on_port(
        binary: &Path,
        s: &Server,
        settings: &Settings,
        rules: &[Rule],
        port: u16,
    ) -> Result<Self, String> {
        Self::start_internal(binary, s, settings, rules, port, None)
    }
    pub fn start_for_uid(
        binary: &Path,
        s: &Server,
        settings: &Settings,
        rules: &[Rule],
        port: u16,
        uid: u32,
    ) -> Result<Self, String> {
        Self::start_internal(binary, s, settings, rules, port, Some(uid))
    }
    fn start_internal(
        binary: &Path,
        s: &Server,
        settings: &Settings,
        rules: &[Rule],
        port: u16,
        uid: Option<u32>,
    ) -> Result<Self, String> {
        if settings.kill_switch {
            return Err(crate::text("message_274").into());
        }
        #[cfg(unix)]
        if settings.tun && unsafe { libc::geteuid() } != 0 {
            return Err(crate::text("message_275").into());
        }
        // Fail clearly instead of mistaking another listener for our core.
        let reservation = std::net::TcpListener::bind(("127.0.0.1", port))
            .map_err(|_| crate::text("message_271"))?;
        let mut api_port = free_port()?;
        while api_port == port {
            api_port = free_port()?
        }
        let secret = Uuid::new_v4().to_string();
        let mut cfg = config(s, settings, rules, port, api_port, &secret)?;
        if uid.is_some() {
            cfg["inbounds"][1]["interface_name"] = json!("utun99");
            cfg["inbounds"][1]["dns_mode"] = json!("disabled");
        }
        let dir = std::env::temp_dir().join(format!("smartvpn-{}", Uuid::new_v4()));
        std::fs::create_dir(&dir).map_err(|_| crate::text("message_276"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| crate::text("message_277"))?;
        }
        let path = dir.join("config.json");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| crate::text("message_278"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|_| crate::text("message_279"))?;
        }
        f.write_all(serde_json::to_string(&cfg).unwrap().as_bytes())
            .map_err(|_| crate::text("message_278"))?;
        let mut validation = Command::new(binary);
        hide_console(&mut validation);
        let valid = validation
            .args(["check", "-c"])
            .arg(&path)
            .output()
            .map_err(|_| {
                let _ = std::fs::remove_dir_all(&dir);
                crate::text("message_280")
            })?;
        if !valid.status.success() {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(friendly_error(&String::from_utf8_lossy(&valid.stderr)));
        }
        drop(reservation);
        let mut command = Command::new(binary);
        hide_console(&mut command);
        if let Some(uid) = uid {
            command.env("FOXVPN_CORE_UID", uid.to_string());
        }
        let mut child = command
            .args(["run", "-c"])
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| {
                let _ = std::fs::remove_dir_all(&dir);
                crate::text("message_281")
            })?;
        #[cfg(windows)]
        let job = match crate::process_lifetime::ProcessJob::attach(&child) {
            Ok(job) => job,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = std::fs::remove_dir_all(&dir);
                return Err(error);
            }
        };
        let logs = Arc::new(Mutex::new(vec![]));
        for stream in [
            child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
            child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let log = logs.clone();
            let secrets = vec![
                s.uuid.clone(),
                s.params.get("pbk").cloned().unwrap_or_default(),
                secret.clone(),
            ];
            std::thread::spawn(move || {
                for line in std::io::BufReader::new(stream)
                    .lines()
                    .map_while(Result::ok)
                {
                    let mut clean = line;
                    for secret in &secrets {
                        if !secret.is_empty() {
                            clean = clean.replace(secret, crate::text("message_282"))
                        }
                    }
                    let mut list = log.lock().unwrap();
                    list.push(clean.chars().take(2000).collect());
                    if list.len() > 200 {
                        list.remove(0);
                    }
                }
            });
        }
        let mut proc = Self {
            child,
            dir,
            proxy_port: port,
            api_port,
            secret,
            logs,
            #[cfg(windows)]
            _job: job,
        };
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(if cfg!(windows) { 15 } else { 3 });
        while std::time::Instant::now() < deadline {
            if proc
                .child
                .try_wait()
                .map_err(|_| crate::text("message_283"))?
                .is_some()
            {
                return Err(friendly_error(&proc.logs.lock().unwrap().join("\n")));
            }
            if std::net::TcpStream::connect_timeout(
                &format!("127.0.0.1:{port}").parse().unwrap(),
                std::time::Duration::from_millis(100),
            )
            .is_ok()
            {
                return Ok(proc);
            }
            std::thread::sleep(std::time::Duration::from_millis(50))
        }
        Err(crate::text("message_284").into())
    }
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
    pub fn stop(&mut self) {
        let _ = self.stop_checked();
    }
    /// A stop acknowledgement requires reaping the actual child process.
    pub fn stop_checked(&mut self) -> Result<(), String> {
        #[cfg(unix)]
        if matches!(self.child.try_wait(), Ok(None)) {
            unsafe {
                libc::kill(self.child.id() as i32, libc::SIGTERM);
            }
            for _ in 0..40 {
                if !matches!(self.child.try_wait(), Ok(None)) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
        match self.child.try_wait() {
            Ok(Some(_)) => (),
            Ok(None) => {
                self.child
                    .kill()
                    .map_err(|_| crate::text("helper_stop_unconfirmed"))?;
                self.child
                    .wait()
                    .map_err(|_| crate::text("helper_stop_unconfirmed"))?;
            }
            Err(_) => return Err(crate::text("helper_stop_unconfirmed").into()),
        }
        let _ = std::fs::remove_dir_all(&self.dir);
        Ok(())
    }
}
impl Drop for CoreProcess {
    fn drop(&mut self) {
        self.stop()
    }
}
