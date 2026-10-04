#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("foxVPN network helper is only supported on macOS");
}
#[cfg(target_os = "macos")]
mod daemon {
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use smart_vpn_engine::{
        network_helper::{self as ipc, Request, Response, StartRequest, Status, CORE_UID},
        vpn::CoreProcess,
    };
    use std::{
        fs,
        io::{Read, Write},
        os::unix::{
            fs::{MetadataExt, PermissionsExt},
            io::AsRawFd,
            net::UnixListener,
        },
        path::PathBuf,
        process::{Command, Stdio},
        sync::atomic::{AtomicBool, Ordering},
        time::{Duration, Instant},
    };
    const NETWORK: &str = "/Library/PrivilegedHelperTools/foxVPN";
    const ANCHOR: &str = "com.apple/ru.smartvpn.router";
    static SHUTDOWN: AtomicBool = AtomicBool::new(false);
    unsafe extern "C" {
        fn fox_verify_socket(fd: i32, expected: *const std::ffi::c_char, owner: u32) -> i32;
        fn fox_dns(enabled: i32) -> i32;
        fn fox_dns_active() -> i32;
        fn fox_watch_network();
        fn fox_network_epoch() -> u64;
        fn proc_pidpath(pid: i32, buffer: *mut std::ffi::c_void, size: u32) -> i32;
    }
    extern "C" fn terminated(_: i32) {
        SHUTDOWN.store(true, Ordering::SeqCst);
    }
    #[derive(Default, Serialize, Deserialize)]
    struct Saved {
        #[serde(default)]
        owner_uid: u32,
        wanted: Option<StartRequest>,
        pid: Option<u32>,
        token: Option<String>,
    }
    struct Manager {
        core: Option<CoreProcess>,
        saved: Saved,
        last: Instant,
        error: Option<String>,
        epoch: u64,
        pause_until: Instant,
        last_health: Instant,
        healthy: bool,
    }
    fn message(key: &str) -> String {
        smart_vpn_engine::text(key).into()
    }
    fn safe_logs(logs: &std::sync::Mutex<Vec<String>>) -> Vec<String> {
        logs.lock()
            .ok()
            .map(|logs| logs.clone())
            .unwrap_or_default()
    }
    fn fixed_command(program: &str, args: &[&str]) -> Result<std::process::Output, String> {
        let out = Command::new(program)
            .args(args)
            .output()
            .map_err(|_| message("helper_system_error"))?;
        if !out.status.success() {
            return Err(message("helper_system_error"));
        }
        Ok(out)
    }
    fn pf(args: &[&str], body: Option<&str>) -> Result<String, String> {
        let mut child = Command::new("/sbin/pfctl")
            .args(args)
            .stdin(if body.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| message("kill_error"))?;
        if let Some(body) = body {
            child
                .stdin
                .take()
                .ok_or_else(|| message("kill_error"))?
                .write_all(body.as_bytes())
                .map_err(|_| message("kill_error"))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|_| message("kill_error"))?;
        if !out.status.success() {
            return Err(message("kill_error"));
        }
        Ok(if args.contains(&"-E") {
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        } else {
            String::from_utf8_lossy(&out.stdout).into_owned()
        })
    }
    fn system_health() -> Result<(), String> {
        reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(8))
            .build()
            .map_err(|_| message("helper_system_error"))?
            .get("https://www.gstatic.com/generate_204")
            .send()
            .and_then(|r| r.error_for_status())
            .map_err(|e| smart_vpn_engine::vpn::friendly_error(&e.to_string()))?;
        Ok(())
    }
    fn guard_rules() -> String {
        format!("pass out quick on lo0 all no state\npass out quick on utun99 all no state\npass out quick inet proto udp from any port 68 to any port 67 no state\npass out quick inet6 proto icmp6 icmp6-type {{ 133, 134, 135, 136 }} no state\npass out quick proto {{ tcp, udp }} all user {CORE_UID} keep state\nblock drop out quick all\n")
    }
    fn recovery_allowed(request: &StartRequest) -> bool {
        request.settings.kill_switch && request.settings.restore
    }
    fn save(s: &Saved) -> Result<(), String> {
        let path = PathBuf::from("/var/run/foxvpn/private/session.json");
        let tmp = path.with_extension("tmp");
        fs::write(
            &tmp,
            serde_json::to_vec(s).map_err(|_| message("helper_system_error"))?,
        )
        .map_err(|_| message("helper_system_error"))?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
            .map_err(|_| message("helper_system_error"))?;
        fs::rename(tmp, path).map_err(|_| message("helper_system_error"))
    }
    fn owns_core(pid: u32) -> bool {
        let mut bytes = [0u8; 4096];
        let len =
            unsafe { proc_pidpath(pid as i32, bytes.as_mut_ptr().cast(), bytes.len() as u32) };
        len > 0
            && String::from_utf8_lossy(&bytes[..(len as usize).min(bytes.len())])
                .trim_end_matches('\0')
                == format!("{NETWORK}/core")
    }
    impl Manager {
        fn status(&mut self) -> Status {
            let running = self.core.as_mut().is_some_and(|c| c.alive());
            let mut s = Status {
                protocol: ipc::PROTOCOL,
                helper_version: env!("CARGO_PKG_VERSION").into(),
                core_alive: running,
                dns_active: unsafe { fox_dns_active() } != 0,
                running: running && self.healthy,
                wanted: self.saved.wanted.is_some(),
                error: self.error.clone(),
                kill_switch: self.saved.token.is_some(),
                interface: if running {
                    "utun99".into()
                } else {
                    String::new()
                },
                ..Status::default()
            };
            if let Some(core) = &self.core {
                s.proxy_port = core.proxy_port;
                s.api_port = core.api_port;
                s.secret = core.secret.clone();
            }
            s
        }
        fn guard(&mut self) -> Result<(), String> {
            if self.saved.token.is_some() {
                let existing = pf(&["-a", ANCHOR, "-sr"], None)?;
                let enabled = pf(&["-s", "info"], None)?.contains("Status: Enabled");
                if existing.contains("block drop out quick")
                    && existing.contains(&format!("user = {CORE_UID}"))
                    && enabled
                {
                    return Ok(());
                }
            }
            let mut main = pf(&["-sr"], None)?;
            if !main.contains("anchor \"com.apple/*\"") {
                let info = pf(&["-s", "info"], None)?;
                if main.trim().is_empty() && info.contains("Status: Disabled") {
                    pf(&["-f", "/etc/pf.conf"], None)?;
                    main = pf(&["-sr"], None)?;
                }
                if !main.contains("anchor \"com.apple/*\"") {
                    return Err(message("kill_anchor_missing"));
                }
            }
            // Validate first; attach only our anchor and retain macOS's PF enable token.
            pf(&["-n", "-a", ANCHOR, "-f", "-"], Some(&guard_rules()))?;
            let enabled = pf(&["-E"], None)?;
            let token = enabled
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(key, _)| key.trim() == "Token")
                        .map(|(_, value)| value.trim())
                })
                .filter(|v| v.chars().all(|c| c.is_ascii_digit()))
                .ok_or_else(|| message("kill_error"))?
                .to_string();
            if let Some(previous) = self.saved.token.replace(token) {
                let _ = pf(&["-X", &previous], None);
            }
            if let Err(error) = save(&self.saved) {
                let _ = self.release_guard();
                return Err(error);
            }
            if let Err(error) = pf(&["-a", ANCHOR, "-f", "-"], Some(&guard_rules())) {
                let _ = self.release_guard();
                return Err(error);
            }
            // Existing floating PF states must not remain a bypass when TUN disappears.
            pf(&["-k", "0.0.0.0/0"], None)?;
            pf(&["-k", "::/0"], None)?;
            Ok(())
        }
        fn release_guard(&mut self) -> Result<(), String> {
            pf(&["-a", ANCHOR, "-F", "all"], None)?;
            if let Some(token) = self.saved.token.as_deref() {
                pf(&["-X", token], None)?;
                self.saved.token = None;
            }
            Ok(())
        }
        fn stop(&mut self) -> Result<(), String> {
            self.saved.wanted = None;
            self.healthy = false;
            save(&self.saved)?;
            if let Some(core) = self.core.as_mut() {
                core.stop_checked()?;
            }
            self.core = None;
            self.saved.pid = None;
            save(&self.saved)?;
            let dns_ok = unsafe { fox_dns(0) } == 1;
            // Keep the traffic guard if DNS cleanup failed. Retrying Stop is safe.
            if !dns_ok {
                return Err(message("helper_dns_error"));
            }
            self.release_guard()?;
            save(&self.saved)?;
            if !self.status().stopped() {
                return Err(message("helper_stop_unconfirmed"));
            }
            self.error = None;
            let _ = fixed_command("/usr/bin/dscacheutil", &["-flushcache"]);
            Ok(())
        }
        fn start(&mut self, mut request: StartRequest) -> Result<(), String> {
            request.settings.validate()?;
            smart_vpn_engine::routing::validate(&request.rules)?;
            if !request.settings.tun || request.rules.len() > 5000 {
                return Err(message("helper_invalid"));
            }
            let profile = smart_vpn_engine::settings::Profile {
                selected: Some(request.server.id.clone()),
                servers: vec![request.server.clone()],
                settings: request.settings.clone(),
                rules: request.rules.clone(),
                ..Default::default()
            };
            profile.validate()?;
            // Resolve only the VPN endpoint before installing the DNS/traffic guard.
            if request.server.address.parse::<std::net::IpAddr>().is_err() {
                use std::net::ToSocketAddrs;
                let ip = (request.server.address.as_str(), request.server.port)
                    .to_socket_addrs()
                    .map_err(|_| message("message_270"))?
                    .next()
                    .ok_or_else(|| message("message_270"))?
                    .ip();
                if request.server.security != "none" && !request.server.params.contains_key("sni") {
                    request
                        .server
                        .params
                        .insert("sni".into(), request.server.address.clone());
                }
                request.server.address = ip.to_string();
            }
            self.saved.wanted = Some(request);
            save(&self.saved)?;
            self.restart()
        }
        fn restart(&mut self) -> Result<(), String> {
            self.last = Instant::now();
            self.healthy = false;
            self.core = None;
            self.saved.pid = None;
            unsafe {
                fox_dns(0);
            }
            let req = self
                .saved
                .wanted
                .clone()
                .ok_or_else(|| message("helper_invalid"))?;
            if req.settings.kill_switch {
                self.guard()?;
            } else {
                self.release_guard()?;
            }
            if Command::new("/sbin/ifconfig")
                .arg("utun99")
                .output()
                .is_ok_and(|o| o.status.success())
            {
                return Err(message("helper_tun_conflict"));
            }
            let settings = smart_vpn_engine::settings::Settings {
                kill_switch: false,
                ..req.settings.clone()
            };
            let mut core = CoreProcess::start_for_uid(
                &PathBuf::from(format!("{NETWORK}/core")),
                &req.server,
                &settings,
                &req.rules,
                settings.proxy_port,
                CORE_UID,
            )?;
            let mut dropped = false;
            for _ in 0..100 {
                if !core.alive() {
                    return Err(message("helper_core_failed"));
                }
                let out = Command::new("/bin/ps")
                    .args(["-o", "uid=", "-p", &core.child.id().to_string()])
                    .output()
                    .map_err(|_| message("helper_system_error"))?;
                if String::from_utf8_lossy(&out.stdout).trim() == CORE_UID.to_string() {
                    dropped = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            if !dropped {
                return Err(message("helper_core_identity"));
            }
            if unsafe { fox_dns(1) } != 1 {
                return Err(message("helper_dns_error"));
            }
            let _ = fixed_command("/usr/bin/dscacheutil", &["-flushcache"]);
            smart_vpn_engine::latency::client(core.proxy_port)?
                .get("https://www.gstatic.com/generate_204")
                .send()
                .and_then(|r| r.error_for_status())
                .map_err(|e| smart_vpn_engine::vpn::friendly_error(&e.to_string()))?;
            // A proxy health check alone misses broken system DNS and TUN routing.
            system_health()?;
            self.saved.pid = Some(core.child.id());
            self.core = Some(core);
            self.error = None;
            self.healthy = true;
            self.last_health = Instant::now();
            save(&self.saved)?;
            self.epoch = unsafe { fox_network_epoch() };
            Ok(())
        }
        fn maintain(&mut self) {
            let dead = self.core.as_mut().is_some_and(|c| !c.alive());
            if !dead
                && self.core.is_some()
                && self.saved.wanted.as_ref().is_some_and(|r| {
                    self.last_health.elapsed() >= Duration::from_secs(r.settings.health_interval)
                })
            {
                self.last_health = Instant::now();
                if let Err(error) = system_health() {
                    self.healthy = false;
                    self.error = Some(error);
                }
            }
            let changed = unsafe { fox_network_epoch() } != self.epoch;
            if self
                .saved
                .wanted
                .as_ref()
                .is_some_and(|r| r.settings.restore)
                && (dead || changed || self.core.is_none() || !self.healthy)
                && self.last.elapsed() >= Duration::from_secs(3)
                && Instant::now() >= self.pause_until
            {
                if let Err(error) = self.restart() {
                    self.error = Some(error);
                }
            }
        }
    }
    pub fn run() -> Result<(), String> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(message("helper_root_needed"));
        }
        unsafe {
            libc::umask(0o077);
            libc::signal(libc::SIGTERM, terminated as *const () as libc::sighandler_t);
            libc::signal(libc::SIGINT, terminated as *const () as libc::sighandler_t);
        }
        let base = PathBuf::from(NETWORK);
        for path in [
            base.join("core"),
            base.join("client.cdhash"),
            base.join("client.uid"),
            base.join("network-version.json"),
        ] {
            let m = fs::symlink_metadata(path).map_err(|_| message("helper_invalid"))?;
            if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 {
                return Err(message("helper_invalid"));
            }
        }
        let info: serde_json::Value = serde_json::from_slice(
            &fs::read(base.join("network-version.json")).map_err(|_| message("helper_invalid"))?,
        )
        .map_err(|_| message("helper_invalid"))?;
        if format!(
            "{:x}",
            Sha256::digest(fs::read(base.join("core")).map_err(|_| message("helper_invalid"))?)
        ) != info["binary_sha256"].as_str().unwrap_or("")
        {
            return Err(message("helper_core_hash"));
        }
        if !unsafe { libc::getpwuid(CORE_UID) }.is_null() {
            return Err(message("helper_uid_conflict"));
        }
        let hash = fs::read_to_string(base.join("client.cdhash"))
            .map_err(|_| message("helper_invalid"))?;
        if hash.len() != 40 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(message("helper_invalid"));
        }
        let expected = std::ffi::CString::new(hash).map_err(|_| message("helper_invalid"))?;
        let owner: u32 = fs::read_to_string(base.join("client.uid"))
            .map_err(|_| message("helper_owner"))?
            .parse()
            .map_err(|_| message("helper_owner"))?;
        if !ipc::valid_owner(owner) || unsafe { libc::getpwuid(owner) }.is_null() {
            return Err(message("helper_owner"));
        }
        fs::create_dir_all("/var/run/foxvpn/private")
            .map_err(|_| message("helper_system_error"))?;
        fs::set_permissions("/var/run/foxvpn", fs::Permissions::from_mode(0o755))
            .map_err(|_| message("helper_system_error"))?;
        fs::set_permissions("/var/run/foxvpn/private", fs::Permissions::from_mode(0o700))
            .map_err(|_| message("helper_system_error"))?;
        let mut saved: Saved = fs::read("/var/run/foxvpn/private/session.json")
            .ok()
            .and_then(|s| serde_json::from_slice(&s).ok())
            .unwrap_or_default();
        if let Some(pid) = saved.pid.filter(|pid| owns_core(*pid)) {
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            for _ in 0..20 {
                if !owns_core(pid) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            if owns_core(pid) {
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
                }
                for _ in 0..20 {
                    if !owns_core(pid) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                if owns_core(pid) {
                    return Err(message("helper_stop_unconfirmed"));
                }
            }
        }
        let changed_owner = saved.owner_uid != owner;
        saved.owner_uid = owner;
        let mut manager = Manager {
            core: None,
            saved,
            last: Instant::now() - Duration::from_secs(10),
            error: None,
            epoch: unsafe { fox_network_epoch() },
            pause_until: Instant::now(),
            last_health: Instant::now(),
            healthy: false,
        };
        // An administrator-approved owner change never inherits another user's
        // server credentials, API secret or reconnecting session.
        if changed_owner {
            manager.stop()?;
        }
        std::thread::spawn(|| unsafe {
            fox_watch_network();
        });
        let _ = fs::remove_file(ipc::SOCKET);
        let listener =
            UnixListener::bind(ipc::SOCKET).map_err(|_| message("helper_system_error"))?;
        let socket = std::ffi::CString::new(ipc::SOCKET).map_err(|_| message("helper_invalid"))?;
        if unsafe { libc::chown(socket.as_ptr(), owner, 0) } != 0 {
            return Err(message("helper_owner"));
        }
        fs::set_permissions(ipc::SOCKET, fs::Permissions::from_mode(0o600))
            .map_err(|_| message("helper_system_error"))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| message("helper_system_error"))?;
        while !SHUTDOWN.load(Ordering::SeqCst) {
            if let Ok((mut stream, _)) = listener.accept() {
                if unsafe { fox_verify_socket(stream.as_raw_fd(), expected.as_ptr(), owner) } != 1 {
                    continue;
                }
                let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
                let mut body = Vec::new();
                if (&mut stream).take(2_000_001).read_to_end(&mut body).is_ok()
                    && body.len() <= 2_000_000
                {
                    let (error, logs) = match serde_json::from_slice::<Request>(&body) {
                        Ok(Request::Start(req)) => (manager.start(*req).err(), vec![]),
                        Ok(Request::Stop) => (manager.stop().err(), vec![]),
                        Ok(Request::TestRecovery) => {
                            if manager.saved.wanted.as_ref().is_some_and(recovery_allowed) {
                                manager.core = None;
                                manager.healthy = false;
                                manager.saved.pid = None;
                                manager.pause_until = Instant::now() + Duration::from_secs(10);
                                let _ = save(&manager.saved);
                                (None, vec![])
                            } else {
                                (Some(message("test_requires_guard")), vec![])
                            }
                        }
                        Ok(Request::Status) => (None, vec![]),
                        Ok(Request::Logs) => (
                            None,
                            manager
                                .core
                                .as_ref()
                                .map(|c| safe_logs(&c.logs))
                                .unwrap_or_default(),
                        ),
                        Err(_) => (Some(message("helper_invalid")), vec![]),
                    };
                    if let Some(error) = &error {
                        manager.error = Some(error.clone());
                    }
                    let response = Response {
                        status: manager.status(),
                        logs,
                        error,
                    };
                    if let Ok(bytes) = serde_json::to_vec(&response) {
                        let _ = stream.write_all(&bytes);
                    }
                }
            }
            manager.maintain();
            std::thread::sleep(Duration::from_millis(100));
        }
        manager.stop()?;
        let _ = fs::remove_file(ipc::SOCKET);
        Ok(())
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn a_poisoned_log_buffer_cannot_panic_the_root_daemon() {
            let logs = std::sync::Arc::new(std::sync::Mutex::new(vec!["diagnostic".into()]));
            let other = logs.clone();
            assert!(std::thread::spawn(move || {
                let _lock = other.lock().unwrap();
                panic!("simulate log writer failure");
            })
            .join()
            .is_err());
            assert!(safe_logs(&logs).is_empty());
        }
        #[test]
        fn socket_authentication_requires_the_kernel_uid_and_exact_signature() {
            use std::os::unix::net::UnixStream;
            let (client, _peer) = UnixStream::pair().unwrap();
            let hash = std::ffi::CString::new(ipc::self_hash().unwrap()).unwrap();
            let owner = unsafe { libc::getuid() };
            assert_eq!(
                unsafe { fox_verify_socket(client.as_raw_fd(), hash.as_ptr(), owner) },
                1
            );
            assert_eq!(
                unsafe { fox_verify_socket(client.as_raw_fd(), hash.as_ptr(), owner + 1) },
                0
            );
            assert_eq!(
                unsafe { fox_verify_socket(client.as_raw_fd(), hash.as_ptr(), 0) },
                0
            );
            let wrong = std::ffi::CString::new("0000000000000000000000000000000000000000").unwrap();
            assert_eq!(
                unsafe { fox_verify_socket(client.as_raw_fd(), wrong.as_ptr(), owner) },
                0
            );
        }
        #[test]
        fn guard_uses_a_dedicated_core_identity_and_blocks_both_ip_families() {
            let rules = guard_rules();
            assert!(rules.contains(&format!("user {CORE_UID}")));
            assert!(!rules.contains("user root") && !rules.contains("user 0 "));
            assert!(rules.contains("block drop out quick all"));
            assert!(rules.contains("on utun99 all no state"));
        }
        #[test]
        fn recovery_diagnostic_requires_protection_and_automatic_restoration() {
            let mut request = StartRequest {
                server: smart_vpn_engine::servers::Server::parse(
                    "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=none&type=tcp#test",
                )
                .unwrap(),
                settings: smart_vpn_engine::settings::Settings::default(),
                rules: vec![],
            };
            assert!(recovery_allowed(&request));
            request.settings.restore = false;
            assert!(!recovery_allowed(&request));
            request.settings.restore = true;
            request.settings.kill_switch = false;
            assert!(!recovery_allowed(&request));
        }
    }
}
#[cfg(target_os = "macos")]
fn main() {
    if let Err(error) = daemon::run() {
        eprintln!("foxVPN: {error}");
        std::process::exit(1);
    }
}
