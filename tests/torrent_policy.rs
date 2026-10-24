use smart_vpn_engine::{
    routing::{Mode, Rule},
    servers::Server,
    settings::Settings,
    vpn::{self, CoreProcess},
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
const PEER: &[u8] = b"\x16\x03\x03opaque-encrypted-peer-fixture";
#[test]
fn mandatory_rules_precede_user_vpn_routes_in_every_mode_and_cannot_be_disabled_by_profile() {
    let server =
        Server::parse("vless://11111111-1111-4111-8111-111111111111@127.0.0.1:9?security=none")
            .unwrap();
    for mode in [Mode::Smart, Mode::Vpn, Mode::Custom, Mode::Direct] {
        let settings = Settings {
            mode,
            tun: false,
            kill_switch: false,
            ..Default::default()
        };
        let cfg = vpn::config(
            &server,
            &settings,
            &[Rule {
                domain: "example.com".into(),
                route: "vpn".into(),
            }],
            2080,
            2081,
            "public-policy",
        )
        .unwrap();
        let rules = cfg["route"]["rules"].as_array().unwrap();
        let manual = rules
            .iter()
            .position(|r| r["domain"][0] == "example.com")
            .unwrap();
        let protocol = rules
            .iter()
            .position(|r| r["protocol"] == "bittorrent")
            .unwrap();
        assert!(protocol < manual);
        assert_eq!(rules[protocol]["outbound"], "direct");
        if cfg!(any(target_os = "macos", windows)) {
            assert_eq!(rules[0]["outbound"], "direct");
            assert!(!rules[0]["process_path_regex"][0]
                .as_str()
                .unwrap()
                .is_empty());
            let guard = rules
                .iter()
                .position(|r| r["action"] == "reject" && r["invert"] == true)
                .unwrap();
            assert!(guard < manual);
            assert_eq!(rules[guard]["process_path_regex"][0], ".+");
            assert_eq!(cfg["route"]["find_process"], true);
        }
    }
}
struct Echo {
    port: u16,
    done: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}
impl Echo {
    fn new() -> Self {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        tcp.set_nonblocking(true).unwrap();
        let udp = UdpSocket::bind(("127.0.0.1", port)).unwrap();
        udp.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let stop = done.clone();
        let t = std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                if let Ok((mut socket, _)) = tcp.accept() {
                    socket.set_nonblocking(false).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut bytes = vec![0; PEER.len()];
                    if socket.read_exact(&mut bytes).is_ok() {
                        let _ = socket.write_all(&bytes);
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        });
        let stop = done.clone();
        let u = std::thread::spawn(move || {
            let mut bytes = [0; 2048];
            while !stop.load(Ordering::SeqCst) {
                if let Ok((n, peer)) = udp.recv_from(&mut bytes) {
                    let _ = udp.send_to(&bytes[..n], peer);
                }
            }
        });
        Self {
            port,
            done,
            threads: vec![t, u],
        }
    }
}
impl Drop for Echo {
    fn drop(&mut self) {
        self.done.store(true, Ordering::SeqCst);
        for t in self.threads.drain(..) {
            t.join().unwrap();
        }
    }
}
fn socks(
    port: u16,
    udp: bool,
    target: u16,
) -> Result<(TcpStream, u16), Box<dyn std::error::Error>> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.set_read_timeout(Some(Duration::from_secs(3)))?;
    s.set_write_timeout(Some(Duration::from_secs(3)))?;
    s.write_all(&[5, 1, 0])?;
    let mut auth = [0; 2];
    s.read_exact(&mut auth)?;
    if auth != [5, 0] {
        return Err("SOCKS authentication".into());
    }
    let mut request = vec![5, if udp { 3 } else { 1 }, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&if udp { 0u16 } else { target }.to_be_bytes());
    s.write_all(&request)?;
    let mut response = [0; 10];
    s.read_exact(&mut response)?;
    if response[..4] != [5, 0, 0, 1] {
        return Err(format!("SOCKS connect rejected: {response:02x?}").into());
    }
    Ok((s, u16::from_be_bytes([response[8], response[9]])))
}
fn fetch(port: u16, target: u16, udp: bool) -> Result<(), Box<dyn std::error::Error>> {
    let (mut s, relay) = socks(port, udp, target)?;
    if !udp {
        s.write_all(PEER)?;
        let mut data = vec![0; PEER.len()];
        s.read_exact(&mut data)?;
        if data != PEER {
            return Err("peer payload mismatch".into());
        }
    } else {
        let u = UdpSocket::bind("127.0.0.1:0")?;
        u.set_read_timeout(Some(Duration::from_secs(2)))?;
        let mut frame = vec![0, 0, 0, 1, 127, 0, 0, 1];
        frame.extend_from_slice(&target.to_be_bytes());
        frame.extend_from_slice(PEER);
        u.send_to(&frame, ("127.0.0.1", relay))?;
        let mut reply = [0; 2048];
        let (n, _) = u.recv_from(&mut reply)?;
        if n < 10 || &reply[10..n] != PEER {
            return Err("UDP peer mismatch".into());
        }
    }
    Ok(())
}
#[test]
#[ignore = "public child fixture; no user data"]
fn public_torrent_client() {
    let port = std::env::var("FOXVPN_TORRENT_TEST_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let target = std::env::var("FOXVPN_TORRENT_TEST_TARGET")
        .unwrap()
        .parse()
        .unwrap();
    let udp = std::env::var("FOXVPN_TORRENT_TEST_UDP").as_deref() == Ok("1");
    fetch(port, target, udp).unwrap();
}
#[cfg(any(target_os = "macos", windows))]
#[test]
fn real_named_clients_use_direct_for_opaque_tcp_and_udp_despite_explicit_vpn_and_never_fall_back() {
    let Ok(binary) = std::env::var("SMARTVPN_TEST_CORE") else {
        return;
    };
    let echo = Echo::new();
    let dir = tempfile::tempdir().unwrap();
    let source = std::env::current_exe().unwrap();
    let names: Vec<&str> = if cfg!(windows) {
        vec![
            "MediaGet.exe",
            "uTorrent.exe",
            "uTorrentie.exe",
            "utweb.exe",
            "qBittorrent.exe",
        ]
    } else {
        vec![
            "MediaGet.app",
            "µTorrent.app",
            "uTorrent Web.app",
            "qBittorrent.app",
        ]
    };
    let vpn_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    vpn_listener.set_nonblocking(true).unwrap();
    let vpn_port = vpn_listener.local_addr().unwrap().port();
    let vpn_hits = Arc::new(AtomicUsize::new(0));
    let hits = vpn_hits.clone();
    let done = Arc::new(AtomicBool::new(false));
    let stop = done.clone();
    let observer = std::thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            if let Ok((socket, _)) = vpn_listener.accept() {
                hits.fetch_add(1, Ordering::SeqCst);
                drop(socket);
            } else {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    });
    let server = Server::parse(&format!(
        "vless://11111111-1111-4111-8111-111111111111@127.0.0.1:{vpn_port}?security=none"
    ))
    .unwrap();
    let clients: Vec<_> = names
        .iter()
        .map(|name| {
            let p = if cfg!(windows) {
                dir.path().join(name)
            } else {
                dir.path().join(name).join("Contents/MacOS/fixture")
            };
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::copy(&source, &p).unwrap();
            #[cfg(target_os = "macos")]
            assert!(std::process::Command::new("/usr/bin/codesign")
                .args(["--force", "--sign", "-"])
                .arg(&p)
                .output()
                .unwrap()
                .status
                .success());
            p
        })
        .collect();
    let run = |path: &std::path::Path, port: u16, target: u16, udp: bool| {
        std::process::Command::new(path)
            .args(["--exact", "public_torrent_client", "--ignored"])
            .env("FOXVPN_TORRENT_TEST_PORT", port.to_string())
            .env("FOXVPN_TORRENT_TEST_TARGET", target.to_string())
            .env("FOXVPN_TORRENT_TEST_UDP", if udp { "1" } else { "0" })
            .output()
            .unwrap()
    };
    let rules = [Rule {
        domain: "127.0.0.1".into(),
        route: "vpn".into(),
    }];
    for mode in [Mode::Smart, Mode::Vpn, Mode::Custom, Mode::Direct] {
        let settings = Settings {
            mode,
            tun: false,
            kill_switch: false,
            ..Default::default()
        };
        let core =
            CoreProcess::start(std::path::Path::new(&binary), &server, &settings, &rules).unwrap();
        for client in &clients {
            for udp in [false, true] {
                let result = run(client, core.proxy_port, echo.port, udp);
                assert!(
                    result.status.success(),
                    "{} UDP={udp}: {}\n{:?}",
                    client.display(),
                    String::from_utf8_lossy(&result.stdout),
                    core.logs.lock().unwrap()
                );
            }
        }
        // Unavailable direct destination must not retry through the VPN server.
        let unused = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = unused.local_addr().unwrap().port();
        drop(unused);
        assert!(!run(&clients[0], core.proxy_port, target, false)
            .status
            .success());
    }
    let port = vpn::free_port().unwrap();
    let upstream = serde_json::json!({"log":{"level":"warn"},"inbounds":[{"type":"vless","listen":"127.0.0.1","listen_port":port,"users":[{"uuid":"11111111-1111-4111-8111-111111111111"}]}],"outbounds":[{"type":"direct","tag":"peer"}],"route":{"rules":[{"action":"route","outbound":"peer","override_address":"127.0.0.1","override_port":echo.port}],"final":"peer"}});
    let path = dir.path().join("vless-server.json");
    std::fs::write(&path, serde_json::to_vec(&upstream).unwrap()).unwrap();
    struct Upstream(std::process::Child);
    impl Drop for Upstream {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let _upstream = Upstream(
        std::process::Command::new(&binary)
            .args(["run", "-c"])
            .arg(path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let remote = Server::parse(&format!(
        "vless://11111111-1111-4111-8111-111111111111@127.0.0.1:{port}?security=none"
    ))
    .unwrap();
    let settings = Settings {
        torrents_vpn: true,
        mode: Mode::Direct,
        tun: false,
        kill_switch: false,
        ..Default::default()
    };
    let core = CoreProcess::start(
        std::path::Path::new(&binary),
        &remote,
        &settings,
        &[Rule {
            domain: "127.0.0.1".into(),
            route: "direct".into(),
        }],
    )
    .unwrap();
    let closed = vpn::free_port().unwrap();
    for udp in [false, true] {
        assert!(
            run(&clients[0], core.proxy_port, closed, udp)
                .status
                .success(),
            "explicit opt-in must use the VLESS server despite direct mode/rule"
        );
    }
    done.store(true, Ordering::SeqCst);
    observer.join().unwrap();
    assert_eq!(
        vpn_hits.load(Ordering::SeqCst),
        0,
        "protected clients attempted VPN"
    );
}
#[cfg(target_os = "macos")]
#[test]
fn unreadable_owner_is_rejected_even_with_manual_direct_route() {
    use std::os::{
        fd::AsRawFd,
        unix::{net::UnixStream, process::CommandExt},
    };
    let Ok(binary) = std::env::var("SMARTVPN_TEST_CORE") else {
        return;
    };
    let echo = Echo::new();
    let dir = tempfile::tempdir().unwrap();
    let port = vpn::free_port().unwrap();
    let server =
        Server::parse("vless://11111111-1111-4111-8111-111111111111@127.0.0.1:9?security=none")
            .unwrap();
    let settings = Settings {
        tun: false,
        kill_switch: false,
        mode: Mode::Direct,
        ..Default::default()
    };
    let cfg = vpn::config(
        &server,
        &settings,
        &[Rule {
            domain: "127.0.0.1".into(),
            route: "direct".into(),
        }],
        port,
        vpn::free_port().unwrap(),
        "public-owner-failure",
    )
    .unwrap();
    let path = dir.path().join("config.json");
    std::fs::write(&path, serde_json::to_vec(&cfg).unwrap()).unwrap();
    let (mut broker, child) = UnixStream::pair().unwrap();
    let fd = child.as_raw_fd();
    let worker = std::thread::spawn(move || {
        let mut frame = [0; 44];
        while broker.read_exact(&mut frame).is_ok() {
            if broker.write_all(&[0; 7]).is_err() {
                break;
            }
        }
    });
    let mut cmd = std::process::Command::new(binary);
    cmd.args(["run", "-c"])
        .arg(path)
        .env("FOXVPN_PROCESS_FD", fd.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    unsafe {
        cmd.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut core = cmd.spawn().unwrap();
    drop(child);
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let results = [
        fetch(port, echo.port, false).is_err(),
        fetch(port, echo.port, true).is_err(),
    ];
    core.kill().unwrap();
    core.wait().unwrap();
    worker.join().unwrap();
    assert_eq!(results, [true, true]);
}

#[test]
fn default_is_direct_and_opt_in_is_preserved_in_profiles_and_overrides_direct_rules() {
    let mut p = smart_vpn_engine::settings::Profile::default();
    assert!(!p.settings.torrents_vpn);
    let legacy: Settings = serde_json::from_str("{}").unwrap();
    assert!(!legacy.torrents_vpn);
    let before = smart_vpn_engine::settings::configuration_digest(&p).unwrap();
    p.settings.torrents_vpn = true;
    assert_ne!(
        before,
        smart_vpn_engine::settings::configuration_digest(&p).unwrap()
    );
    let restored: smart_vpn_engine::settings::Profile =
        serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
    assert!(restored.settings.torrents_vpn);
    let server =
        Server::parse("vless://11111111-1111-4111-8111-111111111111@127.0.0.1:9?security=none")
            .unwrap();
    let cfg = vpn::config(
        &server,
        &p.settings,
        &[Rule {
            domain: "127.0.0.1".into(),
            route: "direct".into(),
        }],
        2080,
        2081,
        "public-policy",
    )
    .unwrap();
    let rules = cfg["route"]["rules"].as_array().unwrap();
    if cfg!(any(target_os = "macos", windows)) {
        assert_eq!(rules[0]["outbound"], "vpn");
    }
    assert_eq!(
        rules
            .iter()
            .find(|r| r["protocol"] == "bittorrent")
            .unwrap()["outbound"],
        "vpn"
    );
    if cfg!(any(target_os = "macos", windows)) {
        assert!(rules
            .iter()
            .any(|r| r["invert"] == true && r["action"] == "reject"));
    }
    let mut helper = smart_vpn_engine::network_helper::Status {
        protocol: smart_vpn_engine::network_helper::PROTOCOL,
        helper_version: "0.1.33".into(),
        ..Default::default()
    };
    assert!(smart_vpn_engine::torrent_policy::require_helper(&helper).is_err());
    helper.helper_version = "0.1.34".into();
    assert!(smart_vpn_engine::torrent_policy::require_helper(&helper).is_ok());
}
