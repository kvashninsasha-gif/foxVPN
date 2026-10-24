use smart_vpn_engine::{
    latency,
    routing::{Mode, Rule},
    servers::Server,
    settings::Settings,
    vpn::CoreProcess,
};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
struct HttpFixture {
    port: u16,
    done: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl HttpFixture {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let stop = done.clone();
        let thread = std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Ok((mut stream, _)) = listener.accept() {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut buffer = [0; 2048];
                    let _ = stream.read(&mut buffer);
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nDIRECT",
                    );
                } else {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        });
        Self {
            port,
            done,
            thread: Some(thread),
        }
    }
}
impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}
fn offline_server() -> Server {
    let unused = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = unused.local_addr().unwrap().port();
    drop(unused);
    Server::parse(&format!(
        "vless://11111111-1111-4111-8111-111111111111@127.0.0.1:{port}?security=none"
    ))
    .unwrap()
}
fn fetch(proxy: u16, url: &str) -> Result<String, reqwest::Error> {
    latency::client(proxy)
        .unwrap()
        .get(url)
        .timeout(Duration::from_secs(3))
        .send()?
        .text()
}
#[test]
fn actual_core_enforces_explicit_routes_in_every_mode_and_never_falls_back() {
    let Ok(binary) = std::env::var("SMARTVPN_TEST_CORE") else {
        return;
    };
    let http = HttpFixture::new();
    let server = offline_server();
    let url = format!("http://localhost:{}/verified", http.port);
    for mode in [Mode::Smart, Mode::Custom, Mode::Vpn, Mode::Direct] {
        let settings = Settings {
            mode,
            tun: false,
            kill_switch: false,
            dns_transport: "local".into(),
            dns_protection: false,
            ..Default::default()
        };
        for route in ["direct", "vpn"] {
            let rules = vec![Rule {
                domain: "localhost".into(),
                route: route.into(),
            }];
            let core =
                CoreProcess::start(std::path::Path::new(&binary), &server, &settings, &rules)
                    .unwrap();
            let result = fetch(core.proxy_port, &url);
            if route == "direct" {
                assert_eq!(result.unwrap(), "DIRECT");
            } else {
                assert!(
                    result.is_err(),
                    "explicit VPN must not fall back to direct: {result:?}"
                );
            }
        }
    }
}
#[cfg(windows)]
#[test]
fn windows_proxy_client_fixture() {
    if let Ok(url) = std::env::var("FOXVPN_EXCLUSION_TEST_URL") {
        let port = std::env::var("FOXVPN_EXCLUSION_TEST_PORT")
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(fetch(port, &url).unwrap(), "DIRECT");
    }
}
#[cfg(windows)]
#[test]
fn actual_windows_core_matches_only_selected_exe_and_respects_explicit_domain_rule() {
    use smart_vpn_engine::app_routes::Application;
    let Ok(binary) = std::env::var("SMARTVPN_TEST_CORE") else {
        return;
    };
    let http = HttpFixture::new();
    let server = offline_server();
    let dir = tempfile::tempdir().unwrap();
    let original = std::env::current_exe().unwrap();
    let chosen = dir.path().join("Chosen.exe");
    let other = dir.path().join("Chosen.exe.other.exe");
    std::fs::copy(&original, &chosen).unwrap();
    std::fs::copy(&original, &other).unwrap();
    let settings = Settings {
        mode: Mode::Vpn,
        tun: false,
        kill_switch: false,
        dns_transport: "local".into(),
        dns_protection: false,
        windows_excluded_apps: vec![Application {
            name: "Chosen".into(),
            path: chosen.to_str().unwrap().to_owned(),
        }],
        ..Default::default()
    };
    let run = |exe: &std::path::Path, port: u16| {
        let start = std::time::Instant::now();
        let output = std::process::Command::new(exe)
            .args(["--exact", "windows_proxy_client_fixture", "--nocapture"])
            .env(
                "FOXVPN_EXCLUSION_TEST_URL",
                format!("http://localhost:{}/", http.port),
            )
            .env("FOXVPN_EXCLUSION_TEST_PORT", port.to_string())
            .output()
            .unwrap();
        assert!(start.elapsed() < Duration::from_secs(15));
        output.status.success()
    };
    let core = CoreProcess::start(std::path::Path::new(&binary), &server, &settings, &[]).unwrap();
    assert!(
        run(&chosen, core.proxy_port),
        "selected exe must use direct"
    );
    assert!(
        !run(&other, core.proxy_port),
        "similar unselected exe must keep VPN"
    );
    drop(core);
    let rules = vec![Rule {
        domain: "localhost".into(),
        route: "vpn".into(),
    }];
    let core =
        CoreProcess::start(std::path::Path::new(&binary), &server, &settings, &rules).unwrap();
    assert!(
        !run(&chosen, core.proxy_port),
        "explicit VPN must override executable exclusion"
    );
}

#[test]
fn actual_router_ip_rules_and_local_network_default_respect_explicit_vpn() {
    use std::process::{Command, Stdio};
    let Ok(binary) = std::env::var("SMARTVPN_TEST_CORE") else {
        return;
    };
    let http = HttpFixture::new();
    let server = offline_server();
    // Actual IP-literal rule (including pasted URL) without any LAN access.
    for route in ["direct", "vpn"] {
        let settings = Settings {
            mode: Mode::Direct,
            tun: false,
            kill_switch: false,
            ..Default::default()
        };
        let rules = vec![Rule {
            domain: format!("http://127.0.0.1:{}/webpages/index.html#/login", http.port),
            route: route.into(),
        }];
        let core =
            CoreProcess::start(std::path::Path::new(&binary), &server, &settings, &rules).unwrap();
        let result = fetch(core.proxy_port, &format!("http://127.0.0.1:{}/", http.port));
        assert_eq!(result.is_ok(), route == "direct");
    }
    // Redirect the matched LAN destination to a disposable loopback fixture.
    // Neither the user's router nor any physical interface is contacted/changed.
    struct FixtureCore(std::process::Child);
    impl Drop for FixtureCore {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    for force_vpn in [false, true] {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = proxy.local_addr().unwrap().port();
        drop(proxy);
        let settings = Settings {
            mode: Mode::Vpn,
            tun: false,
            kill_switch: false,
            ..Default::default()
        };
        let rules = if force_vpn {
            vec![Rule {
                domain: "192.168.0.1".into(),
                route: "vpn".into(),
            }]
        } else {
            vec![]
        };
        let mut cfg =
            smart_vpn_engine::vpn::config(&server, &settings, &rules, port, 0, "fixture").unwrap();
        cfg.as_object_mut().unwrap().remove("experimental");
        let lan = cfg["route"]["rules"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| {
                r["ip_cidr"]
                    .as_array()
                    .is_some_and(|v| v.contains(&serde_json::json!("192.168.0.0/16")))
            })
            .unwrap();
        lan["override_address"] = serde_json::json!("127.0.0.1");
        lan["override_port"] = serde_json::json!(http.port);
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("public-fixture.json");
        std::fs::write(&config, serde_json::to_vec(&cfg).unwrap()).unwrap();
        let mut command = Command::new(&binary);
        command
            .args(["run", "-c"])
            .arg(config)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(target_os = "macos")]
        let (_broker, child_fd) =
            smart_vpn_engine::app_process_broker::Broker::attach(&mut command, &[]).unwrap();
        let _core = FixtureCore(command.spawn().unwrap());
        #[cfg(target_os = "macos")]
        drop(child_fd);
        for _ in 0..60 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        let result = fetch(port, "http://192.168.0.1/webpages/index.html#/login");
        if force_vpn {
            assert!(result.is_err(), "explicit VPN must precede local default");
        } else {
            assert_eq!(result.unwrap(), "DIRECT");
        }
    }
}
