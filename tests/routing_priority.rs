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
