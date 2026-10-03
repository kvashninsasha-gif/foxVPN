use smart_vpn_engine::{
    latency,
    routing::{Mode, Rule},
    servers::Server,
    settings::Settings,
    statistics,
    vpn::{free_port, CoreProcess},
};
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    time::Duration,
};
struct ServerCore(std::process::Child, std::path::PathBuf);
impl Drop for ServerCore {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}
#[test]
fn real_vless_roundtrip_and_clean_disconnect() {
    let Ok(binary) = std::env::var("SMARTVPN_TEST_CORE") else {
        return;
    };
    let uuid = "123e4567-e89b-12d3-a456-426614174000";
    let vless_port = free_port().unwrap();
    let dir = std::env::temp_dir().join(format!("smartvpn-loopback-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("server.json");
    std::fs::write(&path,serde_json::to_vec(&serde_json::json!({"log":{"disabled":true},"inbounds":[{"type":"vless","listen":"127.0.0.1","listen_port":vless_port,"users":[{"uuid":uuid}]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}})).unwrap()).unwrap();
    let child = Command::new(&binary)
        .args(["run", "-c"])
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _server = ServerCore(child, dir);
    for _ in 0..60 {
        if std::net::TcpStream::connect(format!("127.0.0.1:{vless_port}")).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50))
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let http_port = listener.local_addr().unwrap().port();
    let thread = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(8)))
            .unwrap();
        let mut request = [0; 4096];
        let count = stream.read(&mut request).unwrap();
        assert!(String::from_utf8_lossy(&request[..count]).contains("GET /verified"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nVLESS VERIFIED",
            )
            .unwrap();
    });
    let server = Server::parse(&format!(
        "vless://{uuid}@127.0.0.1:{vless_port}?security=none&type=tcp#Local-test"
    ))
    .unwrap();
    let settings = Settings {
        mode: Mode::Vpn,
        tun: false,
        kill_switch: false,
        ..Settings::default()
    };
    let core = CoreProcess::start(std::path::Path::new(&binary), &server, &settings, &[]).unwrap();
    let proxy_port = core.proxy_port;
    let runtime_dir = core.dir.clone();
    let response = latency::client(proxy_port)
        .unwrap()
        .get(format!("http://127.0.0.1:{http_port}/verified"))
        .send()
        .unwrap();
    assert_eq!(response.text().unwrap(), "VLESS VERIFIED");
    thread.join().unwrap();
    let mut measured = false;
    for _ in 0..20 {
        let stats = statistics::read(core.api_port, &core.secret).unwrap();
        if stats.upload > 0 || stats.download > 0 {
            measured = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100))
    }
    assert!(measured);
    drop(core);
    assert!(!runtime_dir.exists());
    assert!(std::net::TcpStream::connect(format!("127.0.0.1:{proxy_port}")).is_err());
}
#[test]
fn explicit_direct_rule_works_with_unavailable_vpn() {
    let Ok(binary) = std::env::var("SMARTVPN_TEST_CORE") else {
        return;
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let http_port = listener.local_addr().unwrap().port();
    let thread = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(8)))
            .unwrap();
        let mut request = [0; 4096];
        let _ = stream.read(&mut request).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nDIRECT")
            .unwrap();
    });
    let server = Server::parse(&format!(
        "vless://123e4567-e89b-12d3-a456-426614174000@127.0.0.1:{}?security=none",
        free_port().unwrap()
    ))
    .unwrap();
    let settings = Settings {
        mode: Mode::Smart,
        tun: false,
        kill_switch: false,
        dns_protection: false,
        dns_transport: "local".into(),
        ..Settings::default()
    };
    let core = CoreProcess::start(
        std::path::Path::new(&binary),
        &server,
        &settings,
        &[Rule {
            domain: "localhost".into(),
            route: "direct".into(),
        }],
    )
    .unwrap();
    let response = latency::client(core.proxy_port)
        .unwrap()
        .get(format!("http://localhost:{http_port}/"))
        .send()
        .unwrap();
    assert_eq!(response.text().unwrap(), "DIRECT");
    thread.join().unwrap();
}
#[test]
fn kill_switch_guard_prevents_unsafe_connect() {
    let s = Server::parse("vless://123e4567-e89b-12d3-a456-426614174000@127.0.0.1:443").unwrap();
    let result = CoreProcess::start(
        std::path::Path::new("nonexistent"),
        &s,
        &Settings::default(),
        &[],
    );
    assert!(result.err().unwrap().contains("Защита при обрыве"));
}

#[test]
fn stable_proxy_port_survives_restarts_and_isolated_probes() {
    let Ok(binary) = std::env::var("SMARTVPN_TEST_CORE") else {
        return;
    };
    let server =
        Server::parse("vless://123e4567-e89b-12d3-a456-426614174000@127.0.0.1:443?security=none")
            .unwrap();
    let settings = Settings {
        mode: Mode::Direct,
        tun: false,
        kill_switch: false,
        ..Settings::default()
    };
    let port = free_port().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let http_port = listener.local_addr().unwrap().port();
    let thread = std::thread::spawn(move || {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(8)))
                .unwrap();
            let mut request = [0; 4096];
            assert!(stream.read(&mut request).unwrap() > 0);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nSTABLE",
                )
                .unwrap();
        }
    });
    for _ in 0..3 {
        let core = CoreProcess::start_on_port(
            std::path::Path::new(&binary),
            &server,
            &settings,
            &[],
            port,
        )
        .unwrap();
        assert_eq!(core.proxy_port, port);
        let probe =
            CoreProcess::start(std::path::Path::new(&binary), &server, &settings, &[]).unwrap();
        assert_ne!(probe.proxy_port, port);
        let response = latency::client(port)
            .unwrap()
            .get(format!("http://127.0.0.1:{http_port}/"))
            .send()
            .unwrap();
        assert_eq!(response.text().unwrap(), "STABLE");
        drop(probe);
        let dir = core.dir.clone();
        drop(core);
        assert!(!dir.exists());
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
    }
    thread.join().unwrap();
}

#[test]
fn occupied_port_is_rejected_without_touching_an_existing_listener() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server =
        Server::parse("vless://123e4567-e89b-12d3-a456-426614174000@127.0.0.1:443?security=none")
            .unwrap();
    let settings = Settings {
        tun: false,
        kill_switch: false,
        ..Settings::default()
    };
    assert!(CoreProcess::start_on_port(
        std::path::Path::new("unused"),
        &server,
        &settings,
        &[],
        port
    )
    .is_err());
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
}
