//! Real UDP DNS over SOCKS5: the destination is deliberately unreachable.
//! Passing proves the engine intercepted DNS rather than forwarding it.
use smart_vpn_engine::{servers::Server, settings::Settings, vpn};
use std::{
    io::{Read, Write},
    net::{TcpStream, UdpSocket},
    process::{Command, Stdio},
    time::Duration,
};
#[test]
fn dns_is_intercepted_after_protocol_sniffing() {
    let Ok(binary) = std::env::var("SMARTVPN_TEST_CORE") else {
        return;
    };
    let dns = UdpSocket::bind("127.0.0.1:0").unwrap();
    dns.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let dns_port = dns.local_addr().unwrap().port();
    let responder = std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        let (n, peer) = dns.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[12..n], b"\x07example\x03com\0\0\x01\0\x01");
        let mut reply = buf[..n].to_vec();
        reply[2] = 0x81;
        reply[3] = 0x80;
        reply[6] = 0;
        reply[7] = 1;
        reply.extend_from_slice(b"\xc0\x0c\0\x01\0\x01\0\0\0\x3c\0\x04\xcb\0\x71\x07");
        dns.send_to(&reply, peer).unwrap();
    });
    let server = Server::parse(
        "vless://123e4567-e89b-12d3-a456-426614174000@192.0.2.1:443?security=none#Unreachable",
    )
    .unwrap();
    let settings = Settings {
        tun: false,
        kill_switch: false,
        ..Settings::default()
    };
    let port = vpn::free_port().unwrap();
    let mut config = vpn::config(
        &server,
        &settings,
        &[],
        port,
        vpn::free_port().unwrap(),
        "test-only",
    )
    .unwrap();
    config["dns"] = serde_json::json!({"servers":[{"type":"udp","tag":"test","server":"127.0.0.1","server_port":dns_port}],"final":"test"});
    config["route"]["default_domain_resolver"] = serde_json::json!("test");
    config["outbounds"][0]["domain_resolver"] = serde_json::json!("test");
    let dir = std::env::temp_dir().join(format!("foxvpn-dns-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("config.json");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let child = Command::new(&binary)
        .args(["run", "-c"])
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    struct Cleanup(std::process::Child, std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
            let _ = std::fs::remove_dir_all(&self.1);
        }
    }
    let _cleanup = Cleanup(child, dir);
    let mut control = None;
    for _ in 0..60 {
        if let Ok(c) = TcpStream::connect(("127.0.0.1", port)) {
            control = Some(c);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut control = control.expect("core listening");
    control
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    control.write_all(&[5, 1, 0]).unwrap();
    let mut greeting = [0; 2];
    control.read_exact(&mut greeting).unwrap();
    assert_eq!(greeting, [5, 0]);
    control
        .write_all(&[5, 3, 0, 1, 127, 0, 0, 1, 0, 0])
        .unwrap();
    let mut relay = [0; 10];
    control.read_exact(&mut relay).unwrap();
    assert_eq!(&relay[..4], &[5, 0, 0, 1]);
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut request = vec![0, 0, 0, 1, 192, 0, 2, 1, 0, 53];
    request.extend_from_slice(b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x07example\x03com\0\0\x01\0\x01");
    udp.send_to(
        &request,
        ("127.0.0.1", u16::from_be_bytes([relay[8], relay[9]])),
    )
    .unwrap();
    let mut answer = [0; 2048];
    let (n, _) = udp.recv_from(&mut answer).expect("intercepted DNS reply");
    assert_eq!(&answer[10..12], &[0x12, 0x34]);
    assert_eq!(&answer[n - 4..n], &[203, 0, 113, 7]);
    responder.join().unwrap();
}
