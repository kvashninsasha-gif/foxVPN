//! Start the TUN DNS configuration without a TUN inbound, routes or external requests.
use smart_vpn_engine::{servers::Server, settings::Settings, vpn};
use std::{
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
#[path = "support/startup_cases.rs"]
mod startup_cases;
#[test]
fn all_public_startup_cases_keep_vpn_dns_and_reject_legacy_detours() {
    let cases = startup_cases::cases();
    assert_eq!(cases.len(), 72);
    for case in cases {
        let cfg = &case["config"];
        assert!(vpn::validate_dns_detours(cfg).is_ok(), "{}", case["name"]);
        assert_eq!(cfg["inbounds"].as_array().unwrap().len(), 1);
        assert_eq!(cfg["inbounds"][0]["type"], "mixed");
        if cfg["dns"]["servers"][2]["type"] != "local" {
            assert_eq!(cfg["dns"]["servers"][2]["detour"], "vpn");
        }
        let mut bad = cfg.clone();
        bad["dns"]["servers"][0]["detour"] = serde_json::json!("direct");
        assert!(vpn::validate_dns_detours(&bad).is_err());
    }
}
struct Running {
    child: Child,
    directory: PathBuf,
}
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
fn start(binary: &str, legacy: bool) -> (Running, u16) {
    let server=Server::parse("vless://11111111-1111-4111-8111-111111111111@127.0.0.1:9?security=none&type=tcp#public-bootstrap-test").unwrap();
    let settings = Settings {
        tun: true,
        kill_switch: false,
        ..Default::default()
    };
    let port = vpn::free_port().unwrap();
    let api = vpn::free_port().unwrap();
    let mut config =
        vpn::config(&server, &settings, &[], port, api, "public-bootstrap-token").unwrap();
    config["inbounds"].as_array_mut().unwrap().truncate(1); // never create an interface
    if legacy {
        config["dns"]["servers"][0]["detour"] = serde_json::json!("direct");
    }
    let directory =
        std::env::temp_dir().join(format!("foxvpn-bootstrap-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("public.json");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let child = Command::new(binary)
        .args(["run", "-c"])
        .arg(path)
        .env_remove("FOXVPN_CORE_UID")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    (Running { child, directory }, port)
}
#[test]
fn tun_bootstrap_starts_and_legacy_empty_direct_detour_is_rejected() {
    let Ok(binary) = std::env::var("SMARTVPN_TEST_CORE") else {
        eprintln!("Real-core regression not run: SMARTVPN_TEST_CORE absent. Artifact startup gate is mandatory before release.");
        return;
    };
    let (mut bad, _) = start(&binary, true);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = bad.child.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Legacy configuration did not fail"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut bad.child.stderr.take().unwrap(), &mut stderr).unwrap();
    assert!(stderr.contains("empty direct outbound"), "{stderr}");
    let (mut good, port) = start(&binary, false);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        assert!(
            good.child.try_wait().unwrap().is_none(),
            "Fixed configuration exited during startup"
        );
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(100),
        )
        .is_ok()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Fixed configuration did not listen"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}
