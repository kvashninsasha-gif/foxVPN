#[test]
#[ignore = "requires the final pinned macOS network core; schema check only"]
fn network_core_accepts_helper_tun_configuration_without_starting_an_interface() {
    use smart_vpn_engine::{servers::Server, settings::Settings, vpn};
    let core = std::env::var("FOXVPN_TEST_NETWORK_CORE").expect("network core path");
    let server = Server::parse("vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&type=tcp&sni=example.com#public-schema-check").unwrap();
    let settings = Settings {
        tun: true,
        kill_switch: false,
        ..Default::default()
    };
    let mut config =
        vpn::config(&server, &settings, &[], 2080, 2081, "public-schema-token").unwrap();
    config["inbounds"][1]["interface_name"] = serde_json::json!("utun99");
    config["inbounds"][1]["dns_mode"] = serde_json::json!("disabled");
    let directory =
        std::env::temp_dir().join(format!("foxvpn-network-schema-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("public-test.json");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let result = std::process::Command::new(core)
        .args(["check", "-c"])
        .arg(&path)
        .output()
        .unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
    assert!(
        result.status.success(),
        "Public fixture error: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}
