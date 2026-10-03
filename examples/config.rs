fn main() {
    let server = smart_vpn_engine::servers::Server::parse(
        "vless://123e4567-e89b-12d3-a456-426614174000@127.0.0.1:20988?security=none&type=tcp",
    )
    .unwrap();
    let settings = smart_vpn_engine::settings::Settings {
        mode: smart_vpn_engine::routing::Mode::Vpn,
        tun: false,
        kill_switch: false,
        ..Default::default()
    };
    println!(
        "{}",
        serde_json::to_string_pretty(
            &smart_vpn_engine::vpn::config(&server, &settings, &[], 20987, 20986, "test-secret")
                .unwrap()
        )
        .unwrap()
    );
}
