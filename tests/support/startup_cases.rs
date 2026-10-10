//! Public fixtures from the production generator. No profile, Keychain, TUN,
//! network requests or machine-specific configuration is read by this harness.
use serde_json::{json, Value};
use smart_vpn_engine::{
    routing::{Mode, Rule},
    servers::Server,
    settings::Settings,
    vpn,
};

pub fn cases() -> Vec<Value> {
    let server = Server::parse("vless://11111111-1111-4111-8111-111111111111@127.0.0.1:9?security=none&type=tcp#public-startup-test").unwrap();
    let rules = vec![
        Rule {
            domain: "example.com".into(),
            route: "direct".into(),
        },
        Rule {
            domain: "*.example.org".into(),
            route: "vpn".into(),
        },
    ];
    let mut cases = Vec::new();
    for tun in [false, true] {
        for mode in [Mode::Smart, Mode::Vpn, Mode::Direct, Mode::Custom] {
            for provider in ["cloudflare", "google", "quad9"] {
                for transport in ["https", "tls", "local"] {
                    let settings = Settings {
                        mode: mode.clone(),
                        tun,
                        kill_switch: false,
                        dns_provider: provider.into(),
                        dns_transport: transport.into(),
                        dns_protection: transport != "local",
                        ..Default::default()
                    };
                    let mut config = vpn::config(
                        &server,
                        &settings,
                        &rules,
                        12345,
                        12346,
                        "public-startup-token",
                    )
                    .unwrap();
                    // Test the actual DNS/routing/outbound startup path while
                    // avoiding privileged interface creation on either OS.
                    config["inbounds"]
                        .as_array_mut()
                        .unwrap()
                        .retain(|v| v["type"] == "mixed");
                    cases.push(json!({"name": format!("{}-{mode:?}-{provider}-{transport}", if tun { "tun-dns" } else { "proxy" }), "config": config}));
                }
            }
        }
    }
    cases
}
