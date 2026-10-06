use base64::Engine;
use smart_vpn_engine::{
    latency,
    routing::{self, Mode, Rule},
    servers::{import, Server},
    settings::{Profile, Settings},
    subscriptions, vpn,
};
fn plain() -> String {
    "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?type=tcp&security=tls#Example"
        .into()
}
fn reality() -> String {
    format!("vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?type=tcp&security=reality&sni=example.org&pbk={}&sid=12ab&fp=chrome&flow=xtls-rprx-vision#%D0%A4%D0%B8%D0%BD%D0%BB%D1%8F%D0%BD%D0%B4%D0%B8%D1%8F",base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8;32]))
}
#[test]
fn reality_fields_and_roundtrip() {
    let s = Server::parse(&reality()).unwrap();
    assert_eq!(s.name, "Финляндия");
    assert_eq!(s.security, "reality");
    assert_eq!(
        s.fingerprint(),
        Server::parse(&s.uri().unwrap()).unwrap().fingerprint()
    );
    let out = vpn::outbound(&s);
    assert_eq!(out["tls"]["reality"]["short_id"], "12ab");
    assert_eq!(out["flow"], "xtls-rprx-vision");
}
#[test]
fn ipv6_endpoint() {
    let raw = plain().replace("example.com", "[2001:db8::1]");
    let s = Server::parse(&raw).unwrap();
    assert_eq!(s.address, "2001:db8::1");
    assert_eq!(
        s.fingerprint(),
        Server::parse(&s.uri().unwrap()).unwrap().fingerprint()
    );
}
#[test]
fn bad_uuid() {
    assert!(Server::parse(&plain().replace("123e4567-e89b-12d3-a456-426614174000", "bad")).is_err())
}
#[test]
fn reject_ambiguous_duplicate_parameters() {
    assert!(Server::parse(&plain().replace("security=tls", "security=tls&security=none")).is_err())
}
#[test]
fn reject_invalid_reality_key_and_sid() {
    assert!(Server::parse(&reality().replace("sid=12ab", "sid=xyz")).is_err());
    assert!(Server::parse(&reality().replace("pbk=", "pbk=broken")).is_err());
}
#[test]
fn do_not_disable_certificate_validation() {
    assert!(
        Server::parse(&plain().replace("security=tls", "security=tls&allowInsecure=1")).is_err()
    )
}
#[test]
fn reject_vision_on_websocket() {
    assert!(Server::parse(&reality().replace("type=tcp", "type=ws")).is_err())
}
#[test]
fn preserve_unknown_parameters() {
    let s = Server::parse(&plain().replace("type=tcp", "type=tcp&extra=value")).unwrap();
    assert_eq!(
        Server::parse(&s.uri().unwrap()).unwrap().params["extra"],
        "value"
    )
}
#[test]
fn bulk_duplicate_names_are_not_identity() {
    let mut servers = vec![];
    let mut text = plain();
    text.push('\n');
    text.push_str(&plain().replace("#Example", "#Other"));
    text.push_str("\nvless://broken");
    let r = import(&text, &mut servers);
    assert_eq!((r.added, r.duplicates, r.errors.len()), (1, 1, 1));
}
#[test]
fn normalized_defaults_deduplicate() {
    let a = Server::parse(&plain()).unwrap();
    let b = Server::parse(&plain().replace("type=tcp&", "")).unwrap();
    assert_eq!(a.fingerprint(), b.fingerprint());
}
#[test]
fn idn_domains_direct() {
    assert_eq!(
        routing::decide("пример.РФ.", &Mode::Smart, &[])
            .unwrap()
            .route,
        "direct"
    );
    for host in ["yandex.ru", "ozon.ru", "example.su"] {
        assert_eq!(
            routing::decide(host, &Mode::Smart, &[]).unwrap().route,
            "direct"
        )
    }
}
#[test]
fn foreign_domains_vpn() {
    for host in ["youtube.com", "github.com", "chatgpt.com", "notru.com"] {
        assert_eq!(
            routing::decide(host, &Mode::Smart, &[]).unwrap().route,
            "vpn"
        )
    }
}
#[test]
fn explicit_rules_override_tld() {
    let rules = vec![
        Rule {
            domain: "bank.ru".into(),
            route: "vpn".into(),
        },
        Rule {
            domain: "*.example.com".into(),
            route: "direct".into(),
        },
    ];
    assert_eq!(
        routing::decide("bank.ru", &Mode::Smart, &rules)
            .unwrap()
            .route,
        "vpn"
    );
    assert_eq!(
        routing::decide("a.example.com", &Mode::Smart, &rules)
            .unwrap()
            .route,
        "direct"
    );
    assert_eq!(
        routing::decide("example.com", &Mode::Smart, &rules)
            .unwrap()
            .route,
        "vpn"
    );
    assert_eq!(
        routing::decide("example.com.evil.org", &Mode::Smart, &rules)
            .unwrap()
            .route,
        "vpn"
    )
}
#[test]
fn global_modes_override_rules() {
    let rules = vec![Rule {
        domain: "github.com".into(),
        route: "direct".into(),
    }];
    assert_eq!(
        routing::decide("github.com", &Mode::Vpn, &rules)
            .unwrap()
            .route,
        "vpn"
    );
    assert_eq!(
        routing::decide("youtube.com", &Mode::Direct, &rules)
            .unwrap()
            .route,
        "direct"
    );
}
#[test]
fn reject_duplicate_rules_after_idn_normalization() {
    assert!(routing::validate(&[
        Rule {
            domain: "пример.рф".into(),
            route: "direct".into()
        },
        Rule {
            domain: "xn--e1afmkfd.xn--p1ai".into(),
            route: "vpn".into()
        }
    ])
    .is_err())
}
#[test]
fn reject_host_injection() {
    for input in [
        "https://example.com",
        "example.com/path",
        "example.com:443",
        "x@host",
        "*.example.com",
        "foo_bar.com",
        "-bad.ru",
        "127.0.0.1",
        "bad..ru",
    ] {
        assert!(routing::normalize(input).is_err(), "{input}")
    }
}
#[test]
fn config_has_protected_dns_and_both_address_families() {
    let s = Server::parse(&reality()).unwrap();
    let c = vpn::config(&s, &Settings::default(), &[], 2080, 2081, "test-secret").unwrap();
    assert_eq!(c["dns"]["servers"][0]["type"], "https");
    assert_eq!(c["dns"]["servers"][0]["detour"], "direct");
    assert_eq!(c["outbounds"][0]["server"], s.address);
    assert_eq!(c["dns"]["servers"][2]["detour"], "vpn");
    assert_eq!(c["dns"]["final"], "dns-vpn");
    assert_eq!(c["inbounds"][1]["address"].as_array().unwrap().len(), 2);
    assert_eq!(c["route"]["rules"][0]["action"], "sniff");
    assert_eq!(c["route"]["rules"][1]["action"], "hijack-dns");
    assert!(c["route"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r.get("ip_is_private").is_none()));
}
#[test]
fn no_direct_fallback() {
    let c = vpn::config(
        &Server::parse(&plain()).unwrap(),
        &Settings::default(),
        &[],
        2080,
        2081,
        "secret",
    )
    .unwrap();
    assert_eq!(c["route"]["final"], "vpn");
    assert!(c["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .all(|o| o["type"] != "urltest"));
}
#[test]
fn websocket_and_grpc() {
    let s =
        Server::parse(&plain().replace("type=tcp", "type=ws&path=%2Fconnect&host=cdn.example.com"))
            .unwrap();
    assert_eq!(vpn::outbound(&s)["transport"]["path"], "/connect");
    let s = Server::parse(&plain().replace("type=tcp", "type=grpc&serviceName=tunnel")).unwrap();
    assert_eq!(vpn::outbound(&s)["transport"]["service_name"], "tunnel");
}
#[test]
fn settings_require_explicit_dns_security_choice() {
    let settings = Settings {
        dns_transport: "local".into(),
        ..Settings::default()
    };
    assert!(settings.validate().is_err());
}
#[test]
fn subscription_formats() {
    let raw = plain();
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        assert_eq!(subscriptions::decode(&engine.encode(&raw)).unwrap(), raw)
    }
    assert!(subscriptions::validate_url("http://example.com/sub").is_err());
    assert!(subscriptions::decode("<html>error</html>").is_err());
}
#[test]
fn selection_excludes_unavailable() {
    let mut a = Server::parse(&plain()).unwrap();
    a.status = "available".into();
    a.latency_ms = Some(50);
    let mut b = a.clone();
    b.id = "other".into();
    b.status = "unavailable".into();
    b.latency_ms = Some(1);
    assert_eq!(
        latency::select(&[a.clone(), b], &Settings::default()),
        Some(a.id)
    );
}
#[test]
fn profile_rejects_missing_selection() {
    let p = Profile {
        selected: Some("missing".into()),
        ..Profile::default()
    };
    assert!(p.validate().is_err())
}
#[test]
fn localized_core_error() {
    assert_eq!(
        vpn::friendly_error("connection refused"),
        "Сервер отклонил соединение"
    )
}
#[test]
fn validate_actual_sing_box_configs() {
    let Ok(binary) = std::env::var("SMARTVPN_TEST_CORE") else {
        return;
    };
    let dir = std::env::temp_dir().join(format!("smartvpn-schema-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    for mode in [Mode::Smart, Mode::Vpn, Mode::Direct, Mode::Custom] {
        for transport in ["tcp", "ws", "grpc"] {
            for security in ["none", "tls", "reality"] {
                let raw = if security == "reality" {
                    reality()
                        .replace("flow=xtls-rprx-vision&", "")
                        .replace("&flow=xtls-rprx-vision", "")
                } else {
                    plain().replace("security=tls", &format!("security={security}"))
                };
                let server =
                    Server::parse(&raw.replace("type=tcp", &format!("type={transport}"))).unwrap();
                let rules = vec![
                    Rule {
                        domain: "*.example.com".into(),
                        route: "vpn".into(),
                    },
                    Rule {
                        domain: "direct.org".into(),
                        route: "direct".into(),
                    },
                ];
                let c = vpn::config(
                    &server,
                    &Settings {
                        mode: mode.clone(),
                        ..Settings::default()
                    },
                    &rules,
                    2080,
                    2081,
                    "secret",
                )
                .unwrap();
                let file = dir.join("config.json");
                std::fs::write(&file, serde_json::to_vec(&c).unwrap()).unwrap();
                let r = std::process::Command::new(&binary)
                    .args(["check", "-c"])
                    .arg(&file)
                    .output()
                    .unwrap();
                assert!(
                    r.status.success(),
                    "{:?}/{transport}/{security}: {}",
                    mode,
                    String::from_utf8_lossy(&r.stderr)
                );
            }
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn encrypted_storage_detects_tampering() {
    use smart_vpn_engine::settings::{decrypt_profile, encrypt_profile};
    let key = [7u8; 32];
    let data = encrypt_profile(&key, b"private-profile").unwrap();
    assert_eq!(decrypt_profile(&key, &data).unwrap(), b"private-profile");
    assert!(decrypt_profile(&[8u8; 32], &data).is_err());
    let mut bad = data;
    bad[20] ^= 1;
    assert!(decrypt_profile(&key, &bad).is_err());
}
#[test]
fn hostile_backup_does_not_panic() {
    let mut p = Profile::default();
    let mut s = Server::parse(&plain()).unwrap();
    s.address = "broken[host".into();
    p.servers.push(s);
    assert!(p.validate().is_err());
}

#[test]
fn backup_cannot_disagree_about_security() {
    let mut p = Profile::default();
    let mut s = Server::parse(&plain()).unwrap();
    s.security = "none".into();
    p.servers.push(s);
    assert!(p.validate().is_err());
}
