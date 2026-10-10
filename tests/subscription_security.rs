use smart_vpn_engine::subscriptions::{checked_addresses, public_address, validate_url};
#[test]
fn local_special_and_obfuscated_literal_urls_are_rejected() {
    for host in [
        "localhost",
        "foo.localhost.",
        "device.local",
        "router.home.arpa",
        "127.0.0.1",
        "127.1",
        "2130706433",
        "0x7f000001",
        "10.1.2.3",
        "172.16.1.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "[::1]",
        "[::ffff:127.0.0.1]",
        "[fc00::1]",
        "[fe80::1]",
        "[2001:db8::1]",
        "[2002:7f00:1::1]",
        "[64:ff9b::7f00:1]",
    ] {
        assert!(
            validate_url(&format!("https://{host}/sub")).is_err(),
            "{host}"
        );
    }
    for url in [
        "https://example.com/sub",
        "https://8.8.8.8/sub",
        "https://[2606:4700::1111]/sub",
    ] {
        assert!(validate_url(url).is_ok());
    }
}
#[test]
fn resolution_rejects_empty_private_or_mixed_answers_before_connection() {
    assert!(checked_addresses(vec![]).is_err());
    assert!(checked_addresses(vec![
        "8.8.8.8:443".parse().unwrap(),
        "127.0.0.1:443".parse().unwrap()
    ])
    .is_err());
    assert!(checked_addresses(vec!["192.168.1.1:443".parse().unwrap()]).is_err());
    assert!(checked_addresses(vec!["8.8.8.8:443".parse().unwrap()]).is_ok());
}
#[test]
fn private_ipv6_transition_and_documentation_addresses_never_become_public() {
    for ip in [
        "::",
        "::1",
        "::ffff:8.8.8.8",
        "2001::1",
        "2001:2::1",
        "2001:db8::1",
        "2002:0808:0808::1",
        "3fff::1",
        "ff02::1",
        "240.0.0.1",
        "192.0.2.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
    ] {
        assert!(!public_address(ip.parse().unwrap()), "{ip}");
    }
    for ip in [
        "8.8.8.8",
        "1.1.1.1",
        "9.9.9.9",
        "2001:4860:4860::8888",
        "2606:4700:4700::1111",
    ] {
        assert!(public_address(ip.parse().unwrap()), "{ip}");
    }
}

#[test]
fn editing_subscription_is_atomic_and_rejects_stale_sources() {
    use smart_vpn_engine::{
        settings::{Profile, Subscription},
        subscriptions,
    };
    let mut profile = Profile::default();
    profile.subscriptions.push(Subscription {
        id: "test".into(),
        name: "Old".into(),
        url: "https://example.com/old".into(),
        updated_at: Some(1),
        server_count: 2,
    });
    let original = serde_json::to_string(&profile).unwrap();
    assert!(subscriptions::edit(&mut profile, "test", "", "https://example.com/new").is_err());
    assert!(subscriptions::edit(&mut profile, "test", "New", "https://127.0.0.1/new").is_err());
    assert_eq!(serde_json::to_string(&profile).unwrap(), original);
    subscriptions::edit(&mut profile, "test", " New ", "https://example.com/new").unwrap();
    assert_eq!(profile.subscriptions[0].name, "New");
    assert_eq!(profile.subscriptions[0].updated_at, None);
    assert_eq!(profile.subscriptions[0].server_count, 2);
    assert!(subscriptions::source_is_current(&profile, "test", "https://example.com/old").is_err());
    assert!(subscriptions::source_is_current(&profile, "test", "https://example.com/new").is_ok());
    profile.subscriptions.clear();
    assert!(subscriptions::source_is_current(&profile, "test", "https://example.com/new").is_err());
}
