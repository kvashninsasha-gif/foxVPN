use smart_vpn_engine::{
    routing::Rule,
    servers::Server,
    settings::{self, ConnectionPlan, Profile},
};
fn legacy_profile() -> Profile {
    let mut p = Profile::default();
    let mut server = Server::parse(
        "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=tls#Existing",
    )
    .unwrap();
    server.favorite = true;
    server.latency_ms = Some(88);
    server.download_mbps = Some(16.4);
    p.selected = Some(server.id.clone());
    p.servers.push(server);
    p.rules.push(Rule {
        domain: "example.ru".into(),
        route: "vpn".into(),
    });
    p.settings.dns_provider = "quad9".into();
    p
}
#[test]
fn first_run_requests_server() {
    assert_eq!(
        settings::connection_plan(&Profile::default()),
        ConnectionPlan::NeedsServer
    );
}
#[test]
fn legacy_defaults_request_proxy_choice_without_changing_profile() {
    let p = legacy_profile();
    let before = serde_json::to_value(&p).unwrap();
    assert_eq!(
        settings::connection_plan(&p),
        ConnectionPlan::NeedsProxyConsent
    );
    assert_eq!(serde_json::to_value(p).unwrap(), before);
}
#[test]
fn explicit_proxy_choice_preserves_every_other_setting() {
    let p = legacy_profile();
    let mut expected = serde_json::to_value(&p).unwrap();
    let next = settings::prepare_proxy(&p, p.selected.as_deref().unwrap()).unwrap();
    expected["settings"]["tun"] = false.into();
    expected["settings"]["kill_switch"] = false.into();
    expected["settings"]["proxy_acknowledged"] = true.into();
    assert_eq!(serde_json::to_value(&next).unwrap(), expected);
    assert_eq!(settings::connection_plan(&next), ConnectionPlan::Ready);
    assert!(p.settings.tun && p.settings.kill_switch);
}
#[test]
fn changed_selection_does_not_apply_old_confirmation() {
    let p = legacy_profile();
    let before = serde_json::to_value(&p).unwrap();
    assert!(settings::prepare_proxy(&p, "different-server").is_err());
    assert_eq!(serde_json::to_value(p).unwrap(), before);
}
#[test]
fn old_backup_loads_without_silently_downgrading_protection() {
    let p = legacy_profile();
    let mut raw = serde_json::to_value(p).unwrap();
    raw["settings"]
        .as_object_mut()
        .unwrap()
        .remove("proxy_acknowledged");
    let restored: Profile = serde_json::from_value(raw).unwrap();
    assert!(restored.settings.tun && restored.settings.kill_switch);
    assert!(!restored.settings.proxy_acknowledged);
    assert_eq!(
        settings::connection_plan(&restored),
        ConnectionPlan::NeedsProxyConsent
    );
}
#[test]
fn enabling_unsupported_option_requires_setup_again() {
    let mut p = legacy_profile();
    p = settings::prepare_proxy(&p, p.selected.as_deref().unwrap()).unwrap();
    p.settings.kill_switch = true;
    assert_eq!(
        settings::connection_plan(&p),
        ConnectionPlan::NeedsProxyConsent
    );
}

#[test]
fn proxy_choice_survives_restart_settings_save_and_server_selection() {
    let p = legacy_profile();
    let chosen = settings::prepare_proxy(&p, p.selected.as_deref().unwrap()).unwrap();
    let mut restored: Profile =
        serde_json::from_slice(&serde_json::to_vec(&chosen).unwrap()).unwrap();
    restored.settings.health_interval = 60;
    let other = Server::parse(
        "vless://123e4567-e89b-12d3-a456-426614174001@example.org:443?security=tls#Other",
    )
    .unwrap();
    restored.selected = Some(other.id.clone());
    restored.servers.push(other);
    restored.validate().unwrap();
    assert_eq!(settings::connection_plan(&restored), ConnectionPlan::Ready);
}
