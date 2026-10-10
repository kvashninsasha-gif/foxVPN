use smart_vpn_engine::network_helper::Request;
use smart_vpn_engine::network_helper::{valid_owner, Status, CORE_UID, PROTOCOL};
#[test]
fn a_manual_update_diagnoses_old_binding_and_other_owner() {
    use smart_vpn_engine::network_helper::binding_error;
    assert_eq!(
        binding_error(Some("old"), Some(501), "new", 501),
        Some("helper_upgrade")
    );
    assert_eq!(
        binding_error(Some("new"), None, "new", 501),
        Some("helper_upgrade")
    );
    assert_eq!(
        binding_error(None, Some(501), "new", 501),
        Some("helper_upgrade")
    );
    assert_eq!(
        binding_error(Some("new"), Some(502), "new", 501),
        Some("helper_owner")
    );
    assert_eq!(binding_error(Some("new"), Some(501), "new", 501), None);
}
#[test]
fn old_helpers_cannot_confirm_a_stop_or_enable_new_capabilities() {
    let old: Status = serde_json::from_str(r#"{"running":false,"wanted":false}"#).unwrap();
    assert!(!old.compatible());
    assert!(!old.stopped());
    let current = Status {
        protocol: PROTOCOL,
        helper_version: env!("CARGO_PKG_VERSION").into(),
        ..Default::default()
    };
    assert!(current.stopped());
    for state in [
        Status {
            running: true,
            ..current.clone()
        },
        Status {
            core_alive: true,
            ..current.clone()
        },
        Status {
            wanted: true,
            ..current.clone()
        },
        Status {
            kill_switch: true,
            ..current.clone()
        },
        Status {
            dns_active: true,
            ..current.clone()
        },
        Status {
            protocol: PROTOCOL + 1,
            ..current.clone()
        },
        Status {
            helper_version: "0.1.5".into(),
            ..current.clone()
        },
    ] {
        assert!(!state.stopped());
    }
}
#[test]
fn component_compatibility_uses_protocol_instead_of_every_app_release_number() {
    let current = Status {
        protocol: PROTOCOL,
        helper_version: "0.1.99".into(),
        ..Default::default()
    };
    assert!(current.compatible());
    assert!(current.stopped());
    assert!(!Status {
        protocol: PROTOCOL - 1,
        ..current.clone()
    }
    .compatible());
    assert!(!Status {
        helper_version: "invalid".into(),
        ..current
    }
    .compatible());
}
#[test]
fn a_helper_owner_must_be_a_normal_mac_user() {
    for uid in [0, 1, 500, CORE_UID, 65534, u32::MAX] {
        assert!(!valid_owner(uid));
    }
    for uid in [501, 502, 1000] {
        assert!(valid_owner(uid));
    }
}
#[test]
fn residual_protection_is_unknown_not_disconnected_or_reconnecting() {
    let current = Status {
        protocol: PROTOCOL,
        helper_version: env!("CARGO_PKG_VERSION").into(),
        ..Default::default()
    };
    assert_eq!(current.connection_state(), "disconnected");
    assert_eq!(
        Status {
            wanted: true,
            ..current.clone()
        }
        .connection_state(),
        "reconnecting"
    );
    for state in [
        Status {
            dns_active: true,
            ..current.clone()
        },
        Status {
            kill_switch: true,
            ..current.clone()
        },
        Status {
            core_alive: true,
            ..current.clone()
        },
        Status::default(),
    ] {
        assert_eq!(state.connection_state(), "unknown");
    }
    assert_eq!(
        Status {
            running: true,
            core_alive: true,
            wanted: true,
            ..current
        }
        .connection_state(),
        "connected"
    );
}
#[test]
fn rejects_arbitrary_paths_commands_and_unknown_operations() {
    for raw in [
        r#"{"operation":"shell","data":"id"}"#,
        r#"{"operation":"status","path":"/etc/passwd"}"#,
        r#"{"operation":"start","data":{"binary":"/bin/sh","config":{}}}"#,
    ] {
        assert!(serde_json::from_str::<Request>(raw).is_err(), "{raw}");
    }
}
#[test]
fn stop_and_recovery_have_no_caller_supplied_system_arguments() {
    assert!(serde_json::from_str::<Request>(r#"{"operation":"stop"}"#).is_ok());
    assert!(serde_json::from_str::<Request>(r#"{"operation":"test_recovery"}"#).is_ok());
    assert!(
        serde_json::from_str::<Request>(r#"{"operation":"stop","data":{"path":"/"}}"#).is_err()
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "Run explicitly with FOXVPN_TEST_RESOURCES from the final macOS bundle"]
fn installer_contains_the_current_owner_and_signature_without_a_profile() {
    use std::{fs, path::PathBuf, process::Command};
    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let resources = PathBuf::from(std::env::var("FOXVPN_TEST_RESOURCES").unwrap());
    let pkg = smart_vpn_engine::network_helper::create_installer(&resources).unwrap();
    let _cleanup = Scratch(pkg.parent().unwrap().to_owned());
    let expanded = pkg.parent().unwrap().join("expanded");
    assert!(Command::new("/usr/sbin/pkgutil")
        .arg("--expand-full")
        .arg(&pkg)
        .arg(&expanded)
        .status()
        .unwrap()
        .success());
    let network = expanded.join("Payload/Library/PrivilegedHelperTools/foxVPN/component");
    let binding: smart_vpn_engine::component_update::Binding =
        serde_json::from_slice(&fs::read(network.join("binding.json")).unwrap()).unwrap();
    assert_eq!(binding.owner, unsafe { libc::getuid() });
    assert_eq!(
        binding.current,
        smart_vpn_engine::network_helper::self_hash().unwrap()
    );
    assert_eq!(binding.previous, None);
    assert_eq!(binding.protocol, smart_vpn_engine::network_helper::PROTOCOL);
    let mut names = fs::read_dir(network)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        ["binding.json", "core", "helper", "network-version.json"]
    );
    assert!(fs::read_to_string(
        expanded.join("Payload/Library/LaunchDaemons/ru.smartvpn.router.network.plist")
    )
    .unwrap()
    .contains("/foxVPN/component/helper"));
    assert!(fs::read_to_string(expanded.join("Scripts/postinstall"))
        .unwrap()
        .contains("/foxVPN/component/binding.json"));
}
