use super::State;
use serde::Serialize;

/// A Start acknowledgement is usable only when every protected path is ready
/// and it refers to the port requested by this connection attempt.
pub fn confirmed_remote_start(
    status: &smart_vpn_engine::network_helper::Status,
    expected_port: u16,
) -> bool {
    status.compatible()
        && status.running
        && status.wanted
        && status.core_alive
        && status.dns_active
        && status.proxy_port >= 1024
        && status.proxy_port == expected_port
}

pub fn connection_error(
    state: &str,
    helper: Option<String>,
    previous: Option<String>,
) -> Option<String> {
    if state == "connected" {
        None
    } else {
        helper.or(previous)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready_status() -> smart_vpn_engine::network_helper::Status {
        smart_vpn_engine::network_helper::Status {
            protocol: smart_vpn_engine::network_helper::PROTOCOL,
            helper_version: "0.1.29".into(),
            running: true,
            wanted: true,
            core_alive: true,
            dns_active: true,
            proxy_port: 2080,
            ..Default::default()
        }
    }

    #[test]
    fn remote_start_accepts_only_the_requested_ready_tunnel() {
        let ready = ready_status();
        assert!(confirmed_remote_start(&ready, 2080));
        assert!(!confirmed_remote_start(&ready, 2081));

        // A stale/helper failure must not be acknowledged as a successful
        // connection just because it returned a running core or an open port.
        for invalid in [
            smart_vpn_engine::network_helper::Status {
                protocol: 0,
                ..ready.clone()
            },
            smart_vpn_engine::network_helper::Status {
                helper_version: "0.1.22".into(),
                ..ready.clone()
            },
            smart_vpn_engine::network_helper::Status {
                helper_version: "invalid".into(),
                ..ready.clone()
            },
            smart_vpn_engine::network_helper::Status {
                helper_version: "0.1.29-beta.1".into(),
                ..ready.clone()
            },
            smart_vpn_engine::network_helper::Status {
                running: false,
                ..ready.clone()
            },
            smart_vpn_engine::network_helper::Status {
                wanted: false,
                ..ready.clone()
            },
            smart_vpn_engine::network_helper::Status {
                core_alive: false,
                ..ready.clone()
            },
            smart_vpn_engine::network_helper::Status {
                dns_active: false,
                ..ready.clone()
            },
        ] {
            assert!(!confirmed_remote_start(&invalid, 2080));
        }
        for port in [0, 1, 1023] {
            let invalid = smart_vpn_engine::network_helper::Status {
                proxy_port: port,
                ..ready.clone()
            };
            assert!(!confirmed_remote_start(&invalid, port));
        }
        for port in [1024, u16::MAX] {
            let valid = smart_vpn_engine::network_helper::Status {
                proxy_port: port,
                ..ready.clone()
            };
            assert!(confirmed_remote_start(&valid, port));
        }
    }

    #[test]
    fn failed_start_is_visible_until_recovery_and_new_helper_errors_take_priority() {
        assert_eq!(
            connection_error("disconnected", None, Some("Start failed".into())),
            Some("Start failed".into())
        );
        assert_eq!(
            connection_error(
                "reconnecting",
                Some("DNS failed".into()),
                Some("Start failed".into())
            ),
            Some("DNS failed".into())
        );
        assert_eq!(
            connection_error("connected", None, Some("Start failed".into())),
            None
        );
    }
}

#[derive(Serialize)]
pub struct Diagnostics {
    version: &'static str,
    platform: &'static str,
    architecture: &'static str,
    core_present: bool,
    core_verified: bool,
    status: String,
    proxy_port: Option<u16>,
    system_vpn_supported: bool,
}

pub fn verify_core(state: &State) -> Result<(), String> {
    let metadata = state
        .binary
        .parent()
        .ok_or_else(|| smart_vpn_engine::text("core_integrity_error").to_string())?
        .join("version.json");
    smart_vpn_engine::core_integrity::verify(
        &state.binary,
        &metadata,
        &smart_vpn_engine::core_integrity::platform(),
    )
}

#[tauri::command]
pub async fn connection_diagnostics(state: tauri::State<'_, State>) -> Result<Diagnostics, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let core_verified = verify_core(&state).is_ok();
        let status = state
            .status
            .lock()
            .map_err(|_| "Не удалось прочитать состояние")?
            .clone();
        let proxy_port = state
            .core
            .lock()
            .map_err(|_| "Не удалось прочитать состояние")?
            .as_ref()
            .map(|core| core.proxy_port);
        Ok(Diagnostics {
            version: env!("CARGO_PKG_VERSION"),
            platform: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
            core_present: state.binary.is_file(),
            core_verified,
            status,
            proxy_port,
            system_vpn_supported: cfg!(target_os = "macos"),
        })
    })
    .await
    .map_err(|_| "Не удалось выполнить диагностику".to_string())?
}
