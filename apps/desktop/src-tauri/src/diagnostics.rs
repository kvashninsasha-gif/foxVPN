use super::State;
use serde::Serialize;

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
