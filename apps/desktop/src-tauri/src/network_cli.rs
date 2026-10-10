//! Owner-bound diagnostics use the same signed executable and helper policy as the UI.
use smart_vpn_engine::{network_helper as ipc, settings::Vault};

#[derive(serde::Serialize)]
struct PublicStatus<'a> {
    state: &'static str,
    helper_version: &'a str,
    compatible: bool,
    core_alive: bool,
    dns_active: bool,
    wanted: bool,
    kill_switch: bool,
    interface: &'a str,
    proxy_port: u16,
    error: &'a Option<String>,
}
fn report(status: &ipc::Status) -> Result<String, String> {
    serde_json::to_string(&PublicStatus {
        state: status.connection_state(),
        helper_version: &status.helper_version,
        compatible: status.compatible(),
        core_alive: status.core_alive,
        dns_active: status.dns_active,
        wanted: status.wanted,
        kill_switch: status.kill_switch,
        interface: &status.interface,
        proxy_port: status.proxy_port,
        error: &status.error,
    })
    .map_err(|_| "Не удалось подготовить диагностику".into())
}
pub fn run(argument: &str) -> Option<Result<String, String>> {
    if !matches!(
        argument,
        "--foxvpn-network-status" | "--foxvpn-network-connect" | "--foxvpn-network-stop"
    ) {
        return None;
    }
    Some((|| {
        ipc::require_current()?;
        if argument == "--foxvpn-network-stop" {
            let status = ipc::request(&ipc::Request::Stop)?.status;
            if !status.stopped() {
                return Err("Остановка VPN не подтверждена".into());
            }
            return report(&status);
        }
        let current = ipc::request(&ipc::Request::Status)?.status;
        if argument == "--foxvpn-network-status" || current.running {
            return report(&current);
        }
        let profile = Vault::new("ru.smartvpn.router").load()?;
        profile.validate()?;
        if !profile.settings.tun {
            return Err("Системный VPN не выбран. Подтвердите настройку в приложении.".into());
        }
        let server = profile
            .servers
            .iter()
            .find(|s| Some(&s.id) == profile.selected.as_ref())
            .ok_or("Сначала выберите сервер в приложении")?;
        let reserves = smart_vpn_engine::latency::recovery_order(
            &profile.servers,
            &server.id,
            &profile.settings,
        )
        .iter()
        .filter(|id| *id != &server.id)
        .filter_map(|id| profile.servers.iter().find(|s| &s.id == id).cloned())
        .collect();
        let response = ipc::request(&ipc::Request::Start(Box::new(ipc::StartRequest {
            server: server.clone(),
            reserves,
            settings: profile.settings,
            rules: profile.rules,
        })))?;
        report(&response.status)
    })())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostic_output_never_contains_private_api_token_or_profile_identity() {
        let status = ipc::Status {
            secret: "PRIVATE_API_TOKEN".into(),
            active_server_id: Some("PRIVATE_SERVER_ID".into()),
            ..Default::default()
        };
        let text = report(&status).unwrap();
        assert!(!text.contains("PRIVATE_"));
        assert!(!text.contains("secret"));
        assert!(run("--other-argument").is_none());
    }
}
