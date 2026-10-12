//! Windows network service protocol and privilege boundary. This is a transport
//! foundation: Start deliberately fails closed until native TUN/WFP acceptance.
use serde::{Deserialize, Serialize};

pub const SERVICE_NAME: &str = "foxVPNNetwork";
pub const PIPE: &str = r"\\.\pipe\foxVPN.Network.v1";
pub const SLOT: &str = r"C:\Program Files\foxVPN Network";
pub const CLIENT: &str = r"C:\Program Files\foxVPN\smart-vpn-desktop.exe";
pub const MAX_FRAME: usize = 512 * 1024;
pub const PROTOCOL: u32 = 1;

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Request {
    Status,
    Start(Box<crate::network_helper::StartRequest>),
    Stop,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub protocol: u32,
    pub version: String,
    pub core_alive: bool,
    pub tun_supported: bool,
    pub kill_switch_supported: bool,
    pub error: Option<String>,
}
impl Default for Status {
    fn default() -> Self {
        Self {
            protocol: PROTOCOL,
            version: env!("CARGO_PKG_VERSION").into(),
            core_alive: false,
            tun_supported: false,
            kill_switch_supported: false,
            error: None,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub protocol: u32,
    pub owner_sid: String,
    pub client_sha256: String,
    pub service_sha256: String,
}
impl Binding {
    pub fn validate(&self) -> Result<(), String> {
        // A normal local/domain user SID, never an alias/group or privileged SID.
        let sid: Vec<_> = self.owner_sid.split('-').collect();
        if self.protocol != PROTOCOL
            || sid.len() != 8
            || sid[..4] != ["S", "1", "5", "21"]
            || sid[4..].iter().any(|p| p.parse::<u32>().is_err())
            || sid[7].parse::<u32>().unwrap_or(0) < 1000
            || ![&self.client_sha256, &self.service_sha256].iter().all(|h| {
                h.len() == 64
                    && h.bytes()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            })
        {
            return Err("Invalid Windows service binding".into());
        }
        Ok(())
    }
}

pub fn decode(bytes: &[u8]) -> Result<Request, String> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err("Invalid Windows service frame".into());
    }
    serde_json::from_slice(bytes).map_err(|_| "Invalid Windows service request".into())
}

/// Core-owned routing and DNS only. No host DNS/route commands or client paths
/// enter the privileged process; release gate remains closed in dispatch below.
pub fn tun_config(
    request: &crate::network_helper::StartRequest,
) -> Result<serde_json::Value, String> {
    if !request.settings.tun || request.reserves.len() > 31 || request.rules.len() > 5000 {
        return Err("Invalid Windows TUN request".into());
    }
    if request.settings.dns_transport == "local" || !request.settings.dns_protection {
        return Err("Protected DNS is required for Windows TUN".into());
    }
    for server in std::iter::once(&request.server).chain(request.reserves.iter()) {
        let uri = server.uri()?;
        let parsed = crate::servers::Server::parse(&uri)?;
        if parsed.transport != server.transport || parsed.security != server.security {
            return Err("Invalid Windows service server".into());
        }
    }
    let mut settings = request.settings.clone();
    // WFP protection is owned by the service rather than the core config.
    settings.kill_switch = false;
    let mut config = crate::vpn::config(
        &request.server,
        &settings,
        &request.rules,
        2080,
        2081,
        "service-private",
    )?;
    config["inbounds"][1]["interface_name"] = serde_json::json!("foxVPN");
    // Avoid exposing a privileged core controller/proxy to unrelated local apps.
    config["inbounds"] = serde_json::json!([config["inbounds"][1].clone()]);
    config.as_object_mut().unwrap().remove("experimental");
    Ok(config)
}

pub fn dispatch(request: Request) -> Status {
    let mut status = Status::default();
    if let Request::Start(start) = request {
        status.error = Some(match tun_config(&start) {
            Err(error) => error,
            Ok(_) => "Windows TUN/WFP is not accepted; connection is disabled".into(),
        });
    }
    status
}

#[cfg(windows)]
pub mod native;

#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> Binding {
        Binding {
            protocol: PROTOCOL,
            owner_sid: "S-1-5-21-1-2-3-1001".into(),
            client_sha256: "a".repeat(64),
            service_sha256: "b".repeat(64),
        }
    }
    #[test]
    fn rejects_privileged_group_and_malformed_owners() {
        for sid in [
            "S-1-5-18",
            "S-1-5-32-544",
            "S-1-5-21-1-2-3-500",
            "S-1-5-21-1-2-3-1001)(A;;GA;;;WD)",
        ] {
            let mut b = binding();
            b.owner_sid = sid.into();
            assert!(b.validate().is_err());
        }
        assert!(binding().validate().is_ok());
    }
    #[test]
    fn frames_have_no_commands_paths_or_unknown_fields() {
        for bytes in [
            br#"{"operation":"exec","data":"cmd.exe"}"#.as_slice(),
            br#"{"operation":"stop","path":"C:\\anything"}"#,
            br#"{"operation":"install_update"}"#,
        ] {
            assert!(decode(bytes).is_err());
        }
        assert!(decode(&vec![b' '; MAX_FRAME + 1]).is_err());
        assert!(decode(br#"{"operation":"status"}"#).is_ok());
    }
    #[test]
    fn start_rejects_unprotected_dns_and_mismatched_server_fields() {
        let mut start = crate::network_helper::StartRequest {
            server: crate::servers::Server::parse(
                "vless://11111111-1111-1111-1111-111111111111@127.0.0.1:443?security=none&type=tcp",
            )
            .unwrap(),
            reserves: vec![],
            settings: crate::settings::Settings::default(),
            rules: vec![],
        };
        start.settings.dns_protection = false;
        assert!(tun_config(&start).is_err());
        start.settings.dns_protection = true;
        start.settings.dns_transport = "local".into();
        assert!(tun_config(&start).is_err());
        start.settings.dns_transport = "https".into();
        start.server.security = "reality".into();
        assert!(tun_config(&start).is_err());
        start.server.security = "none".into();
        start.reserves = vec![start.server.clone(); 32];
        assert!(tun_config(&start).is_err());
    }
    #[test]
    fn start_cannot_advertise_unaccepted_network_protection() {
        let start = crate::network_helper::StartRequest {
            server: crate::servers::Server::parse(
                "vless://11111111-1111-1111-1111-111111111111@127.0.0.1:443?security=none&type=tcp",
            )
            .unwrap(),
            reserves: vec![],
            settings: crate::settings::Settings::default(),
            rules: vec![],
        };
        let config = tun_config(&start).unwrap();
        assert_eq!(config["inbounds"].as_array().unwrap().len(), 1);
        assert_eq!(config["inbounds"][0]["interface_name"], "foxVPN");
        assert!(config.get("experimental").is_none());
        let status = dispatch(Request::Start(Box::new(start)));
        assert!(!status.core_alive && !status.tun_supported && !status.kill_switch_supported);
        assert!(status.error.is_some());
    }
}
