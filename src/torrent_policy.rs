//! Mandatory direct-only policy for known torrent clients. User routes cannot
//! opt a protected client into VPN. Unknown owners are rejected on desktop;
//! protocol sniffing supplements process identity, never replaces it.
use serde_json::{json, Value};

const MAC_BUNDLES: &[&str] = &[
    "mediaget",
    "utorrent",
    "µtorrent",
    "μtorrent",
    "utorrent web",
    "µtorrent web",
    "bittorrent",
    "bittorrent web",
    "qbittorrent",
    "transmission",
    "deluge",
    "webtorrent",
    "folx",
    "vuze",
    "azureus",
    "biglybt",
    "frostwire",
    "tribler",
    "bitcomet",
    "bitlord",
    "tixati",
    "motrix",
    "free download manager",
];
pub const WINDOWS_PATH: &str = r"(?i)[\\/](?:mediaget|utorrent|µtorrent|μtorrent|utorrentie|utweb|bittorrent|btweb|qbittorrent|transmission-qt|transmission-daemon|transmission-cli|deluge|deluged|deluge-gtk|webtorrent|folx|vuze|azureus|biglybt|frostwire|tribler|bitcomet|bitlord|tixati|motrix|picotorrent|fdm)(?:[-_. ][^\\/]*)?\.exe$";
pub const MAC_PATH: &str = r"(?i)(?:^foxvpn:protected-torrent-owner$|/(?:mediaget|utorrent|µtorrent|μtorrent|utorrent web|µtorrent web|bittorrent|bittorrent web|qbittorrent|transmission|deluge|webtorrent|folx|vuze|azureus|biglybt|frostwire|tribler|bitcomet|bitlord|tixati|motrix|free download manager)\.app/)";
/// Broker discloses the actual path only for protected/user-selected bundles.
/// Other positively identified owners use a fixed non-sensitive marker.
pub const TORRENT_OWNER: &str = "foxvpn:protected-torrent-owner";
pub const OTHER_OWNER: &str = "foxvpn:identified-other-owner";
pub fn mac_torrent_path(path: &str) -> bool {
    let mut parts = path.split('/').peekable();
    while let Some(part) = parts.next() {
        let lower = part.to_lowercase();
        if lower
            .strip_suffix(".app")
            .is_some_and(|name| MAC_BUNDLES.contains(&name))
            && parts.peek().is_some_and(|next| !next.is_empty())
        {
            return true;
        }
    }
    false
}
pub fn require_helper(status: &crate::network_helper::Status) -> Result<(), String> {
    if !status.compatible()
        || !semver::Version::parse(&status.helper_version)
            .is_ok_and(|v| v >= semver::Version::new(0, 1, 34))
    {
        return Err(
            "Обновите сетевой компонент macOS: прежняя версия не поддерживает маршрут торрентов"
                .into(),
        );
    }
    Ok(())
}
pub fn desktop_rules(through_vpn: bool) -> Vec<Value> {
    if !cfg!(any(target_os = "macos", windows)) {
        return vec![];
    }
    let rules = vec![
        json!({"process_path_regex":[if cfg!(windows) { WINDOWS_PATH } else { MAC_PATH }],"action":"route","outbound":if through_vpn {"vpn"} else {"direct"}}),
    ];
    rules
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bundle_match_is_case_insensitive_includes_helpers_and_has_component_boundaries() {
        for path in [
            "/Applications/MediaGet.app/Contents/MacOS/MediaGet",
            "/Users/test/µTorrent.app/Contents/Helpers/Child",
            "/private/UTorRent Web.App/Contents/MacOS/utweb",
        ] {
            assert!(mac_torrent_path(path), "{path}");
        }
        for path in [
            "/Applications/MediaGet.app.evil/Contents/MacOS/MediaGet",
            "/Applications/NotMediaGet.app/Contents/MacOS/MediaGet",
            "/Applications/MediaGet.app",
            "/Applications/Safari.app/Contents/MacOS/Safari",
        ] {
            assert!(!mac_torrent_path(path), "{path}");
        }
    }
}
