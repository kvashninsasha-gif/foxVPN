use serde::Serialize;
#[derive(Default, Serialize, Clone)]
pub struct Traffic {
    pub upload: u64,
    pub download: u64,
    pub vpn_upload: u64,
    pub vpn_download: u64,
    pub direct_upload: u64,
    pub direct_download: u64,
    pub connections: Vec<Connection>,
}
#[derive(Serialize, Clone)]
pub struct Connection {
    pub domain: String,
    pub route: String,
    pub upload: u64,
    pub download: u64,
}
pub fn read(port: u16, secret: &str) -> Result<Traffic, String> {
    let c = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .map_err(|_| crate::text("message_254"))?;
    let v: serde_json::Value = c
        .get(format!("http://127.0.0.1:{port}/connections"))
        .bearer_auth(secret)
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.json())
        .map_err(|_| crate::text("message_255"))?;
    let mut t = Traffic {
        upload: v["uploadTotal"].as_u64().unwrap_or(0),
        download: v["downloadTotal"].as_u64().unwrap_or(0),
        ..Traffic::default()
    };
    if let Some(list) = v["connections"].as_array() {
        for item in list.iter().take(100) {
            let vpn = item["chains"]
                .as_array()
                .is_some_and(|a| a.iter().any(|s| s.as_str() == Some("vpn")));
            let up = item["upload"].as_u64().unwrap_or(0);
            let down = item["download"].as_u64().unwrap_or(0);
            if vpn {
                t.vpn_upload += up;
                t.vpn_download += down
            } else {
                t.direct_upload += up;
                t.direct_download += down
            }
            t.connections.push(Connection {
                domain: item["metadata"]["host"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .or(item["metadata"]["destinationIP"].as_str())
                    .unwrap_or("—")
                    .into(),
                route: if vpn { "vpn" } else { "direct" }.into(),
                upload: up,
                download: down,
            });
        }
    }
    Ok(t)
}
