use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use url::{Host, Url};
use uuid::Uuid;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Server {
    pub id: String,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub uuid: String,
    pub transport: String,
    pub security: String,
    pub params: BTreeMap<String, String>,
    pub favorite: bool,
    pub group: String,
    pub subscription: Option<String>,
    pub latency_ms: Option<u64>,
    pub download_mbps: Option<f64>,
    pub status: String,
    pub successes: u64,
    pub failures: u64,
    pub last_error: Option<String>,
}
impl Server {
    pub fn parse(raw: &str) -> Result<Self, String> {
        if raw.len() > 16384 {
            return Err(crate::text("message_219").into());
        }
        let u = Url::parse(raw.trim()).map_err(|_| crate::text("message_220"))?;
        if u.scheme() != "vless" {
            return Err(crate::text("message_221").into());
        }
        if u.password().is_some() {
            return Err(crate::text("message_222").into());
        }
        let uuid = Uuid::parse_str(u.username())
            .map_err(|_| crate::text("message_223"))?
            .to_string();
        let address = match u.host() {
            Some(Host::Domain(h)) => h.to_owned(),
            Some(Host::Ipv4(h)) => h.to_string(),
            Some(Host::Ipv6(h)) => h.to_string(),
            None => return Err(crate::text("message_224").into()),
        };
        let port = u
            .port()
            .filter(|p| *p > 0)
            .ok_or(crate::text("message_225"))?;
        let mut params = BTreeMap::new();
        for (k, v) in u.query_pairs() {
            if params.insert(k.to_string(), v.to_string()).is_some() {
                return Err(crate::text("parameter_duplicate").replace("{k}", &k));
            }
        }
        let transport = params.get("type").cloned().unwrap_or("tcp".into());
        if !["tcp", "ws", "grpc"].contains(&transport.as_str()) {
            return Err(crate::text("message_226").into());
        }
        let security = params.get("security").cloned().unwrap_or("none".into());
        if !["none", "tls", "reality"].contains(&security.as_str()) {
            return Err(crate::text("message_227").into());
        }
        if params.get("encryption").is_some_and(|v| v != "none") {
            return Err(crate::text("message_228").into());
        }
        if params
            .get("allowInsecure")
            .is_some_and(|v| ["1", "true"].contains(&v.as_str()))
        {
            return Err(crate::text("message_229").into());
        }
        let flow = params.get("flow").map(String::as_str).unwrap_or("");
        if !["", "xtls-rprx-vision"].contains(&flow) {
            return Err(crate::text("message_230").into());
        }
        if !flow.is_empty() && (transport != "tcp" || security == "none") {
            return Err(crate::text("message_231").into());
        }
        if security == "reality" {
            if params.get("sni").is_none_or(|s| s.is_empty()) {
                return Err(crate::text("message_232").into());
            }
            let key = params.get("pbk").ok_or(crate::text("message_233"))?;
            if URL_SAFE_NO_PAD.decode(key).map(|b| b.len()).unwrap_or(0) != 32 {
                return Err(crate::text("message_234").into());
            }
            let sid = params.get("sid").map(String::as_str).unwrap_or("");
            if sid.len() > 16 || sid.len() % 2 != 0 || !sid.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(crate::text("message_235").into());
            }
        }
        if params.get("fp").is_some_and(|v| {
            ![
                "chrome",
                "firefox",
                "safari",
                "edge",
                "ios",
                "android",
                "random",
                "randomized",
                "360",
                "qq",
            ]
            .contains(&v.as_str())
        }) {
            return Err(crate::text("message_236").into());
        }
        // Retain supported and unknown URI parameters in the vault and exported URI.
        let name = percent_encoding::percent_decode_str(u.fragment().unwrap_or(&address))
            .decode_utf8()
            .map_err(|_| crate::text("message_237"))?
            .to_string();
        if name.chars().count() > 200 || name.chars().any(|c| c.is_control()) {
            return Err(crate::text("invalid_server_name").into());
        }
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            name,
            address,
            port,
            uuid,
            transport,
            security,
            params,
            favorite: false,
            group: crate::text("main").into(),
            subscription: None,
            latency_ms: None,
            download_mbps: None,
            status: "untested".into(),
            successes: 0,
            failures: 0,
            last_error: None,
        })
    }
    pub fn fingerprint(&self) -> String {
        let mut params = self.params.clone();
        for k in ["type", "security", "encryption"] {
            params.remove(k);
        }
        let text = serde_json::to_string(&(
            &self.address.to_lowercase(),
            self.port,
            &self.uuid,
            &self.transport,
            &self.security,
            params,
        ))
        .unwrap();
        format!("{:x}", Sha256::digest(text.as_bytes()))
    }
    pub fn uri(&self) -> Result<String, String> {
        let host = if self.address.contains(':') {
            format!("[{}]", self.address)
        } else {
            self.address.clone()
        };
        let mut u = Url::parse(&format!("vless://{}@{}:{}", self.uuid, host, self.port))
            .map_err(|_| crate::text("message_238"))?;
        {
            let mut pairs = u.query_pairs_mut();
            for (k, v) in &self.params {
                pairs.append_pair(k, v);
            }
        }
        u.set_fragment(Some(&self.name));
        Ok(u.to_string())
    }
}
#[derive(Serialize)]
pub struct ImportReport {
    pub added: usize,
    pub duplicates: usize,
    pub errors: Vec<String>,
}
pub fn import(text: &str, servers: &mut Vec<Server>) -> ImportReport {
    let mut report = ImportReport {
        added: 0,
        duplicates: 0,
        errors: vec![],
    };
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match Server::parse(line) {
            Ok(s) => {
                if servers.iter().any(|v| v.fingerprint() == s.fingerprint()) {
                    report.duplicates += 1
                } else {
                    servers.push(s);
                    report.added += 1
                }
            }
            Err(e) => report.errors.push(
                crate::text("import_line_error")
                    .replace("{line}", &(n + 1).to_string())
                    .replace("{error}", &e),
            ),
        }
    }
    report
}
