use crate::{routing::Mode, servers::Server, settings::Settings, vpn::CoreProcess};
use serde::Serialize;
use std::{
    path::Path,
    time::{Duration, Instant},
};
#[derive(Serialize)]
pub struct Measurement {
    pub latency_ms: u64,
    pub download_mbps: Option<f64>,
    pub bytes: u64,
}
pub fn client(port: u16) -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .proxy(
            reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))
                .map_err(|_| crate::text("message_248"))?,
        )
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|_| crate::text("message_249").into())
}
pub fn measure(binary: &Path, s: &Server, speed: bool) -> Result<Measurement, String> {
    let settings = Settings {
        mode: Mode::Vpn,
        tun: false,
        kill_switch: false,
        ..Settings::default()
    };
    let process = CoreProcess::start(binary, s, &settings, &[])?;
    measure_port(process.proxy_port, if speed { 10_000_000 } else { 0 })
}
/// Measure the existing connection, without starting another tunnel.
pub fn measure_port(port: u16, download_bytes: u64) -> Result<Measurement, String> {
    let c = client(port)?;
    let mut samples = vec![];
    for _ in 0..3 {
        let now = Instant::now();
        let r = c
            .get("https://www.gstatic.com/generate_204")
            .send()
            .map_err(|e| crate::vpn::friendly_error(&e.to_string()))?;
        if r.status().as_u16() != 204 {
            return Err(crate::text("message_250").into());
        }
        samples.push(now.elapsed().as_millis() as u64);
    }
    samples.sort();
    let mut result = Measurement {
        latency_ms: samples[1],
        download_mbps: None,
        bytes: 0,
    };
    if download_bytes > 0 {
        let now = Instant::now();
        let mut response = c
            .get(format!(
                "https://speed.cloudflare.com/__down?bytes={download_bytes}"
            ))
            .send()
            .map_err(|e| crate::vpn::friendly_error(&e.to_string()))?
            .error_for_status()
            .map_err(|_| crate::text("message_251"))?;
        let bytes = std::io::copy(
            &mut std::io::Read::take(&mut response, download_bytes + 1),
            &mut std::io::sink(),
        )
        .map_err(|_| crate::text("message_252"))?;
        if bytes != download_bytes {
            return Err(crate::text("message_253").into());
        }
        result.bytes = bytes;
        result.download_mbps = Some(bytes as f64 * 8.0 / now.elapsed().as_secs_f64() / 1_000_000.0);
    }
    Ok(result)
}
pub fn select(servers: &[Server], settings: &Settings) -> Option<String> {
    let candidates: Vec<_> = servers
        .iter()
        .filter(|s| s.status == "available" || s.status == "slow")
        .filter(|s| !settings.favorites_only || s.favorite)
        .collect();
    if settings.strategy == "random" && !candidates.is_empty() {
        let seed = uuid::Uuid::new_v4().as_u128();
        return Some(
            candidates[(seed % candidates.len() as u128) as usize]
                .id
                .clone(),
        );
    }
    candidates
        .into_iter()
        .max_by(|a, b| score(a, settings).total_cmp(&score(b, settings)))
        .map(|s| s.id.clone())
}
fn score(s: &Server, settings: &Settings) -> f64 {
    let latency = s.latency_ms.unwrap_or(10_000) as f64;
    let stability = (s.successes + 1) as f64 / (s.successes + s.failures + 2) as f64;
    match settings.strategy.as_str() {
        "latency" => -latency,
        "speed" => s.download_mbps.unwrap_or(0.0),
        "stability" => stability,
        _ => stability * 1000.0 - latency + s.download_mbps.unwrap_or(0.0) * 0.1,
    }
}
