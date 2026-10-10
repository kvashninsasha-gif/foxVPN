use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use std::{
    io::Read,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    time::{Duration, Instant},
};
use url::{Host, Url};

pub fn edit(
    profile: &mut crate::settings::Profile,
    id: &str,
    name: &str,
    url: &str,
) -> Result<(), String> {
    let name = name.trim();
    let url = url.trim();
    if name.is_empty() || name.chars().count() > 128 {
        return Err("Название подписки должно содержать от 1 до 128 символов".into());
    }
    validate_url(url)?;
    if profile
        .subscriptions
        .iter()
        .any(|s| s.id != id && s.url == url)
    {
        return Err(crate::text("message_327").into());
    }
    let sub = profile
        .subscriptions
        .iter_mut()
        .find(|s| s.id == id)
        .ok_or(crate::text("message_328"))?;
    if sub.url != url {
        sub.updated_at = None;
    }
    sub.name = name.into();
    sub.url = url.into();
    Ok(())
}

pub fn source_is_current(
    profile: &crate::settings::Profile,
    id: &str,
    url: &str,
) -> Result<(), String> {
    if profile
        .subscriptions
        .iter()
        .any(|s| s.id == id && s.url == url)
    {
        Ok(())
    } else {
        Err("Подписка изменилась во время загрузки. Повторите обновление.".into())
    }
}
/// Conservative public Internet policy. Special-purpose blocks are excluded,
/// including mapped/transition IPv6, even when some subranges are global.
pub fn public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 168 || (b == 0 && (c == 0 || c == 2))))
                || (a == 192
                    && ((b == 31 && c == 196)
                        || (b == 52 && c == 193)
                        || (b == 88 && c == 99)
                        || (b == 175 && c == 48)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            s[0] & 0xe000 == 0x2000
                && !(s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] < 0x1000)
                && !(s[0] == 0x2620 && s[1] == 0x4f && s[2] == 0x8000)
        }
    }
}
pub fn checked_addresses(addresses: Vec<SocketAddr>) -> Result<Vec<SocketAddr>, String> {
    if addresses.is_empty() || addresses.iter().any(|a| !public_address(a.ip())) {
        return Err(crate::text("subscription_public_only").into());
    }
    Ok(addresses)
}
pub fn validate_url(raw: &str) -> Result<(), String> {
    let u = Url::parse(raw).map_err(|_| crate::text("message_239"))?;
    if u.scheme() != "https"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
    {
        return Err(crate::text("message_240").into());
    }
    match u.host() {
        Some(Host::Ipv4(ip)) if !public_address(ip.into()) => {
            return Err(crate::text("subscription_public_only").into())
        }
        Some(Host::Ipv6(ip)) if !public_address(ip.into()) => {
            return Err(crate::text("subscription_public_only").into())
        }
        Some(Host::Domain(host)) => {
            let host = host.trim_end_matches('.').to_ascii_lowercase();
            if host == "localhost"
                || host.ends_with(".localhost")
                || host.ends_with(".local")
                || host.ends_with(".home.arpa")
            {
                return Err(crate::text("subscription_public_only").into());
            }
        }
        _ => (),
    }
    Ok(())
}
pub fn decode(text: &str) -> Result<String, String> {
    if text.trim().starts_with("vless://") {
        return Ok(text.trim().into());
    }
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(&compact) {
            if let Ok(s) = String::from_utf8(bytes) {
                if s.trim().starts_with("vless://") {
                    return Ok(s);
                }
            }
        }
    }
    Err(crate::text("message_241").into())
}
pub fn fetch(raw: &str) -> Result<String, String> {
    let mut url = Url::parse(raw).map_err(|_| crate::text("message_239"))?;
    let deadline = Instant::now() + Duration::from_secs(25);
    let mut response = None;
    // Each redirect gets a fresh resolution, public-address validation and a
    // pinned connection. reqwest never performs a second, unvalidated lookup.
    for hop in 0..=3 {
        validate_url(url.as_str())?;
        let host = url
            .host_str()
            .ok_or(crate::text("message_240"))?
            .trim_matches(['[', ']']);
        let port = url
            .port_or_known_default()
            .ok_or(crate::text("message_240"))?;
        let addresses = checked_addresses(
            (host, port)
                .to_socket_addrs()
                .map_err(|_| crate::text("message_243"))?
                .collect(),
        )?;
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(crate::text("message_243"))?;
        let c = reqwest::blocking::Client::builder()
            .no_proxy()
            .https_only(true)
            .timeout(timeout)
            .resolve_to_addrs(host, &addresses)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| crate::text("message_242"))?;
        let next = c
            .get(url.clone())
            .send()
            .map_err(|_| crate::text("message_243"))?
            .error_for_status()
            .map_err(|_| crate::text("message_244"))?;
        if next.status().is_redirection() {
            if hop == 3 {
                return Err(crate::text("subscription_redirect_error").into());
            }
            let target = next
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|h| h.to_str().ok())
                .ok_or(crate::text("subscription_redirect_error"))?;
            url = url
                .join(target)
                .map_err(|_| crate::text("subscription_redirect_error"))?;
        } else {
            response = Some(next);
            break;
        }
    }
    let response = response.ok_or(crate::text("subscription_redirect_error"))?;
    let mut data = Vec::new();
    response
        .take(4_000_001)
        .read_to_end(&mut data)
        .map_err(|_| crate::text("message_245"))?;
    if data.len() > 4_000_000 {
        return Err(crate::text("message_246").into());
    }
    decode(std::str::from_utf8(&data).map_err(|_| crate::text("message_247"))?)
}
