use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use std::{io::Read, time::Duration};
use url::Url;
pub fn validate_url(raw: &str) -> Result<(), String> {
    let u = Url::parse(raw).map_err(|_| crate::text("message_239"))?;
    if u.scheme() != "https"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
    {
        return Err(crate::text("message_240").into());
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
    validate_url(raw)?;
    let c = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(25))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 3 || attempt.url().scheme() != "https" {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .build()
        .map_err(|_| crate::text("message_242"))?;
    let response = c
        .get(raw)
        .send()
        .map_err(|_| crate::text("message_243"))?
        .error_for_status()
        .map_err(|_| crate::text("message_244"))?;
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
