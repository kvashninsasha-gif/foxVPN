use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Smart,
    Vpn,
    Direct,
    Custom,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rule {
    pub domain: String,
    pub route: String,
}
#[derive(Serialize)]
pub struct Decision {
    pub domain: String,
    pub route: String,
    pub reason: String,
}
pub fn normalize(input: &str) -> Result<String, String> {
    let input = input.trim();
    if input.chars().any(char::is_control) {
        return Err(crate::text("message_256").into());
    }
    let value = if input.contains("://") {
        let url = url::Url::parse(input).map_err(|_| crate::text("message_257"))?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(crate::text("message_256").into());
        }
        match url
            .host()
            .ok_or_else(|| crate::text("message_257").to_string())?
        {
            url::Host::Ipv4(ip) => return Ok(ip.to_string()),
            url::Host::Ipv6(ip) => return Ok(ip.to_string()),
            url::Host::Domain(domain) => domain.trim_end_matches('.').to_lowercase(),
        }
    } else {
        input.trim_end_matches('.').to_lowercase()
    };
    let ip_literal = value
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .unwrap_or(&value);
    if let Ok(ip) = ip_literal.parse::<std::net::IpAddr>() {
        return Ok(ip.to_string());
    }
    if value.is_empty() || value.contains('/') || value.contains(':') || value.contains('@') {
        return Err(crate::text("message_256").into());
    }
    let host = url::Host::parse(&value).map_err(|_| crate::text("message_257"))?;
    if !matches!(host, url::Host::Domain(_)) {
        return Err(crate::text("message_257").into());
    }
    let domain = host.to_string();
    if domain.len() > 253
        || domain.split('.').any(|s| {
            s.is_empty()
                || s.len() > 63
                || s.starts_with('-')
                || s.ends_with('-')
                || !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
    {
        return Err(crate::text("message_257").into());
    }
    Ok(domain)
}
pub fn validate(rules: &[Rule]) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    for r in rules {
        if !["vpn", "direct"].contains(&r.route.as_str()) {
            return Err(crate::text("message_259").into());
        }
        let d = normalize(r.domain.strip_prefix("*.").unwrap_or(&r.domain))?;
        if r.domain.starts_with("*.") && d.parse::<std::net::IpAddr>().is_ok() {
            return Err(crate::text("message_257").into());
        }
        let key = (r.domain.starts_with("*."), d);
        if !seen.insert(key) {
            return Err(crate::text("message_260").into());
        }
    }
    Ok(())
}
pub fn matches(pattern: &str, domain: &str) -> bool {
    let wildcard = pattern.starts_with("*.");
    let Ok(p) = normalize(pattern.strip_prefix("*.").unwrap_or(pattern)) else {
        return false;
    };
    if wildcard {
        domain.ends_with(&format!(".{p}"))
    } else {
        domain == p
    }
}
/// Exact hosts precede wildcard rules; the most specific wildcard wins.
/// Shared by the preview and the generated traffic/DNS rules.
pub fn ordered_rules(rules: &[Rule]) -> Vec<&Rule> {
    let mut ordered: Vec<_> = rules.iter().collect();
    ordered.sort_by_cached_key(|r| {
        let wildcard = r.domain.starts_with("*.");
        let normalized =
            normalize(r.domain.strip_prefix("*.").unwrap_or(&r.domain)).unwrap_or_default();
        (wildcard, std::cmp::Reverse(normalized.len()), normalized)
    });
    ordered
}
pub fn decide(input: &str, mode: &Mode, rules: &[Rule]) -> Result<Decision, String> {
    let domain = normalize(input)?;
    if let Some(r) = ordered_rules(rules)
        .into_iter()
        .find(|r| matches(&r.domain, &domain))
    {
        return Ok(Decision {
            domain,
            route: r.route.clone(),
            reason: crate::text("custom_rule_reason").replace("{domain}", &r.domain),
        });
    }
    if domain
        .parse::<std::net::IpAddr>()
        .is_ok_and(is_local_address)
    {
        return Ok(Decision {
            domain,
            route: "direct".into(),
            reason: "Локальная сеть: напрямую".into(),
        });
    }
    let (route, reason) = match mode {
        Mode::Vpn => ("vpn", crate::text("message_261")),
        Mode::Direct => ("direct", crate::text("message_262")),
        Mode::Smart
            if ["ru", "su", "xn--p1ai"]
                .iter()
                .any(|t| domain.ends_with(&format!(".{t}"))) =>
        {
            ("direct", crate::text("message_263"))
        }
        _ => ("vpn", crate::text("message_264")),
    };
    Ok(Decision {
        domain,
        route: route.into(),
        reason: reason.into(),
    })
}

/// Local LAN ranges only. Explicit user rules always precede this default.
/// Loopback and the broad set of reserved/special-use addresses are not included.
pub const LOCAL_NETWORKS: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
    "fe80::/10",
];
pub fn is_local_address(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => ip.is_private(),
        std::net::IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}
