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
    let value = input.trim().trim_end_matches('.').to_lowercase();
    if value.is_empty() || value.contains('/') || value.contains(':') || value.contains('@') {
        return Err(crate::text("message_256").into());
    }
    let host = url::Host::parse(&value).map_err(|_| crate::text("message_257"))?;
    if !matches!(host, url::Host::Domain(_)) {
        return Err(crate::text("message_258").into());
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
pub fn decide(input: &str, mode: &Mode, rules: &[Rule]) -> Result<Decision, String> {
    let domain = normalize(input)?;
    let (route, reason) = match mode {
        Mode::Vpn => ("vpn", crate::text("message_261")),
        Mode::Direct => ("direct", crate::text("message_262")),
        _ => {
            if let Some(r) = rules.iter().find(|r| matches(&r.domain, &domain)) {
                return Ok(Decision {
                    domain,
                    route: r.route.clone(),
                    reason: crate::text("custom_rule_reason").replace("{domain}", &r.domain),
                });
            }
            if *mode == Mode::Smart
                && ["ru", "su", "xn--p1ai"]
                    .iter()
                    .any(|t| domain.ends_with(&format!(".{t}")))
            {
                ("direct", crate::text("message_263"))
            } else {
                ("vpn", crate::text("message_264"))
            }
        }
    };
    Ok(Decision {
        domain,
        route: route.into(),
        reason: reason.into(),
    })
}
