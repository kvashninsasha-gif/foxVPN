pub mod latency;
pub mod lifecycle;
pub mod routing;
pub mod servers;
pub mod settings;
pub mod statistics;
pub mod subscriptions;
pub mod vpn;

pub fn text(key: &str) -> &'static str {
    static STRINGS: std::sync::OnceLock<std::collections::BTreeMap<String, String>> =
        std::sync::OnceLock::new();
    STRINGS
        .get_or_init(|| serde_json::from_str(include_str!("../locales/ru.json")).expect("locale"))
        .get(key)
        .map(String::as_str)
        .unwrap_or("Неизвестное сообщение")
}
