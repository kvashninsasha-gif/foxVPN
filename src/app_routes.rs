//! Portable storage of macOS application exclusions. Matching uses a bounded,
//! escaped bundle path, never a process basename or user-provided expression.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Application {
    pub name: String,
    pub path: String,
}

pub fn validate(apps: &[Application]) -> Result<(), String> {
    if apps.len() > 100 {
        return Err("Можно исключить не более 100 приложений".into());
    }
    let mut paths = std::collections::HashSet::new();
    for app in apps {
        if app.name.trim().is_empty()
            || app.name.len() > 256
            || app.name.chars().any(char::is_control)
            || app.path.len() > 4096
            || !app.path.starts_with('/')
            || !app.path.to_ascii_lowercase().ends_with(".app")
            || app.path.chars().any(char::is_control)
            || app.path.contains('\\')
            || app.path[1..]
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err("Неверное приложение: выберите установленный пакет .app".into());
        }
        if !paths.insert(&app.path) {
            return Err("Приложение уже добавлено в исключения".into());
        }
    }
    Ok(())
}

/// The trailing slash is essential: Foo.app must not match Foo.app.evil.
/// Include nested helpers/XPC executables belonging to this selected bundle.
pub fn bundle_pattern(app: &Application) -> String {
    let mut pattern = String::from("^");
    for c in app.path.chars() {
        if ".+*?()[]{}^$|\\".contains(c) {
            pattern.push('\\');
        }
        pattern.push(c);
    }
    pattern.push('/');
    pattern
}
