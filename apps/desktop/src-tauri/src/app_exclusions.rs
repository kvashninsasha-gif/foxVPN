//! Native app discovery/picker. The WebView cannot provide filesystem paths to
//! read; only validated bundle metadata is returned, and nothing is launched.
use super::{edit, State};
use smart_vpn_engine::app_routes::{self, Application};

#[cfg(target_os = "macos")]
fn application(path: &std::path::Path) -> Result<Application, String> {
    let path = path.canonicalize().map_err(|_| "Приложение не найдено")?;
    if !path.is_dir() {
        return Err("Выберите установленное приложение .app".into());
    }
    let plist_path = path.join("Contents/Info.plist");
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&plist_path)
        .map_err(|_| "Нет описания приложения")?;
    if !file
        .metadata()
        .is_ok_and(|m| m.is_file() && m.len() <= 1024 * 1024)
    {
        return Err("Неверное описание приложения".into());
    }
    use std::io::Read;
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Не удалось прочитать описание приложения")?;
    if bytes.len() > 1024 * 1024 {
        return Err("Неверное описание приложения".into());
    }
    let value = plist::Value::from_reader(std::io::Cursor::new(bytes))
        .map_err(|_| "Неверное описание приложения")?;
    let dict = value
        .as_dictionary()
        .ok_or("Неверное описание приложения")?;
    let string = |key: &str| dict.get(key).and_then(plist::Value::as_string);
    if string("CFBundleIdentifier") == Some("ru.smartvpn.router") {
        return Err("foxVPN нельзя добавить в собственные исключения".into());
    }
    let executable = string("CFBundleExecutable").ok_or("Нет исполняемого файла приложения")?;
    if executable.is_empty()
        || executable.contains(['/', '\\'])
        || executable == "."
        || executable == ".."
        || !path.join("Contents/MacOS").join(executable).is_file()
    {
        return Err("Нет исполняемого файла приложения".into());
    }
    let app = Application {
        name: string("CFBundleDisplayName")
            .or_else(|| string("CFBundleName"))
            .unwrap_or_else(|| {
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("Приложение")
            })
            .to_owned(),
        path: path
            .to_str()
            .ok_or("Неподдерживаемое имя приложения")?
            .to_owned(),
    };
    app_routes::validate(std::slice::from_ref(&app))?;
    Ok(app)
}

#[cfg(target_os = "macos")]
fn scan(root: &std::path::Path, depth: u8, apps: &mut Vec<Application>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.take(1000).flatten() {
        if apps.len() >= 500 {
            break;
        }
        let path = entry.path();
        if path
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("app"))
        {
            if let Ok(app) = application(&path) {
                if !apps.iter().any(|a| a.path == app.path) {
                    apps.push(app);
                }
            }
        } else if depth > 0 && entry.file_type().is_ok_and(|t| t.is_dir()) {
            scan(&path, depth - 1, apps);
        }
    }
}

#[tauri::command]
pub async fn list_macos_apps() -> Result<Vec<Application>, String> {
    #[cfg(target_os = "macos")]
    {
        tauri::async_runtime::spawn_blocking(|| {
            let mut apps = vec![];
            for root in ["/Applications", "/System/Applications"] {
                scan(std::path::Path::new(root), 1, &mut apps);
            }
            if let Some(home) = std::env::var_os("HOME") {
                scan(
                    &std::path::PathBuf::from(home).join("Applications"),
                    1,
                    &mut apps,
                );
            }
            apps.sort_by_key(|a| a.name.to_lowercase());
            Ok(apps)
        })
        .await
        .map_err(|_| "Не удалось получить список приложений")?
    }
    #[cfg(not(target_os = "macos"))]
    Err("Исключения приложений доступны только в macOS".into())
}

#[tauri::command]
pub async fn pick_macos_app(app: tauri::AppHandle) -> Result<Option<Application>, String> {
    #[cfg(target_os = "macos")]
    {
        use tauri_plugin_dialog::DialogExt;
        tauri::async_runtime::spawn_blocking(move || {
            let _dialog = super::file_actions::DialogGuard::acquire()?;
            let Some(file) = app
                .dialog()
                .file()
                .set_title("Выберите приложение без VPN")
                .set_directory("/Applications")
                .add_filter("Приложение macOS", &["app"])
                .blocking_pick_file()
            else {
                return Ok(None);
            };
            application(
                &file
                    .into_path()
                    .map_err(|_| "Не удалось выбрать приложение")?,
            )
            .map(Some)
        })
        .await
        .map_err(|_| "Не удалось выбрать приложение")?
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = app;
        Err("Исключения приложений доступны только в macOS".into())
    }
}

#[tauri::command]
pub async fn save_app_exclusions(
    apps: Vec<Application>,
    expected: Vec<Application>,
    s: tauri::State<'_, State>,
) -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("Исключения приложений доступны только в macOS".into());
    }
    app_routes::validate(&apps)?;
    app_routes::validate(&expected)?;
    let state = s.inner().clone();
    tauri::async_runtime::spawn_blocking(move || save(apps, expected, &state))
        .await
        .map_err(|_| "Не удалось сохранить исключения")?
}
fn save(apps: Vec<Application>, expected: Vec<Application>, state: &State) -> Result<(), String> {
    app_routes::validate(&apps)?;
    app_routes::validate(&expected)?;
    edit(state, |profile| {
        if state.wanted.pending(state.wanted.ticket())
            || state
                .core
                .lock()
                .map_err(|_| "Не удалось проверить подключение")?
                .is_some()
            || state
                .status
                .lock()
                .map_err(|_| "Не удалось проверить подключение")?
                .as_str()
                != "disconnected"
        {
            return Err("Сначала отключите VPN, затем сохраните исключения".into());
        }
        if profile.settings.excluded_apps != expected {
            return Err(
                "Исключения изменились в другом окне. Отмените местные изменения и повторите выбор"
                    .into(),
            );
        }
        profile.settings.excluded_apps = apps;
        Ok(())
    })
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    fn fixture(path: std::path::PathBuf) -> State {
        use std::sync::{atomic::AtomicBool, Arc, Mutex};
        State {
            installing: Arc::new(AtomicBool::new(false)),
            profile: Arc::new(Mutex::new(Default::default())),
            vault: Arc::new(smart_vpn_engine::settings::Vault::test_fixture(
                path, [42; 32],
            )),
            core: Arc::new(Mutex::new(None)),
            binary: "unused".into(),
            status: Arc::new(Mutex::new("disconnected".into())),
            gate: Arc::new(Mutex::new(())),
            measurements: Arc::new(Mutex::new(())),
            proxy_error: Arc::new(Mutex::new(None)),
            wanted: Arc::new(Default::default()),
        }
    }
    fn selected() -> Application {
        Application {
            name: "Windows App".into(),
            path: "/Applications/Windows App.app".into(),
        }
    }
    #[test]
    fn saving_exclusions_preserves_settings_and_rejects_stale_selection() {
        let dir = tempfile::tempdir().unwrap();
        let state = fixture(dir.path().join("profile.enc"));
        super::edit(&state, |profile| {
            profile.settings.dns_provider = "quad9".into();
            Ok(())
        })
        .unwrap();
        save(vec![selected()], vec![], &state).unwrap();
        let stored = state.vault.load().unwrap();
        assert_eq!(stored.settings.excluded_apps, vec![selected()]);
        assert_eq!(stored.settings.dns_provider, "quad9");
        assert!(save(vec![], vec![], &state).is_err());
        assert_eq!(
            state.vault.load().unwrap().settings.excluded_apps,
            vec![selected()]
        );
        save(vec![], vec![selected()], &state).unwrap();
        assert!(state
            .vault
            .load()
            .unwrap()
            .settings
            .excluded_apps
            .is_empty());
    }
    #[test]
    fn saving_exclusions_is_blocked_for_active_pending_and_concurrent_disk_changes() {
        let dir = tempfile::tempdir().unwrap();
        let state = fixture(dir.path().join("profile.enc"));
        *state.status.lock().unwrap() = "connected".into();
        assert!(save(vec![selected()], vec![], &state).is_err());
        *state.status.lock().unwrap() = "disconnected".into();
        state.wanted.request().unwrap();
        assert!(save(vec![selected()], vec![], &state).is_err());
        state.wanted.cancel();
        let mut latest = state.vault.load().unwrap();
        latest.settings.dns_provider = "google".into();
        state.vault.save(&latest).unwrap();
        assert!(save(vec![selected()], vec![], &state).is_err());
        let stored = state.vault.load().unwrap();
        assert_eq!(stored.settings.dns_provider, "google");
        assert!(stored.settings.excluded_apps.is_empty());
    }
    #[test]
    fn native_catalog_validates_public_binary_plist_without_launching_it() {
        // A public synthetic bundle also covers spaces and binary Info.plist.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Windows App.app");
        std::fs::create_dir_all(path.join("Contents/MacOS")).unwrap();
        std::fs::write(path.join("Contents/MacOS/Windows App"), b"public fixture").unwrap();
        let value = plist::Value::Dictionary(
            [
                (
                    "CFBundleName".to_owned(),
                    plist::Value::String("Windows App".into()),
                ),
                (
                    "CFBundleExecutable".to_owned(),
                    plist::Value::String("Windows App".into()),
                ),
            ]
            .into_iter()
            .collect(),
        );
        value
            .to_file_binary(path.join("Contents/Info.plist"))
            .unwrap();
        let app = application(&path).unwrap();
        assert_eq!(app.name, "Windows App");
        assert!(app.path.ends_with("/Windows App.app"));
        let mut found = vec![];
        scan(dir.path(), 1, &mut found);
        assert_eq!(found, vec![app]);
        std::fs::remove_file(path.join("Contents/MacOS/Windows App")).unwrap();
        assert!(application(&path).is_err());
        assert!(application(dir.path()).is_err());
    }
}
