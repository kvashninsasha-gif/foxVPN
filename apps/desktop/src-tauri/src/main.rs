#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use serde::Serialize;
use smart_vpn_engine::{
    latency,
    routing::{self, Rule},
    servers::{self, ImportReport},
    settings::{connection_plan, ConnectionPlan, Profile, Settings, Subscription, Vault},
    statistics,
    vpn::{config, CoreProcess},
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Emitter, Manager,
};
#[derive(Clone)]
struct State {
    profile: Arc<Mutex<Profile>>,
    vault: Arc<Vault>,
    core: Arc<Mutex<Option<CoreProcess>>>,
    binary: PathBuf,
    status: Arc<Mutex<String>>,
    gate: Arc<Mutex<()>>,
    wanted: Arc<std::sync::atomic::AtomicBool>,
}
#[derive(Serialize)]
struct Snapshot {
    profile: Profile,
    status: String,
    proxy_port: Option<u16>,
    core_version: String,
    connection_plan: ConnectionPlan,
    logs: Vec<String>,
}
fn edit<T>(s: &State, f: impl FnOnce(&mut Profile) -> Result<T, String>) -> Result<T, String> {
    let _operation = s
        .gate
        .lock()
        .map_err(|_| smart_vpn_engine::text("message_311"))?;
    let mut current = s
        .profile
        .lock()
        .map_err(|_| smart_vpn_engine::text("message_312"))?;
    let mut next = current.clone();
    let value = f(&mut next)?;
    s.vault.save(&next)?;
    *current = next;
    Ok(value)
}
#[tauri::command]
fn snapshot(s: tauri::State<State>) -> Snapshot {
    let (proxy_port, logs) = {
        let mut core = s.core.lock().unwrap();
        if core.as_mut().is_some_and(|c| !c.alive()) {
            *s.status.lock().unwrap() = "reconnecting".into();
        }
        (
            core.as_ref().map(|c| c.proxy_port),
            core.as_ref()
                .map(|c| c.logs.lock().unwrap().clone())
                .unwrap_or_default(),
        )
    };
    let profile = s.profile.lock().unwrap().clone();
    Snapshot {
        connection_plan: connection_plan(&profile),
        profile,
        status: s.status.lock().unwrap().clone(),
        proxy_port,
        core_version: "1.14.2".into(),
        logs,
    }
}
#[tauri::command]
fn import_servers(text: String, s: tauri::State<State>) -> Result<ImportReport, String> {
    if text.len() > 4_000_000 {
        return Err(smart_vpn_engine::text("message_313").into());
    }
    edit(&s, |p| {
        let r = servers::import(&text, &mut p.servers);
        if p.selected.is_none() {
            p.selected = p.servers.first().map(|s| s.id.clone())
        }
        Ok(r)
    })
}
#[tauri::command]
fn select_server(id: String, s: tauri::State<State>) -> Result<(), String> {
    if s.core.lock().unwrap().is_some() {
        return Err(smart_vpn_engine::text("message_314").into());
    }
    edit(&s, |p| {
        if s.core.lock().unwrap().is_some() {
            return Err(smart_vpn_engine::text("disconnect_first").into());
        }
        if !p.servers.iter().any(|s| s.id == id) {
            return Err(smart_vpn_engine::text("message_315").into());
        }
        p.selected = Some(id);
        Ok(())
    })
}
#[tauri::command]
fn delete_server(id: String, s: tauri::State<State>) -> Result<(), String> {
    if s.core.lock().unwrap().is_some() {
        return Err(smart_vpn_engine::text("message_316").into());
    }
    edit(&s, |p| {
        if s.core.lock().unwrap().is_some() {
            return Err(smart_vpn_engine::text("disconnect_first").into());
        }
        p.servers.retain(|s| s.id != id);
        if p.selected.as_ref() == Some(&id) {
            p.selected = p.servers.first().map(|s| s.id.clone())
        }
        Ok(())
    })
}
#[tauri::command]
fn favorite(id: String, s: tauri::State<State>) -> Result<(), String> {
    edit(&s, |p| {
        let v = p
            .servers
            .iter_mut()
            .find(|v| v.id == id)
            .ok_or(smart_vpn_engine::text("message_315"))?;
        v.favorite = !v.favorite;
        Ok(())
    })
}
#[tauri::command]
fn rename_server(
    id: String,
    name: String,
    group: String,
    s: tauri::State<State>,
) -> Result<(), String> {
    if name.trim().is_empty() || name.len() > 200 || group.len() > 100 {
        return Err(smart_vpn_engine::text("message_317").into());
    }
    edit(&s, |p| {
        let v = p
            .servers
            .iter_mut()
            .find(|v| v.id == id)
            .ok_or(smart_vpn_engine::text("message_315"))?;
        v.name = name.trim().into();
        v.group = group.trim().into();
        Ok(())
    })
}
#[tauri::command]
fn server_uri(id: String, s: tauri::State<State>) -> Result<String, String> {
    s.profile
        .lock()
        .unwrap()
        .servers
        .iter()
        .find(|v| v.id == id)
        .ok_or(smart_vpn_engine::text("message_315").into())
        .and_then(|v| v.uri())
}
#[tauri::command]
fn save_rules(rules: Vec<Rule>, s: tauri::State<State>) -> Result<(), String> {
    if s.core.lock().unwrap().is_some() {
        return Err(smart_vpn_engine::text("message_318").into());
    }
    routing::validate(&rules)?;
    edit(&s, |p| {
        if s.core.lock().unwrap().is_some() {
            return Err(smart_vpn_engine::text("disconnect_first").into());
        }
        p.rules = rules;
        Ok(())
    })
}
#[tauri::command]
fn save_settings(settings: Settings, s: tauri::State<State>) -> Result<(), String> {
    if s.core.lock().unwrap().is_some() {
        return Err(smart_vpn_engine::text("message_319").into());
    }
    settings.validate()?;
    edit(&s, |p| {
        if s.core.lock().unwrap().is_some() {
            return Err(smart_vpn_engine::text("disconnect_first").into());
        }
        p.settings = settings;
        Ok(())
    })
}
#[tauri::command]
fn check_route(domain: String, s: tauri::State<State>) -> Result<routing::Decision, String> {
    let p = s.profile.lock().unwrap();
    routing::decide(&domain, &p.settings.mode, &p.rules)
}
fn disconnect(s: &State) {
    s.wanted.store(false, std::sync::atomic::Ordering::SeqCst);
    stop_core(s)
}
fn stop_core(s: &State) {
    let _guard = s.gate.lock().unwrap();
    *s.core.lock().unwrap() = None;
    *s.status.lock().unwrap() = "disconnected".into();
}
fn connect_impl(s: &State) -> Result<u16, String> {
    let _guard = s.gate.lock().unwrap();
    if !s.wanted.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(smart_vpn_engine::text("connection_cancelled").into());
    }
    if let Some(c) = s.core.lock().unwrap().as_ref() {
        return Ok(c.proxy_port);
    }
    let p = s.profile.lock().unwrap().clone();
    if connection_plan(&p) == ConnectionPlan::NeedsProxyConsent {
        return Err(smart_vpn_engine::text("proxy_setup_needed").into());
    }
    let server = p
        .servers
        .iter()
        .find(|v| Some(&v.id) == p.selected.as_ref())
        .ok_or(smart_vpn_engine::text("message_320"))?;
    *s.status.lock().unwrap() = "connecting".into();
    let result = (|| {
        let core = CoreProcess::start(&s.binary, server, &p.settings, &p.rules)?;
        let c = latency::client(core.proxy_port)?;
        c.get("https://www.gstatic.com/generate_204")
            .send()
            .map_err(|e| smart_vpn_engine::vpn::friendly_error(&e.to_string()))?
            .error_for_status()
            .map_err(|_| smart_vpn_engine::text("message_321"))?;
        if !s.wanted.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(smart_vpn_engine::text("connection_cancelled").into());
        }
        let port = core.proxy_port;
        *s.core.lock().unwrap() = Some(core);
        Ok(port)
    })();
    *s.status.lock().unwrap() = if result.is_ok() {
        "connected"
    } else {
        "disconnected"
    }
    .into();
    result
}
#[tauri::command]
fn prepare_proxy(expected_selected: String, s: tauri::State<State>) -> Result<(), String> {
    edit(&s, |profile| {
        if s.core.lock().unwrap().is_some() {
            return Err(smart_vpn_engine::text("disconnect_first").into());
        }
        *profile = smart_vpn_engine::settings::prepare_proxy(profile, &expected_selected)?;
        Ok(())
    })
}
#[tauri::command]
async fn connect(s: tauri::State<'_, State>) -> Result<u16, String> {
    let state = s.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        state
            .wanted
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let result = connect_impl(&state);
        if result.is_err() {
            state
                .wanted
                .store(false, std::sync::atomic::Ordering::SeqCst)
        }
        result
    })
    .await
    .map_err(|_| smart_vpn_engine::text("message_322"))?
}
#[tauri::command]
async fn stop(s: tauri::State<'_, State>) -> Result<(), String> {
    let state = s.inner().clone();
    state
        .wanted
        .store(false, std::sync::atomic::Ordering::SeqCst);
    tauri::async_runtime::spawn_blocking(move || disconnect(&state))
        .await
        .map_err(|_| smart_vpn_engine::text("message_322"))?;
    Ok(())
}
fn test_impl(s: &State, id: &str, speed: bool) -> Result<latency::Measurement, String> {
    let server = s
        .profile
        .lock()
        .unwrap()
        .servers
        .iter()
        .find(|v| v.id == id)
        .cloned()
        .ok_or(smart_vpn_engine::text("message_315"))?;
    let result = latency::measure(&s.binary, &server, speed);
    edit(s, |p| {
        let Some(v) = p.servers.iter_mut().find(|v| v.id == id) else {
            return Ok(());
        };
        match &result {
            Ok(m) => {
                v.latency_ms = Some(m.latency_ms);
                if m.download_mbps.is_some() {
                    v.download_mbps = m.download_mbps
                }
                v.status = if m.latency_ms > 500 {
                    "slow"
                } else {
                    "available"
                }
                .into();
                v.successes += 1;
                v.last_error = None
            }
            Err(e) => {
                v.failures += 1;
                v.status = "unavailable".into();
                v.last_error = Some(e.clone());
                v.latency_ms = None;
                v.download_mbps = None
            }
        }
        Ok(())
    })?;
    result
}
#[tauri::command]
async fn test_server(
    id: String,
    speed: bool,
    s: tauri::State<'_, State>,
) -> Result<latency::Measurement, String> {
    let state = s.inner().clone();
    tauri::async_runtime::spawn_blocking(move || test_impl(&state, &id, speed))
        .await
        .map_err(|_| smart_vpn_engine::text("message_323"))?
}
#[tauri::command]
async fn test_all(app: tauri::AppHandle, s: tauri::State<'_, State>) -> Result<(), String> {
    let state = s.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let ids: Vec<_> = state
            .profile
            .lock()
            .unwrap()
            .servers
            .iter()
            .map(|v| v.id.clone())
            .collect();
        for id in ids {
            let _ = test_impl(&state, &id, false);
            let _ = app.emit("servers-updated", ());
        }
        Ok(())
    })
    .await
    .map_err(|_| smart_vpn_engine::text("message_323"))?
}
#[tauri::command]
fn auto_select(s: tauri::State<State>) -> Result<String, String> {
    if s.core.lock().unwrap().is_some() {
        return Err(smart_vpn_engine::text("message_324").into());
    }
    edit(&s, |p| {
        if s.core.lock().unwrap().is_some() {
            return Err(smart_vpn_engine::text("disconnect_first").into());
        }
        let id = latency::select(&p.servers, &p.settings)
            .ok_or(smart_vpn_engine::text("message_325"))?;
        p.selected = Some(id.clone());
        Ok(id)
    })
}
#[tauri::command]
async fn traffic(s: tauri::State<'_, State>) -> Result<statistics::Traffic, String> {
    let Some((port, secret)) = s
        .core
        .lock()
        .unwrap()
        .as_ref()
        .map(|c| (c.api_port, c.secret.clone()))
    else {
        return Ok(statistics::Traffic::default());
    };
    tauri::async_runtime::spawn_blocking(move || statistics::read(port, &secret))
        .await
        .map_err(|_| smart_vpn_engine::text("message_326"))?
}
#[tauri::command]
fn add_subscription(name: String, url: String, s: tauri::State<State>) -> Result<(), String> {
    smart_vpn_engine::subscriptions::validate_url(&url)?;
    edit(&s, |p| {
        if p.subscriptions.iter().any(|v| v.url == url) {
            return Err(smart_vpn_engine::text("message_327").into());
        }
        p.subscriptions.push(Subscription {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            url,
            updated_at: None,
            server_count: 0,
        });
        Ok(())
    })
}
fn update_sub(s: &State, id: &str) -> Result<ImportReport, String> {
    let url = s
        .profile
        .lock()
        .unwrap()
        .subscriptions
        .iter()
        .find(|v| v.id == id)
        .map(|v| v.url.clone())
        .ok_or(smart_vpn_engine::text("message_328"))?;
    let text = smart_vpn_engine::subscriptions::fetch(&url)?;
    let mut imported = vec![];
    let report = servers::import(&text, &mut imported);
    if report.added == 0 || !report.errors.is_empty() {
        return Err(smart_vpn_engine::text("message_329").into());
    }
    edit(s, |p| {
        if s.core.lock().unwrap().is_some() {
            return Err(smart_vpn_engine::text("message_330").into());
        }
        for item in &mut imported {
            item.subscription = Some(id.into());
            if let Some(old) = p.servers.iter().find(|old| {
                old.subscription.as_deref() == Some(id) && old.fingerprint() == item.fingerprint()
            }) {
                let name = item.name.clone();
                *item = old.clone();
                item.name = name;
            }
        }
        p.servers.retain(|v| v.subscription.as_deref() != Some(id));
        for item in imported {
            if !p
                .servers
                .iter()
                .any(|old| old.fingerprint() == item.fingerprint())
            {
                p.servers.push(item)
            }
        }
        let count = p
            .servers
            .iter()
            .filter(|v| v.subscription.as_deref() == Some(id))
            .count();
        if !p.servers.iter().any(|v| Some(&v.id) == p.selected.as_ref()) {
            p.selected = p.servers.first().map(|v| v.id.clone())
        }
        let sub = p
            .subscriptions
            .iter_mut()
            .find(|v| v.id == id)
            .ok_or(smart_vpn_engine::text("message_328"))?;
        sub.server_count = count;
        sub.updated_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        Ok(report)
    })
}
#[tauri::command]
async fn update_subscription(
    id: String,
    s: tauri::State<'_, State>,
) -> Result<ImportReport, String> {
    let state = s.inner().clone();
    tauri::async_runtime::spawn_blocking(move || update_sub(&state, &id))
        .await
        .map_err(|_| smart_vpn_engine::text("message_331"))?
}
#[tauri::command]
fn delete_subscription(id: String, s: tauri::State<State>) -> Result<(), String> {
    edit(&s, |p| {
        p.subscriptions.retain(|v| v.id != id);
        for v in &mut p.servers {
            if v.subscription.as_deref() == Some(&id) {
                v.subscription = None;
            }
        }
        Ok(())
    })
}
#[tauri::command]
fn import_file(path: String, s: tauri::State<State>) -> Result<ImportReport, String> {
    let m = std::fs::metadata(&path).map_err(|_| smart_vpn_engine::text("message_332"))?;
    if m.len() > 4_000_000 {
        return Err(smart_vpn_engine::text("message_333").into());
    }
    let text = std::fs::read_to_string(path).map_err(|_| smart_vpn_engine::text("message_334"))?;
    import_servers(text, s)
}
#[tauri::command]
fn export_backup(path: String, s: tauri::State<State>) -> Result<(), String> {
    let text = serde_json::to_string_pretty(&*s.profile.lock().unwrap())
        .map_err(|_| smart_vpn_engine::text("message_335"))?;
    write_private(&path, &text)
}
fn write_private(path: &str, text: &str) -> Result<(), String> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options
        .open(path)
        .map_err(|_| smart_vpn_engine::text("message_336"))?;
    f.write_all(text.as_bytes())
        .map_err(|_| smart_vpn_engine::text("message_337").into())
}
#[tauri::command]
fn import_backup(path: String, s: tauri::State<State>) -> Result<(), String> {
    if s.core.lock().unwrap().is_some() {
        return Err(smart_vpn_engine::text("message_338").into());
    }
    let meta = std::fs::metadata(&path).map_err(|_| smart_vpn_engine::text("message_339"))?;
    if meta.len() > 4_000_000 {
        return Err(smart_vpn_engine::text("message_340").into());
    }
    let text = std::fs::read_to_string(path).map_err(|_| smart_vpn_engine::text("message_341"))?;
    let p: Profile =
        serde_json::from_str(&text).map_err(|_| smart_vpn_engine::text("message_342"))?;
    p.validate()?;
    edit(&s, |current| {
        if s.core.lock().unwrap().is_some() {
            return Err(smart_vpn_engine::text("disconnect_first").into());
        }
        *current = p;
        Ok(())
    })
}
#[tauri::command]
fn export_config(path: String, s: tauri::State<State>) -> Result<(), String> {
    let p = s.profile.lock().unwrap();
    let server = p
        .servers
        .iter()
        .find(|v| Some(&v.id) == p.selected.as_ref())
        .ok_or(smart_vpn_engine::text("message_343"))?;
    let tun_settings = Settings {
        tun: true,
        ..p.settings.clone()
    };
    let cfg = config(
        server,
        &tun_settings,
        &p.rules,
        2080,
        2081,
        &uuid::Uuid::new_v4().to_string(),
    )?;
    write_private(&path, &serde_json::to_string_pretty(&cfg).unwrap())
}
fn main() {
    let strings: serde_json::Value =
        serde_json::from_str(include_str!("../../../../locales/ru.json")).expect("Russian locale");
    let t = move |key: &str| strings[key].as_str().unwrap().to_string();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .setup(move |app| {
            let vault = Arc::new(Vault::new("ru.smartvpn.router"));
            let profile = vault.load().map_err(std::io::Error::other)?;
            profile.validate().map_err(std::io::Error::other)?;
            let resource = app
                .path()
                .resource_dir()?
                .join("core")
                .join(if cfg!(windows) {
                    "sing-box.exe"
                } else {
                    "sing-box"
                });
            let binary = if resource.exists() {
                resource
            } else {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../core/sing-box")
            };
            let state = State {
                profile: Arc::new(Mutex::new(profile.clone())),
                vault,
                core: Arc::new(Mutex::new(None)),
                binary,
                status: Arc::new(Mutex::new("disconnected".into())),
                gate: Arc::new(Mutex::new(())),
                wanted: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            };
            app.manage(state.clone());
            let show = MenuItem::with_id(app, "show", t("open_app"), true, None::<&str>)?;
            let connect = MenuItem::with_id(app, "connect", t("connect"), true, None::<&str>)?;
            let stop = MenuItem::with_id(app, "stop", t("disconnect"), true, None::<&str>)?;
            let tests = MenuItem::with_id(app, "tests", t("test_all"), true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", t("exit"), true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &connect, &stop, &tests, &quit])?;
            let mut tray = TrayIconBuilder::new()
                .menu(&menu)
                .tooltip("Smart VPN Router")
                .on_menu_event(|app, e| {
                    let state = app.state::<State>().inner().clone();
                    match e.id.as_ref() {
                        "show" => {
                            if let Some(w) = app.get_webview_window("main") {
                                let _ = w.show();
                                let _ = w.set_focus();
                            }
                        }
                        "connect" => {
                            let plan = connection_plan(&state.profile.lock().unwrap());
                            if plan != ConnectionPlan::Ready {
                                if let Some(window) = app.get_webview_window("main") {
                                    let _ = window.show();
                                    let _ = window.set_focus();
                                }
                                let _ = app.emit("connection-setup-required", plan);
                                return;
                            }
                            let handle = app.clone();
                            tauri::async_runtime::spawn_blocking(move || {
                                state
                                    .wanted
                                    .store(true, std::sync::atomic::Ordering::SeqCst);
                                match connect_impl(&state) {
                                    Ok(_) => (),
                                    Err(e) => {
                                        state
                                            .wanted
                                            .store(false, std::sync::atomic::Ordering::SeqCst);
                                        let _ = handle.emit("operation-error", e);
                                    }
                                }
                                let _ = handle.emit("servers-updated", ());
                            });
                        }
                        "stop" => {
                            state
                                .wanted
                                .store(false, std::sync::atomic::Ordering::SeqCst);
                            let handle = app.clone();
                            tauri::async_runtime::spawn_blocking(move || {
                                disconnect(&state);
                                let _ = handle.emit("servers-updated", ());
                            });
                        }
                        "tests" => {
                            let handle = app.clone();
                            tauri::async_runtime::spawn_blocking(move || {
                                let ids: Vec<_> = state
                                    .profile
                                    .lock()
                                    .unwrap()
                                    .servers
                                    .iter()
                                    .map(|v| v.id.clone())
                                    .collect();
                                for id in ids {
                                    let _ = test_impl(&state, &id, false);
                                    let _ = handle.emit("servers-updated", ());
                                }
                            });
                        }
                        "quit" => {
                            disconnect(&state);
                            app.exit(0)
                        }
                        _ => (),
                    }
                });
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.build(app)?;
            // Native menu strings remain Russian, including macOS application menu.
            let close =
                MenuItem::with_id(app, "hide", t("hide_window"), true, Some("CmdOrCtrl+W"))?;
            let exit = MenuItem::with_id(app, "exit-app", t("exit"), true, Some("CmdOrCtrl+Q"))?;
            app.set_menu(Menu::with_items(app, &[&close, &exit])?)?;
            if profile.settings.start_minimized
                && !(profile.settings.auto_connect
                    && connection_plan(&profile) != ConnectionPlan::Ready)
            {
                if let Some(w) = app.get_webview_window("main") {
                    w.hide()?;
                }
            }
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                if profile.settings.auto_connect
                    && connection_plan(&profile) == ConnectionPlan::Ready
                {
                    state
                        .wanted
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    match connect_impl(&state) {
                        Ok(_) => (),
                        Err(e) => {
                            state
                                .wanted
                                .store(false, std::sync::atomic::Ordering::SeqCst);
                            let _ = handle.emit("operation-error", e);
                        }
                    }
                }
                let mut last = std::time::Instant::now();
                let mut last_sub = std::time::Instant::now();
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    let p = state.profile.lock().unwrap().clone();
                    if last.elapsed().as_secs() >= p.settings.health_interval {
                        last = std::time::Instant::now();
                        let endpoint = state.core.lock().unwrap().as_ref().map(|c| c.proxy_port);
                        if let Some(port) = endpoint {
                            let ok = latency::client(port)
                                .and_then(|c| {
                                    c.get("https://www.gstatic.com/generate_204")
                                        .send()
                                        .map(|r| r.status().is_success())
                                        .map_err(|_| smart_vpn_engine::text("message_344").into())
                                })
                                .unwrap_or(false);
                            if !ok && state.wanted.load(std::sync::atomic::Ordering::SeqCst) {
                                *state.status.lock().unwrap() = "reconnecting".into();
                                stop_core(&state);
                                if p.settings.failover {
                                    for server in &p.servers {
                                        if p.settings.favorites_only && !server.favorite {
                                            continue;
                                        }
                                        if test_impl(&state, &server.id, false).is_ok() {
                                            let _ = edit(&state, |p| {
                                                p.selected = Some(server.id.clone());
                                                Ok(())
                                            });
                                            break;
                                        }
                                    }
                                }
                                if p.settings.restore
                                    && state.wanted.load(std::sync::atomic::Ordering::SeqCst)
                                {
                                    if let Err(e) = connect_impl(&state) {
                                        let _ = handle.emit("operation-error", e);
                                    }
                                }
                                let _ = handle.emit("servers-updated", ());
                            }
                        } else if p.settings.restore
                            && state.wanted.load(std::sync::atomic::Ordering::SeqCst)
                        {
                            let _ = connect_impl(&state);
                            let _ = handle.emit("servers-updated", ());
                        }
                    }
                    if p.settings.subscription_interval > 0
                        && last_sub.elapsed().as_secs() >= p.settings.subscription_interval
                    {
                        last_sub = std::time::Instant::now();
                        if state.core.lock().unwrap().is_none() {
                            for sub in &p.subscriptions {
                                let _ = update_sub(&state, &sub.id);
                            }
                            let _ = handle.emit("servers-updated", ());
                        }
                    }
                }
            });
            Ok(())
        })
        .on_menu_event(|app, e| match e.id.as_ref() {
            "hide" => {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.hide();
                }
            }
            "exit-app" => {
                disconnect(&app.state::<State>());
                app.exit(0)
            }
            _ => (),
        })
        .on_window_event(|window, e| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = e {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            snapshot,
            import_servers,
            select_server,
            delete_server,
            favorite,
            rename_server,
            server_uri,
            save_rules,
            save_settings,
            check_route,
            connect,
            prepare_proxy,
            stop,
            test_server,
            test_all,
            auto_select,
            traffic,
            add_subscription,
            update_subscription,
            delete_subscription,
            import_file,
            export_backup,
            import_backup,
            export_config
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|_| panic!("{}", smart_vpn_engine::text("message_345")));
}
