//! Restart recovery never restores a profile or starts a connection silently.
use super::State;
use smart_vpn_engine::setup_recovery::{Phase, Record};
use std::sync::atomic::Ordering;
use tauri::Emitter;
#[derive(serde::Serialize)]
pub struct Info {
    pub pending: bool,
    pub recovery_id: Option<String>,
    pub can_restore: bool,
    pub phase: Option<Phase>,
    pub originally_active: bool,
    pub error: Option<String>,
}
pub fn ensure_resolved(state: &State) -> Result<(), String> {
    ensure_authorized(state, None)
}
pub fn ensure_authorized(state: &State, recovery_id: Option<&str>) -> Result<(), String> {
    if state
        .vault
        .load_setup_recovery()?
        .is_some_and(|r| r.pending() && Some(r.operation_id.as_str()) != recovery_id)
    {
        return Err("Обнаружена незавершённая настройка. Сначала выберите восстановление или сохранение текущих параметров".into());
    }
    Ok(())
}
pub fn pending(state: &State) -> bool {
    ensure_resolved(state).is_err()
}
fn inspect(state: &State) -> Info {
    match state.vault.load_setup_recovery() {
        Ok(Some(r)) if r.pending()=>{
            let current=state.vault.load().and_then(|p| {p.validate()?;r.accepts(&p)});
            let can_restore=current.as_ref().is_ok_and(|v|*v);
            Info {pending:true,recovery_id:Some(r.operation_id),can_restore,phase:Some(r.phase),originally_active:r.originally_active,error:if current.is_err(){Some("Текущий защищённый профиль не удалось проверить. Возврат отключён до исправления доступа или данных".into())}else if can_restore{None}else{Some("После прерванной настройки параметры изменились. Возврат отключён, чтобы сохранить новые изменения".into())}}
        },
        Ok(_)=>Info {pending:false,recovery_id:None,can_restore:false,phase:None,originally_active:false,error:None},
        Err(_)=>Info {pending:true,recovery_id:None,can_restore:false,phase:None,originally_active:false,error:Some("Журнал настройки не прошёл проверку. Автоматическое подключение при запуске отложено; прежние параметры не заменялись".into())},
    }
}
#[tauri::command]
pub async fn setup_recovery_state(state: tauri::State<'_, State>) -> Result<Info, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || inspect(&state))
        .await
        .map_err(|_| "Не удалось проверить восстановление".into())
}
fn check_token(r: &Record, id: &Option<String>) -> Result<(), String> {
    if id.as_deref() != Some(r.operation_id.as_str()) {
        return Err("Операция восстановления изменилась. Обновите проверку".into());
    }
    Ok(())
}
fn restore_checked(
    state: &State,
    id: &str,
    stop: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let lease = state.vault.lock_configuration()?;
    let mut record = state
        .vault
        .load_setup_recovery()?
        .ok_or("Журнал восстановления отсутствует")?;
    check_token(&record, &Some(id.to_string()))?;
    if !record.pending() {
        return Err("Настройка уже завершена".into());
    }
    let current = state.vault.load()?;
    current.validate()?;
    if !record.accepts(&current)? {
        return Err("Параметры изменились. Прежняя копия не применялась".into());
    }
    record.phase = Phase::Restoring;
    state.vault.save_setup_recovery(&record)?;
    stop()?;
    for port in [record.before.settings.proxy_port, record.target_port] {
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_err() {
            return Err("Локальный порт остаётся занят. Закройте прежний процесс или перезапустите компьютер, затем повторите восстановление. Другие процессы не завершались".into());
        }
    }
    let restored = super::setup_plan::with_observations(&record.before, &current)?;
    state.vault.save_locked(&restored, &lease)?;
    *state
        .profile
        .lock()
        .map_err(|_| "Не удалось вернуть параметры")? = restored;
    record.phase = Phase::Restored;
    state.vault.save_setup_recovery(&record)?;
    let _ = state.vault.clear_setup_recovery();
    Ok(())
}
#[tauri::command]
pub async fn restore_setup_recovery(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
    recovery_id: String,
    approved: bool,
) -> Result<(), String> {
    if !approved {
        return Err("Восстановление требует вашего согласия".into());
    }
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _measure = state
            .measurements
            .lock()
            .map_err(|_| "Дождитесь проверки")?;
        let _gate = state.gate.lock().map_err(|_| "Настройка занята")?;
        if state.installing.load(Ordering::SeqCst) {
            return Err("Дождитесь обновления приложения".into());
        }
        restore_checked(&state, &recovery_id, || {
            let ticket = state.wanted.cancel();
            super::disconnect_locked(&state, ticket)
        })?;
        let _ = app.emit("servers-updated", ());
        let _ = app.emit("setup-recovery-changed", ());
        Ok(())
    })
    .await
    .map_err(|_| "Не удалось завершить восстановление")?
}
fn discard_checked(state: &State, recovery_id: &Option<String>) -> Result<(), String> {
    let _lease = state.vault.lock_configuration()?;
    match state.vault.load_setup_recovery() {
        Ok(Some(r)) => check_token(&r, recovery_id)?,
        Ok(None) => return Err("Журнал уже завершён".into()),
        Err(_) if recovery_id.is_none() => (),
        Err(e) => return Err(e),
    }
    let current = state.vault.load()?;
    current.validate()?;
    // Keeping the latest disk profile also refreshes this session. Otherwise a
    // later connect/export could use stale cached settings once recovery unblocks.
    let mut cached = state
        .profile
        .lock()
        .map_err(|_| "Не удалось сохранить текущие параметры")?;
    state.vault.clear_setup_recovery()?;
    *cached = current;
    Ok(())
}
#[tauri::command]
pub async fn discard_setup_recovery(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
    recovery_id: Option<String>,
    approved: bool,
) -> Result<(), String> {
    if !approved {
        return Err("Сохранение текущих параметров требует вашего согласия".into());
    }
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _gate = state.gate.lock().map_err(|_| "Настройка занята")?;
        if state.installing.load(Ordering::SeqCst) {
            return Err("Дождитесь обновления приложения".into());
        }
        discard_checked(&state, &recovery_id)?;
        let _ = app.emit("servers-updated", ());
        let _ = app.emit("setup-recovery-changed", ());
        Ok(())
    })
    .await
    .map_err(|_| "Не удалось завершить восстановление")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use smart_vpn_engine::{
        lifecycle::ConnectionIntent,
        settings::{Profile, Vault},
    };
    use std::sync::{atomic::AtomicBool, Arc, Mutex};
    fn state(path: std::path::PathBuf, p: Profile) -> State {
        State {
            installing: Arc::new(AtomicBool::new(false)),
            profile: Arc::new(Mutex::new(p)),
            vault: Arc::new(Vault::test_fixture(path, [42; 32])),
            core: Arc::new(Mutex::new(None)),
            binary: std::path::PathBuf::from("unused"),
            status: Arc::new(Mutex::new("disconnected".into())),
            gate: Arc::new(Mutex::new(())),
            measurements: Arc::new(Mutex::new(())),
            proxy_error: Arc::new(Mutex::new(None)),
            wanted: Arc::new(ConnectionIntent::default()),
        }
    }
    #[test]
    fn restoration_reads_disk_preserves_later_data_and_never_overwrites_a_stale_profile() {
        let dir = tempfile::tempdir().unwrap();
        let mut before = Profile::default();
        before.settings.proxy_port = smart_vpn_engine::vpn::free_port().unwrap();
        let mut after = before.clone();
        after.settings.dns_provider = "google".into();
        let state = state(dir.path().join("profile.enc"), after.clone());
        state.vault.save(&after).unwrap();
        let record = Record::new(&uuid::Uuid::new_v4().to_string(), &before, &after, true).unwrap();
        state.vault.save_setup_recovery(&record).unwrap();
        assert!(pending(&state));
        let mut later = after.clone();
        later.settings.auto_connect = true;
        state.vault.save(&later).unwrap();
        let mut stopped = false;
        assert!(restore_checked(&state, &record.operation_id, || {
            stopped = true;
            Ok(())
        })
        .is_err());
        assert!(!stopped);
        assert!(state.vault.load().unwrap().settings.auto_connect);
        state.vault.save(&after).unwrap();
        restore_checked(&state, &record.operation_id, || Ok(())).unwrap();
        assert_eq!(
            state.vault.load().unwrap().settings.dns_provider,
            "cloudflare"
        );
        assert!(!pending(&state));
        assert!(state.core.lock().unwrap().is_none());
    }
    #[test]
    fn unconfirmed_stop_keeps_authenticated_pending_journal_and_current_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let before = Profile::default();
        let mut after = before.clone();
        after.settings.dns_provider = "google".into();
        let state = state(dir.path().join("profile.enc"), after.clone());
        state.vault.save(&after).unwrap();
        let record = Record::new(&uuid::Uuid::new_v4().to_string(), &before, &after, true).unwrap();
        state.vault.save_setup_recovery(&record).unwrap();
        assert!(restore_checked(&state, &record.operation_id, || Err(
            "public stop failure".into()
        ))
        .is_err());
        assert!(state
            .vault
            .load_setup_recovery()
            .unwrap()
            .unwrap()
            .pending());
        assert_eq!(state.vault.load().unwrap().settings.dns_provider, "google");
    }
    #[test]
    fn forged_recovery_tokens_and_unknown_connection_authorization_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = Profile::default();
        let state = state(dir.path().join("profile.enc"), p.clone());
        state.vault.save(&p).unwrap();
        let record = Record::new(&uuid::Uuid::new_v4().to_string(), &p, &p, false).unwrap();
        state.vault.save_setup_recovery(&record).unwrap();
        assert!(check_token(&record, &Some("forged".into())).is_err());
        assert!(ensure_resolved(&state).is_err());
        assert!(ensure_authorized(&state, Some("forged")).is_err());
        assert!(ensure_authorized(&state, Some(&record.operation_id)).is_ok());
    }
    #[test]
    fn keeping_current_profile_refreshes_stale_session_without_writing_or_connecting() {
        let dir = tempfile::tempdir().unwrap();
        let before = Profile::default();
        let mut after = before.clone();
        after.settings.dns_provider = "google".into();
        let state = state(dir.path().join("profile.enc"), after.clone());
        state.vault.save(&after).unwrap();
        let record =
            Record::new(&uuid::Uuid::new_v4().to_string(), &before, &after, false).unwrap();
        state.vault.save_setup_recovery(&record).unwrap();
        let mut latest = after.clone();
        latest.settings.dns_provider = "quad9".into();
        latest.settings.auto_connect = true;
        state.vault.save(&latest).unwrap();
        let bytes = std::fs::read(dir.path().join("profile.enc")).unwrap();
        discard_checked(&state, &Some(record.operation_id)).unwrap();
        assert_eq!(state.profile.lock().unwrap().settings.dns_provider, "quad9");
        assert!(state.profile.lock().unwrap().settings.auto_connect);
        assert_eq!(
            std::fs::read(dir.path().join("profile.enc")).unwrap(),
            bytes
        );
        assert!(!pending(&state));
        assert!(state.core.lock().unwrap().is_none());
        assert_eq!(*state.status.lock().unwrap(), "disconnected");
        assert!(!state.wanted.load(Ordering::SeqCst));
    }
    #[test]
    fn stale_discard_token_or_corrupt_current_profile_keeps_pending_journal_and_cache() {
        let dir = tempfile::tempdir().unwrap();
        let before = Profile::default();
        let mut after = before.clone();
        after.settings.dns_provider = "google".into();
        let state = state(dir.path().join("profile.enc"), after.clone());
        state.vault.save(&after).unwrap();
        let record =
            Record::new(&uuid::Uuid::new_v4().to_string(), &before, &after, false).unwrap();
        state.vault.save_setup_recovery(&record).unwrap();
        assert!(discard_checked(&state, &Some("stale-token".into())).is_err());
        assert!(pending(&state));
        std::fs::write(dir.path().join("profile.enc"), b"corrupt-public-fixture").unwrap();
        assert!(discard_checked(&state, &Some(record.operation_id)).is_err());
        assert!(pending(&state));
        assert_eq!(
            state.profile.lock().unwrap().settings.dns_provider,
            "google"
        );
        let info = inspect(&state);
        assert!(!info.can_restore);
        assert!(info.error.unwrap().contains("Текущий защищённый профиль"));
    }
}
