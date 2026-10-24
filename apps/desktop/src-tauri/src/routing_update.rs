//! A scoped routing edit may replace the running core, never the OS proxy lease.
//! Mac replacements use helper Start directly, preserving its PF guard.
use super::{ActiveCore, State};
use smart_vpn_engine::{
    app_routes::Application,
    lifecycle::ConnectionIntent,
    network_helper,
    routing::{self, Mode, Rule},
    settings::{configuration_digest, Profile},
    setup_recovery::{Phase, Record},
    vpn::CoreProcess,
};
use std::sync::atomic::Ordering;
use tauri::Emitter;

pub enum Change {
    Torrents {
        enabled: bool,
        expected: bool,
    },
    Rules {
        rules: Vec<Rule>,
        expected: Vec<Rule>,
    },
    Mode {
        mode: Mode,
        expected: Mode,
    },
    Apps {
        apps: Vec<Application>,
        expected: Vec<Application>,
    },
}
fn same(a: &impl serde::Serialize, b: &impl serde::Serialize) -> Result<bool, String> {
    Ok(
        serde_json::to_value(a).map_err(|_| "Не удалось проверить маршруты")?
            == serde_json::to_value(b).map_err(|_| "Не удалось проверить маршруты")?,
    )
}
impl Change {
    fn apply(self, p: &mut Profile) -> Result<(), String> {
        let stale =
            "Маршруты изменились в другом окне. Отмените местный черновик и повторите изменение";
        match self {
            Self::Torrents { enabled, expected } => {
                if p.settings.torrents_vpn != expected {
                    return Err(stale.into());
                }
                p.settings.torrents_vpn = enabled;
            }
            Self::Rules {
                mut rules,
                expected,
            } => {
                if !same(&p.rules, &expected)? {
                    return Err(stale.into());
                }
                routing::validate(&rules)?;
                for r in &mut rules {
                    let wildcard = r.domain.starts_with("*.");
                    let host =
                        routing::normalize(r.domain.strip_prefix("*.").unwrap_or(&r.domain))?;
                    r.domain = if wildcard { format!("*.{host}") } else { host };
                }
                p.rules = rules;
            }
            Self::Mode { mode, expected } => {
                if p.settings.mode != expected {
                    return Err(stale.into());
                }
                p.settings.mode = mode;
            }
            Self::Apps { apps, expected } => {
                let validate = if cfg!(windows) {
                    smart_vpn_engine::app_routes::validate_windows
                } else {
                    smart_vpn_engine::app_routes::validate
                };
                validate(&apps)?;
                validate(&expected)?;
                let selected = if cfg!(windows) {
                    &mut p.settings.windows_excluded_apps
                } else {
                    &mut p.settings.excluded_apps
                };
                if *selected != expected {
                    return Err(stale.into());
                }
                *selected = apps;
            }
        }
        p.validate()
    }
}
struct Pending<'a>(&'a ConnectionIntent, u64);
impl Drop for Pending<'_> {
    fn drop(&mut self) {
        self.0.finish_current(self.1);
    }
}
pub async fn dispatch(app: tauri::AppHandle, state: State, change: Change) -> Result<(), String> {
    let ticket = state.wanted.ticket();
    let result = tauri::async_runtime::spawn_blocking(move || apply(&state, change, ticket))
        .await
        .unwrap_or_else(|_| {
            Err("Не удалось применить маршруты. Проверьте незавершённую настройку".into())
        });
    // An unsuccessful rollback must expose recovery actions immediately, too.
    let _ = app.emit("setup-recovery-changed", ());
    result
}
pub(super) fn apply(state: &State, change: Change, ticket: u64) -> Result<(), String> {
    let _measure = state
        .measurements
        .lock()
        .map_err(|_| "Дождитесь проверки подключения")?;
    let _gate = state
        .gate
        .lock()
        .map_err(|_| "Маршруты заняты другой операцией")?;
    if state.installing.load(Ordering::SeqCst) {
        return Err("Дождитесь обновления приложения".into());
    }
    let _lease = state.vault.lock_configuration()?;
    // Inspect recovery under the same cross-window lease as the profile write.
    super::setup_recovery::ensure_resolved(state)?;
    let before = state.vault.load()?;
    before.validate()?;
    if configuration_digest(&before)?
        != configuration_digest(
            &*state
                .profile
                .lock()
                .map_err(|_| "Не удалось проверить профиль")?,
        )?
    {
        *state
            .profile
            .lock()
            .map_err(|_| "Не удалось прочитать профиль")? = before;
        return Err("Профиль изменился в другом окне. Обновите маршруты".into());
    }
    if !state.wanted.current(ticket) || state.wanted.pending(ticket) {
        return Err("Дождитесь завершения подключения или отключения".into());
    }
    let status = state
        .status
        .lock()
        .map_err(|_| "Нет состояния VPN")?
        .clone();
    let present = state
        .core
        .lock()
        .map_err(|_| "Нет состояния VPN")?
        .is_some();
    let active = match (status.as_str(), present) {
        ("connected", true) => true,
        ("disconnected", false) => false,
        _ => return Err("Состояние подключения не подтверждено. Сначала проверьте VPN".into()),
    };
    let mut after = before.clone();
    change.apply(&mut after)?;
    if configuration_digest(&after)? == configuration_digest(&before)? {
        return Ok(());
    }
    if !active {
        return state.wanted.with_current(ticket, || {
            state.vault.save_locked(&after, &_lease)?;
            *state
                .profile
                .lock()
                .map_err(|_| "Не удалось сохранить профиль")? = after;
            Ok(())
        });
    }
    super::diagnostics::verify_core(state)?;
    let mut runtime = Native::new(state, &before)?;
    state.wanted.begin_update(ticket)?;
    let _pending = Pending(&state.wanted, ticket);
    transact(state, &before, &after, ticket, &mut runtime, |p| {
        state.vault.save_locked(p, &_lease)
    })
}
trait Runtime {
    fn replace(&mut self, p: &Profile) -> Result<(), String>;
    fn stop(&mut self) -> Result<(), String>;
}
fn checkpoint(state: &State, record: &mut Record, phase: Phase) -> Result<(), String> {
    let owned = state
        .vault
        .load_setup_recovery()?
        .ok_or("Журнал изменения маршрутов отсутствует")?;
    if owned.operation_id != record.operation_id || !owned.pending() {
        return Err("Журнал относится к другой операции".into());
    }
    record.phase = phase;
    state.vault.save_setup_recovery(record)
}
fn transact(
    state: &State,
    before: &Profile,
    after: &Profile,
    ticket: u64,
    runtime: &mut impl Runtime,
    mut save: impl FnMut(&Profile) -> Result<(), String>,
) -> Result<(), String> {
    let mut record = Record::new(&uuid::Uuid::new_v4().to_string(), before, after, true)?;
    state.vault.save_setup_recovery(&record)?;
    *state.status.lock().map_err(|_| "Нет состояния VPN")? = "reconnecting".into();
    let result = (|| {
        checkpoint(state, &mut record, Phase::Starting)?;
        if !state.wanted.current(ticket) {
            return Err("Изменение отменено".into());
        }
        runtime.replace(after)?;
        checkpoint(state, &mut record, Phase::Verifying)?;
        state.wanted.with_current(ticket, || {
            checkpoint(state, &mut record, Phase::Saving)?;
            save(after)?;
            *state
                .profile
                .lock()
                .map_err(|_| "Не удалось сохранить профиль")? = after.clone();
            checkpoint(state, &mut record, Phase::Committed)?;
            let _ = state.vault.clear_setup_recovery();
            *state
                .status
                .lock()
                .map_err(|_| "Не удалось обновить статус")? = "connected".into();
            *state
                .proxy_error
                .lock()
                .map_err(|_| "Не удалось обновить статус")? = None;
            Ok(())
        })
    })();
    if let Err(error) = result {
        // A newer Stop/Connect must not be followed by a late automatic reconnect.
        let mut cancelled = !state.wanted.current(ticket);
        let mut failures = vec![];
        if let Err(e) = checkpoint(state, &mut record, Phase::Restoring) {
            *state.status.lock().map_err(|_| "Нет состояния VPN")? = "unknown".into();
            return Err(format!(
                "Не удалось применить маршруты: {error}. Восстановление требует проверки: {e}"
            ));
        }
        let restored = if cancelled {
            runtime.stop()
        } else {
            runtime.replace(before)
        };
        if let Err(e) = restored {
            failures.push(e);
        }
        // Stop can arrive while the previous core is being restored, too.
        if !cancelled && !state.wanted.current(ticket) {
            cancelled = true;
            if let Err(e) = runtime.stop() {
                failures.push(e);
            }
        }
        match state.vault.load() {
            Ok(current) if record.accepts(&current).unwrap_or(false) => {
                if configuration_digest(&current).ok() != Some(record.before_digest.clone()) {
                    if let Err(e) = save(before) {
                        failures.push(e);
                    }
                }
                if failures.is_empty() {
                    *state
                        .profile
                        .lock()
                        .map_err(|_| "Не удалось вернуть профиль")? = before.clone();
                }
            }
            _ => failures
                .push("Профиль изменился или недоступен; чужие изменения не заменялись".into()),
        }
        if failures.is_empty() {
            checkpoint(state, &mut record, Phase::Restored)?;
            let _ = state.vault.clear_setup_recovery();
            *state.status.lock().map_err(|_| "Нет состояния VPN")? = if cancelled {
                "disconnected"
            } else {
                "connected"
            }
            .into();
            return Err(if cancelled {
                "Изменение маршрутов отменено; подключение не возобновлялось".into()
            } else {
                format!("Не удалось применить маршруты: {error}. Прежние правила и подключение восстановлены")
            });
        }
        *state.status.lock().map_err(|_| "Нет состояния VPN")? = "unknown".into();
        return Err(format!(
            "Не удалось применить маршруты: {error}. Восстановление требует проверки: {}",
            failures.join("; ")
        ));
    }
    Ok(())
}
struct Native<'a> {
    state: &'a State,
    remote: bool,
    server_id: Option<String>,
}
impl<'a> Native<'a> {
    fn new(state: &'a State, p: &Profile) -> Result<Self, String> {
        let remote = state
            .core
            .lock()
            .map_err(|_| "Нет подключения")?
            .as_ref()
            .is_some_and(|c| c.local.is_none());
        let server_id = if remote {
            let helper = network_helper::require_current()?;
            smart_vpn_engine::torrent_policy::require_helper(&helper)?;
            let status = network_helper::request(&network_helper::Request::Status)?.status;
            if !super::diagnostics::confirmed_remote_start(&status, p.settings.proxy_port) {
                return Err("Системный VPN не подтвердил готовность".into());
            }
            status.active_server_id.or_else(|| p.selected.clone())
        } else {
            p.selected.clone()
        };
        Ok(Self {
            state,
            remote,
            server_id,
        })
    }
}
impl Runtime for Native<'_> {
    fn replace(&mut self, p: &Profile) -> Result<(), String> {
        let server = p
            .servers
            .iter()
            .find(|s| Some(&s.id) == self.server_id.as_ref())
            .ok_or("Текущий сервер отсутствует в профиле")?;
        if self.remote {
            let response = network_helper::request(&network_helper::Request::Start(Box::new(
                network_helper::StartRequest {
                    server: server.clone(),
                    settings: p.settings.clone(),
                    rules: p.rules.clone(),
                    reserves: smart_vpn_engine::latency::recovery_order(
                        &p.servers,
                        &server.id,
                        &p.settings,
                    )
                    .iter()
                    .filter(|id| *id != &server.id)
                    .filter_map(|id| p.servers.iter().find(|s| &s.id == id).cloned())
                    .collect(),
                },
            )))?;
            if !super::diagnostics::confirmed_remote_start(&response.status, p.settings.proxy_port)
                || response.status.kill_switch != p.settings.kill_switch
            {
                return Err("Системный VPN не подтвердил новые маршруты".into());
            }
            *self.state.core.lock().map_err(|_| "Нет состояния VPN")? =
                Some(ActiveCore::remote(response.status));
            return Ok(());
        }
        // Keep the existing Windows guardian/OS lease alive across replacement.
        let mut active = self
            .state
            .core
            .lock()
            .map_err(|_| "Нет подключения")?
            .take()
            .ok_or("Нет подключения")?;
        let result = (|| {
            active
                .local
                .as_mut()
                .ok_or("Нет локального ядра")?
                .stop_checked()?;
            let next = CoreProcess::start_on_port(
                &self.state.binary,
                server,
                &p.settings,
                &p.rules,
                p.settings.proxy_port,
            )?;
            smart_vpn_engine::statistics::read(next.api_port, &next.secret)?;
            active.proxy_port = next.proxy_port;
            active.api_port = next.api_port;
            active.secret = next.secret.clone();
            active.logs = next.logs.clone();
            active.local = Some(next);
            Ok(())
        })();
        *self
            .state
            .core
            .lock()
            .map_err(|_| "Нет состояния подключения")? = Some(active);
        result
    }
    fn stop(&mut self) -> Result<(), String> {
        super::disconnect_locked(self.state, self.state.wanted.ticket())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{atomic::AtomicBool, Arc, Mutex};
    fn profile() -> Profile {
        let mut p = Profile::default();
        let server = smart_vpn_engine::servers::Server::parse("vless://11111111-1111-4111-8111-111111111111@127.0.0.1:9?security=none&type=tcp#public-route-test").unwrap();
        p.selected = Some(server.id.clone());
        p.servers.push(server);
        p.servers[0].latency_ms = Some(37);
        p.settings.tun = false;
        p.settings.kill_switch = false;
        p.settings.mode = Mode::Direct;
        p.settings.proxy_acknowledged = true;
        p.settings.windows_proxy_auto = Some(false);
        p
    }
    fn fixture(p: &Profile, path: std::path::PathBuf) -> State {
        let state = State {
            installing: Arc::new(AtomicBool::new(false)),
            profile: Arc::new(Mutex::new(p.clone())),
            vault: Arc::new(smart_vpn_engine::settings::Vault::test_fixture(
                path, [42; 32],
            )),
            core: Arc::new(Mutex::new(None)),
            binary: "unused".into(),
            status: Arc::new(Mutex::new("connected".into())),
            gate: Arc::new(Mutex::new(())),
            measurements: Arc::new(Mutex::new(())),
            proxy_error: Arc::new(Mutex::new(None)),
            wanted: Arc::new(Default::default()),
        };
        state.vault.save(p).unwrap();
        let ticket = state.wanted.request().unwrap();
        state.wanted.finish_current(ticket);
        state
    }
    struct Fake<'a> {
        state: &'a State,
        calls: Vec<String>,
        fail: usize,
        cancel_at: usize,
        foreign: bool,
    }
    impl Runtime for Fake<'_> {
        fn replace(&mut self, p: &Profile) -> Result<(), String> {
            self.calls.push(format!("{:?}", p.settings.mode));
            if self.cancel_at == self.calls.len() {
                self.state.wanted.cancel();
            }
            if self.foreign {
                let other = Record::new(&uuid::Uuid::new_v4().to_string(), p, p, true).unwrap();
                self.state.vault.save_setup_recovery(&other).unwrap();
            }
            if self.fail > 0 {
                self.fail -= 1;
                Err("public injected runtime failure".into())
            } else {
                Ok(())
            }
        }
        fn stop(&mut self) -> Result<(), String> {
            self.calls.push("stop".into());
            Ok(())
        }
    }
    fn transaction_case(
        fail: usize,
        cancel_at: usize,
        save_fail: bool,
    ) -> (Vec<String>, State, tempfile::TempDir, Result<(), String>) {
        let dir = tempfile::tempdir().unwrap();
        let before = profile();
        let state = fixture(&before, dir.path().join("profile.enc"));
        let mut after = before.clone();
        after.settings.mode = Mode::Vpn;
        let mut runtime = Fake {
            state: &state,
            calls: vec![],
            fail,
            cancel_at,
            foreign: false,
        };
        let result = transact(
            &state,
            &before,
            &after,
            state.wanted.ticket(),
            &mut runtime,
            |p| {
                if save_fail {
                    Err("public injected fsync failure".into())
                } else {
                    state.vault.save(p)
                }
            },
        );
        (runtime.calls, state, dir, result)
    }
    #[test]
    fn commits_only_after_replacement_and_preserves_other_preferences() {
        let (calls, state, _dir, result) = transaction_case(0, 0, false);
        result.unwrap();
        assert_eq!(calls, ["Vpn"]);
        let p = state.vault.load().unwrap();
        assert_eq!(p.settings.mode, Mode::Vpn);
        assert_eq!(p.servers[0].latency_ms, Some(37));
        assert_eq!(p.settings.dns_provider, "cloudflare");
        assert!(state.vault.load_setup_recovery().unwrap().is_none());
        assert_eq!(*state.status.lock().unwrap(), "connected");
    }
    #[test]
    fn failed_replacement_and_failed_save_restore_previous_runtime_and_profile() {
        for (fail, save_fail) in [(1, false), (0, true)] {
            let (calls, state, _dir, result) = transaction_case(fail, 0, save_fail);
            assert!(result.unwrap_err().contains("восстановлены"));
            assert_eq!(calls, ["Vpn", "Direct"]);
            assert_eq!(state.vault.load().unwrap().settings.mode, Mode::Direct);
            assert!(state.vault.load_setup_recovery().unwrap().is_none());
            assert_eq!(*state.status.lock().unwrap(), "connected");
        }
    }
    #[test]
    fn error_after_profile_write_restores_the_durable_previous_profile() {
        let dir = tempfile::tempdir().unwrap();
        let before = profile();
        let state = fixture(&before, dir.path().join("profile.enc"));
        let mut after = before.clone();
        after.settings.mode = Mode::Vpn;
        let mut runtime = Fake {
            state: &state,
            calls: vec![],
            fail: 0,
            cancel_at: 0,
            foreign: false,
        };
        let mut writes = 0;
        let result = transact(
            &state,
            &before,
            &after,
            state.wanted.ticket(),
            &mut runtime,
            |p| {
                state.vault.save(p)?;
                writes += 1;
                if writes == 1 {
                    Err("public post-write failure".into())
                } else {
                    Ok(())
                }
            },
        );
        assert!(result.unwrap_err().contains("восстановлены"));
        assert_eq!(writes, 2);
        assert_eq!(runtime.calls, ["Vpn", "Direct"]);
        assert_eq!(state.vault.load().unwrap().settings.mode, Mode::Direct);
        assert!(state.vault.load_setup_recovery().unwrap().is_none());
    }
    #[test]
    fn failed_rollback_retains_encrypted_recovery_and_reports_unknown() {
        let (calls, state, _dir, result) = transaction_case(2, 0, false);
        assert!(result.unwrap_err().contains("требует проверки"));
        assert_eq!(calls, ["Vpn", "Direct"]);
        assert!(state
            .vault
            .load_setup_recovery()
            .unwrap()
            .unwrap()
            .pending());
        assert_eq!(*state.status.lock().unwrap(), "unknown");
        assert_eq!(state.vault.load().unwrap().settings.mode, Mode::Direct);
    }
    #[test]
    fn stop_during_replacement_or_rollback_never_leaves_reconnected_vpn() {
        for (fail, cancel_at, expected) in [
            (0, 1, vec!["Vpn", "stop"]),
            (1, 2, vec!["Vpn", "Direct", "stop"]),
        ] {
            let (calls, state, _dir, result) = transaction_case(fail, cancel_at, false);
            assert!(result.unwrap_err().contains("отменено"));
            assert_eq!(calls, expected);
            assert_eq!(state.vault.load().unwrap().settings.mode, Mode::Direct);
            assert_eq!(*state.status.lock().unwrap(), "disconnected");
            assert!(state.vault.load_setup_recovery().unwrap().is_none());
        }
    }
    #[test]
    fn foreign_journal_does_not_allow_rollback_or_profile_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let before = profile();
        let state = fixture(&before, dir.path().join("profile.enc"));
        let mut after = before.clone();
        after.settings.mode = Mode::Vpn;
        let mut runtime = Fake {
            state: &state,
            calls: vec![],
            fail: 0,
            cancel_at: 0,
            foreign: true,
        };
        assert!(transact(
            &state,
            &before,
            &after,
            state.wanted.ticket(),
            &mut runtime,
            |p| state.vault.save(p)
        )
        .is_err());
        assert_eq!(runtime.calls, ["Vpn"]);
        assert_eq!(state.vault.load().unwrap().settings.mode, Mode::Direct);
        assert!(state
            .vault
            .load_setup_recovery()
            .unwrap()
            .unwrap()
            .pending());
        assert_eq!(*state.status.lock().unwrap(), "unknown");
    }
    #[test]
    fn scoped_edits_reject_stale_rules_and_preserve_unrelated_settings() {
        let dir = tempfile::tempdir().unwrap();
        let before = profile();
        let state = fixture(&before, dir.path().join("profile.enc"));
        *state.status.lock().unwrap() = "disconnected".into();
        let rules = vec![Rule {
            domain: "http://192.168.0.1/webpages/index.html#/login".into(),
            route: "direct".into(),
        }];
        apply(
            &state,
            Change::Rules {
                rules,
                expected: vec![],
            },
            state.wanted.ticket(),
        )
        .unwrap();
        let saved = state.vault.load().unwrap();
        assert_eq!(saved.rules[0].domain, "192.168.0.1");
        assert!(apply(
            &state,
            Change::Rules {
                rules: vec![],
                expected: vec![]
            },
            state.wanted.ticket()
        )
        .is_err());
        apply(
            &state,
            Change::Mode {
                mode: Mode::Vpn,
                expected: Mode::Direct,
            },
            state.wanted.ticket(),
        )
        .unwrap();
        assert_eq!(state.vault.load().unwrap().rules[0].domain, "192.168.0.1");
        assert_eq!(
            state.vault.load().unwrap().settings.dns_provider,
            "cloudflare"
        );
        let ticket = state.wanted.request().unwrap();
        assert!(apply(
            &state,
            Change::Mode {
                mode: Mode::Smart,
                expected: Mode::Vpn
            },
            ticket
        )
        .is_err());
        state.wanted.finish_current(ticket);
        assert!(apply(
            &state,
            Change::Mode {
                mode: Mode::Smart,
                expected: Mode::Vpn
            },
            ticket.wrapping_sub(1)
        )
        .is_err());
    }
    #[test]
    fn torrent_choice_is_scoped_and_rejects_a_stale_expected_value() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile();
        let state = fixture(&p, dir.path().join("profile.enc"));
        *state.status.lock().unwrap() = "disconnected".into();
        apply(
            &state,
            Change::Torrents {
                enabled: true,
                expected: false,
            },
            state.wanted.ticket(),
        )
        .unwrap();
        assert!(state.vault.load().unwrap().settings.torrents_vpn);
        assert_eq!(state.vault.load().unwrap().settings.mode, Mode::Direct);
        assert_eq!(state.vault.load().unwrap().servers[0].latency_ms, Some(37));
        assert!(apply(
            &state,
            Change::Torrents {
                enabled: false,
                expected: false
            },
            state.wanted.ticket()
        )
        .is_err());
        apply(
            &state,
            Change::Torrents {
                enabled: false,
                expected: true,
            },
            state.wanted.ticket(),
        )
        .unwrap();
        assert!(!state.vault.load().unwrap().settings.torrents_vpn);
    }
    #[test]
    fn unresolved_recovery_and_another_window_lease_block_scoped_writes() {
        let dir = tempfile::tempdir().unwrap();
        let before = profile();
        let state = fixture(&before, dir.path().join("profile.enc"));
        *state.status.lock().unwrap() = "disconnected".into();
        let record =
            Record::new(&uuid::Uuid::new_v4().to_string(), &before, &before, true).unwrap();
        state.vault.save_setup_recovery(&record).unwrap();
        let change = || Change::Mode {
            mode: Mode::Vpn,
            expected: Mode::Direct,
        };
        assert!(apply(&state, change(), state.wanted.ticket()).is_err());
        assert_eq!(
            state
                .vault
                .load_setup_recovery()
                .unwrap()
                .unwrap()
                .operation_id,
            record.operation_id
        );
        state.vault.clear_setup_recovery().unwrap();
        let _lease = state.vault.lock_configuration().unwrap();
        assert!(apply(&state, change(), state.wanted.ticket()).is_err());
        assert_eq!(state.vault.load().unwrap().settings.mode, Mode::Direct);
    }
    #[test]
    fn real_core_replaces_active_rules_and_mode_on_same_port_without_os_changes() {
        exercise_real_core(false);
    }
    #[cfg(windows)]
    #[test]
    #[ignore = "changes disposable runner proxy; requires FOXVPN_TEST_ALLOW_SYSTEM_PROXY=1"]
    fn windows_real_proxy_restore_and_parent_death_with_active_routing() {
        assert_eq!(
            std::env::var("FOXVPN_TEST_ALLOW_SYSTEM_PROXY").as_deref(),
            Ok("1")
        );
        assert!(std::env::var("SMARTVPN_TEST_CORE").is_ok());
        exercise_real_core(true);
    }
    fn exercise_real_core(real_proxy: bool) {
        let Ok(binary) = std::env::var("SMARTVPN_TEST_CORE") else {
            return;
        };
        use std::{
            io::{Read, Write},
            net::TcpListener,
            time::Duration,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let stopped = done.clone();
        let responder = std::thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                if let Ok((mut stream, _)) = listener.accept() {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut data = [0; 4096];
                    let _ = stream.read(&mut data);
                    let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                } else {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let mut before = profile();
        before.settings.proxy_port = smart_vpn_engine::vpn::free_port().unwrap();
        #[cfg(windows)]
        struct ProxyEnvironment(
            smart_vpn_engine::windows_proxy::Configuration,
            Option<std::ffi::OsString>,
        );
        #[cfg(windows)]
        impl Drop for ProxyEnvironment {
            fn drop(&mut self) {
                let _ = smart_vpn_engine::windows_proxy::set_configuration(&self.0);
                match self.1.take() {
                    Some(v) => std::env::set_var("APPDATA", v),
                    None => std::env::remove_var("APPDATA"),
                }
            }
        }
        #[cfg(windows)]
        let cleanup = if real_proxy {
            let cleanup = ProxyEnvironment(
                smart_vpn_engine::windows_proxy::configuration().unwrap(),
                std::env::var_os("APPDATA"),
            );
            std::env::set_var("APPDATA", dir.path());
            Some(cleanup)
        } else {
            None
        };
        #[cfg(not(windows))]
        assert!(!real_proxy);
        let mut state = fixture(&before, dir.path().join("profile.enc"));
        state.binary = binary.into();
        let core = CoreProcess::start_on_port(
            &state.binary,
            &before.servers[0],
            &before.settings,
            &before.rules,
            before.settings.proxy_port,
        )
        .unwrap();
        *state.core.lock().unwrap() = Some(ActiveCore::local(core));
        #[cfg(windows)]
        if real_proxy {
            state.core.lock().unwrap().as_mut().unwrap().proxy_session = Some(
                crate::windows_proxy_auto::Session::start(before.settings.proxy_port).unwrap(),
            );
        }
        let check_lease = || {
            #[cfg(windows)]
            if let Some(cleanup) = cleanup.as_ref() {
                assert_eq!(
                    smart_vpn_engine::windows_proxy::configuration().unwrap(),
                    cleanup.0.managed(before.settings.proxy_port)
                );
                assert!(state
                    .core
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .proxy_session
                    .as_mut()
                    .unwrap()
                    .alive());
            }
        };
        check_lease();
        let client = reqwest::blocking::Client::builder()
            .proxy(
                reqwest::Proxy::all(format!("http://127.0.0.1:{}", before.settings.proxy_port))
                    .unwrap(),
            )
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let probe = || {
            client
                .get(format!("http://{address}/route-proof"))
                .send()
                .is_ok_and(|r| r.status().as_u16() == 204)
        };
        assert!(
            probe(),
            "{:?}",
            state
                .core
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .logs
                .lock()
                .unwrap()
        );
        let forced = vec![Rule {
            domain: "127.0.0.1".into(),
            route: "vpn".into(),
        }];
        apply(
            &state,
            Change::Rules {
                rules: forced.clone(),
                expected: vec![],
            },
            state.wanted.ticket(),
        )
        .unwrap();
        check_lease();
        assert!(!probe(), "explicit VPN must never fall back to direct");
        let direct = vec![Rule {
            domain: "127.0.0.1".into(),
            route: "direct".into(),
        }];
        apply(
            &state,
            Change::Rules {
                rules: direct.clone(),
                expected: forced,
            },
            state.wanted.ticket(),
        )
        .unwrap();
        assert!(probe());
        apply(
            &state,
            Change::Mode {
                mode: Mode::Vpn,
                expected: Mode::Direct,
            },
            state.wanted.ticket(),
        )
        .unwrap();
        check_lease();
        assert!(probe(), "explicit direct survives a mode change");
        assert_eq!(
            state.core.lock().unwrap().as_ref().unwrap().proxy_port,
            before.settings.proxy_port
        );
        assert!(!state.wanted.pending(state.wanted.ticket()));
        assert!(state.vault.load_setup_recovery().unwrap().is_none());
        state.core.lock().unwrap().take();
        #[cfg(windows)]
        if let Some(cleanup) = cleanup.as_ref() {
            assert_eq!(
                smart_vpn_engine::windows_proxy::configuration().unwrap(),
                cleanup.0
            );
        }
        done.store(true, Ordering::SeqCst);
        responder.join().unwrap();
    }
}
