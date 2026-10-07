//! Local proxy recovery never controls a remote TUN session or a newer connection.
use super::{connect_for_ticket, edit, State};
use smart_vpn_engine::{
    latency,
    lifecycle::{RecoveryClock, RetryBackoff},
};
use std::{
    collections::VecDeque,
    sync::atomic::Ordering,
    time::{Duration, Instant, SystemTime},
};
use tauri::Emitter;

pub fn stop_if_current(
    state: &State,
    token: &str,
    ticket: u64,
    restore: bool,
) -> Result<bool, String> {
    let _operation = state
        .gate
        .lock()
        .map_err(|_| "Не удалось прочитать состояние")?;
    if !state.wanted.current(ticket) {
        return Ok(false);
    }
    let mut core = state
        .core
        .lock()
        .map_err(|_| "Не удалось прочитать состояние")?;
    let Some(current) = core
        .as_mut()
        .filter(|c| c.local.is_some() && c.secret == token)
    else {
        return Ok(false);
    };
    current
        .local
        .as_mut()
        .ok_or("Нет локального компонента")?
        .stop_checked()?;
    if !restore {
        state.wanted.fail_current(ticket);
    }
    *core = None;
    *state
        .status
        .lock()
        .map_err(|_| "Не удалось прочитать состояние")? = if state.wanted.load(Ordering::SeqCst) {
        "reconnecting"
    } else {
        "disconnected"
    }
    .into();
    Ok(true)
}

pub struct Worker {
    health: RecoveryClock,
    retry: RetryBackoff,
    candidates: VecDeque<String>,
    last_error: Option<String>,
    ticket: Option<u64>,
}
impl Worker {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            health: RecoveryClock::new(now, SystemTime::now()),
            retry: RetryBackoff::new(now),
            candidates: VecDeque::new(),
            last_error: None,
            ticket: None,
        }
    }
    fn error(&mut self, app: &tauri::AppHandle, error: String) {
        if self.last_error.as_ref() != Some(&error) {
            let _ = app.emit("connection-error", &error);
        }
        self.last_error = Some(error);
    }
    pub fn tick(&mut self, state: &State, app: &tauri::AppHandle) {
        let ticket = state.wanted.ticket();
        if self.ticket != Some(ticket) {
            self.ticket = Some(ticket);
            self.candidates.clear();
            self.last_error = None;
            self.retry.reset(Instant::now());
        }
        if state.wanted.pending(ticket) {
            return;
        }
        let profile = match state.profile.lock() {
            Ok(p) => p.clone(),
            Err(_) => return,
        };
        if profile.settings.tun || !state.wanted.load(Ordering::SeqCst) {
            self.candidates.clear();
            self.last_error = None;
            self.retry.reset(Instant::now());
            return;
        }
        let current = match state.core.lock() {
            Ok(mut core) => core
                .as_mut()
                .filter(|c| c.local.is_some())
                .map(|c| (c.secret.clone(), c.proxy_port, c.alive())),
            Err(_) => return,
        };
        if let Some((token, port, alive)) = current {
            if self.health.due(
                Instant::now(),
                SystemTime::now(),
                Duration::from_secs(profile.settings.health_interval),
                !alive,
            ) {
                let healthy = alive
                    && latency::client(port)
                        .and_then(|c| {
                            c.get("https://www.gstatic.com/generate_204")
                                .send()
                                .map(|r| r.status().is_success())
                                .map_err(|_| "Не удалось проверить подключение".into())
                        })
                        .unwrap_or(false);
                if !healthy {
                    match stop_if_current(state, &token, ticket, profile.settings.restore) {
                        Ok(true) => {
                            if !profile.settings.restore {
                                self.error(app, smart_vpn_engine::text("message_344").into());
                            }
                            let _ = app.emit("servers-updated", ());
                        }
                        Ok(false) => return, // a manual reconnect installed a different core
                        Err(error) => {
                            self.error(app, error);
                            return;
                        }
                    }
                } else {
                    self.retry.reset(Instant::now());
                    self.candidates.clear();
                    self.last_error = None;
                }
            }
        }
        let empty = state.core.lock().is_ok_and(|core| core.is_none());
        if !empty
            || !profile.settings.restore
            || !state.wanted.load(Ordering::SeqCst)
            || !self.retry.ready(Instant::now())
        {
            return;
        }
        if self.candidates.is_empty() {
            if let Some(id) = profile.selected.as_ref() {
                self.candidates =
                    latency::recovery_order(&profile.servers, id, &profile.settings).into();
            }
        }
        let Some(id) = self.candidates.pop_front() else {
            return;
        };
        self.candidates.push_back(id.clone());
        let changed = edit(state, |p| {
            if p.settings.tun
                || !state.wanted.current(ticket)
                || !state.wanted.load(Ordering::SeqCst)
                || state
                    .core
                    .lock()
                    .map_err(|_| "Не удалось прочитать состояние")?
                    .is_some()
            {
                return Ok(false);
            }
            if !p.servers.iter().any(|s| s.id == id) {
                return Ok(false);
            }
            p.selected = Some(id.clone());
            Ok(true)
        });
        match changed {
            Ok(true) => match connect_for_ticket(state, ticket, false) {
                Ok(_) => {
                    self.retry.reset(Instant::now());
                    self.candidates.clear();
                    self.last_error = None;
                }
                Err(error) => {
                    self.retry.failed(Instant::now());
                    let current = {
                        let _operation = state.gate.lock().unwrap();
                        if state.wanted.current(ticket)
                            && state.wanted.load(Ordering::SeqCst)
                            && state.core.lock().unwrap().is_none()
                        {
                            *state.status.lock().unwrap() = "reconnecting".into();
                            true
                        } else {
                            false
                        }
                    };
                    if current {
                        self.error(app, error);
                    }
                }
            },
            Ok(false) => {
                self.candidates.clear();
                self.retry.failed(Instant::now());
            }
            Err(error) => {
                self.retry.failed(Instant::now());
                self.error(app, error);
            }
        }
        let _ = app.emit("servers-updated", ());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ActiveCore;
    use smart_vpn_engine::{
        lifecycle::ConnectionIntent,
        routing::Mode,
        servers::Server,
        settings::{Profile, Settings, Vault},
        vpn::CoreProcess,
    };
    use std::sync::{atomic::AtomicBool, Arc, Mutex};
    #[test]
    fn stale_health_result_cannot_stop_a_newer_intent_or_session() {
        let Ok(binary) = std::env::var("SMARTVPN_TEST_CORE") else {
            return;
        };
        let server = Server::parse("vless://11111111-1111-4111-8111-111111111111@127.0.0.1:9?security=none&type=tcp#public-session-test").unwrap();
        let settings = Settings {
            tun: false,
            kill_switch: false,
            mode: Mode::Direct,
            ..Default::default()
        };
        let core =
            CoreProcess::start(std::path::Path::new(&binary), &server, &settings, &[]).unwrap();
        let token = core.secret.clone();
        let port = core.proxy_port;
        let state = State {
            installing: Arc::new(AtomicBool::new(false)),
            profile: Arc::new(Mutex::new(Profile::default())),
            vault: Arc::new(Vault::new("foxvpn-unused-test-vault")),
            core: Arc::new(Mutex::new(Some(ActiveCore::local(core)))),
            binary: binary.into(),
            status: Arc::new(Mutex::new("connected".into())),
            gate: Arc::new(Mutex::new(())),
            measurements: Arc::new(Mutex::new(())),
            wanted: Arc::new(ConnectionIntent::default()),
        };
        let old = state.wanted.request().unwrap();
        assert!(!stop_if_current(&state, "old-session-token", old, true).unwrap());
        state.wanted.cancel();
        let new = state.wanted.request().unwrap();
        assert!(!stop_if_current(&state, &token, old, true).unwrap());
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
        assert!(stop_if_current(&state, &token, new, true).unwrap());
        assert!(state.core.lock().unwrap().is_none());
        assert_eq!(state.status.lock().unwrap().as_str(), "reconnecting");
    }
}
