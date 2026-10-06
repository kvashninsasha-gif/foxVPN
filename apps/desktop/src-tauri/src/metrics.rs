//! Minute measurements use the active proxy and never change connection health.
use super::{edit, State};
use std::time::{Duration, Instant};
use tauri::Emitter;
#[derive(Clone, PartialEq, Eq)]
struct Connection {
    id: String,
    port: u16,
    token: String,
}
#[derive(Default)]
struct Clock {
    connection: Option<Connection>,
    next: Option<Instant>,
}
impl Clock {
    fn due(&mut self, current: Option<Connection>, now: Instant) -> bool {
        if current.is_none() {
            self.connection = None;
            self.next = None;
            return false;
        }
        let due = self.connection != current || self.next.is_none_or(|next| now >= next);
        self.connection = current;
        if due {
            self.next = Some(now + Duration::from_secs(60));
        }
        due
    }
}
fn connection(s: &State) -> Option<Connection> {
    if s.installing.load(std::sync::atomic::Ordering::SeqCst)
        || s.status.lock().ok()?.as_str() != "connected"
    {
        return None;
    }
    let id = s.profile.lock().ok()?.selected.clone()?;
    let core = s.core.lock().ok()?;
    let core = core.as_ref()?;
    Some(Connection {
        id,
        port: core.proxy_port,
        token: core.secret.clone(),
    })
}
pub fn start(state: State, app: tauri::AppHandle) {
    std::thread::spawn(move || {
        let mut clock = Clock::default();
        loop {
            let current = connection(&state);
            if clock.due(current.clone(), Instant::now()) {
                if let (Some(current), Ok(_measurement)) = (current, state.measurements.try_lock())
                {
                    let result = smart_vpn_engine::latency::measure_port(current.port, 1_000_000);
                    // Disconnection, reconnection or selection changes invalidate a late result.
                    if connection(&state).as_ref() == Some(&current) {
                        let changed = edit(&state, |profile| {
                            let core = state.core.lock().map_err(|_| "metric state unavailable")?;
                            if state
                                .status
                                .lock()
                                .map_err(|_| "metric state unavailable")?
                                .as_str()
                                != "connected"
                                || profile.selected.as_ref() != Some(&current.id)
                                || !core.as_ref().is_some_and(|c| {
                                    c.proxy_port == current.port && c.secret == current.token
                                })
                            {
                                return Ok(false);
                            }
                            if let Some(server) =
                                profile.servers.iter_mut().find(|s| s.id == current.id)
                            {
                                server.latency_ms = result.as_ref().ok().map(|m| m.latency_ms);
                                server.download_mbps =
                                    result.as_ref().ok().and_then(|m| m.download_mbps);
                                return Ok(true);
                            }
                            Ok(false)
                        })
                        .unwrap_or(false);
                        if changed {
                            let _ = app.emit("metrics-updated", ());
                        }
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    });
}
#[cfg(test)]
mod tests {
    use super::*;
    fn sample(token: &str) -> Connection {
        Connection {
            id: "fixture".into(),
            port: 2080,
            token: token.into(),
        }
    }
    #[test]
    fn immediate_then_once_per_minute_and_reconnect_invalidates_identity() {
        let now = Instant::now();
        let mut clock = Clock::default();
        assert!(!clock.due(None, now));
        assert!(clock.due(Some(sample("a")), now));
        assert!(!clock.due(Some(sample("a")), now + Duration::from_secs(59)));
        assert!(clock.due(Some(sample("a")), now + Duration::from_secs(60)));
        assert!(clock.due(Some(sample("b")), now + Duration::from_secs(61)));
        assert!(!clock.due(None, now + Duration::from_secs(62)));
        assert!(clock.due(Some(sample("b")), now + Duration::from_secs(63)));
        assert!(sample("a") != sample("b"));
    }
}
