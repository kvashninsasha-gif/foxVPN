use std::time::{Duration, Instant, SystemTime};

#[derive(Default)]
struct IntentState {
    ticket: u64,
    wanted: bool,
    closing: bool,
    pending: bool,
}
#[derive(Default)]
pub struct ConnectionIntent(std::sync::Mutex<IntentState>);
impl ConnectionIntent {
    pub fn request_startup(&self) -> Option<u64> {
        let mut state = self.0.lock().ok()?;
        if state.ticket != 0 || state.closing {
            return None;
        }
        state.ticket = 1;
        state.wanted = true;
        state.pending = true;
        Some(1)
    }
    pub fn request(&self) -> Result<u64, String> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| crate::text("connection_cancelled"))?;
        if state.closing {
            return Err(crate::text("app_closing").into());
        }
        state.ticket = state.ticket.wrapping_add(1);
        state.wanted = true;
        state.pending = true;
        Ok(state.ticket)
    }
    pub fn cancel(&self) -> u64 {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !state.closing {
            state.ticket = state.ticket.wrapping_add(1);
        }
        state.wanted = false;
        state.pending = false;
        state.ticket
    }
    pub fn close(&self) -> u64 {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !state.closing {
            state.ticket = state.ticket.wrapping_add(1);
        }
        state.wanted = false;
        state.pending = false;
        state.closing = true;
        state.ticket
    }
    pub fn reopen(&self) {
        if let Ok(mut state) = self.0.lock() {
            state.closing = false;
        }
    }
    pub fn ticket(&self) -> u64 {
        self.0.lock().map(|s| s.ticket).unwrap_or_default()
    }
    pub fn current(&self, ticket: u64) -> bool {
        self.0.lock().is_ok_and(|s| s.ticket == ticket)
    }
    pub fn fail_current(&self, ticket: u64) {
        if let Ok(mut state) = self.0.lock() {
            if state.ticket == ticket {
                state.wanted = false;
                state.pending = false;
            }
        }
    }
    pub fn finish_current(&self, ticket: u64) {
        if let Ok(mut state) = self.0.lock() {
            if state.ticket == ticket {
                state.pending = false;
            }
        }
    }
    pub fn pending(&self, ticket: u64) -> bool {
        self.0.lock().is_ok_and(|s| s.ticket == ticket && s.pending)
    }
    // Compatibility for readers and cancellation sites; a new request carries
    // a ticket so a late result cannot cancel a newer user's action.
    pub fn load(&self, _: std::sync::atomic::Ordering) -> bool {
        self.0.lock().is_ok_and(|s| s.wanted)
    }
    pub fn store(&self, wanted: bool, _: std::sync::atomic::Ordering) {
        if wanted {
            let _ = self.request();
        } else {
            self.cancel();
        }
    }
}

/// Health checks remain spaced out after failures, but a dead child or a long
/// wall-clock gap (sleep/wake, process suspension) schedules a prompt check.
pub struct RecoveryClock {
    health: Instant,
    wall: SystemTime,
}

/// Failed recovery attempts use their own clock, independently of health checks.
pub struct RetryBackoff {
    failures: u32,
    next: Instant,
}
impl RetryBackoff {
    pub fn new(now: Instant) -> Self {
        Self {
            failures: 0,
            next: now,
        }
    }
    pub fn ready(&self, now: Instant) -> bool {
        now >= self.next
    }
    pub fn reset(&mut self, now: Instant) {
        self.failures = 0;
        self.next = now;
    }
    pub fn failed(&mut self, now: Instant) {
        let seconds = (3u64 << self.failures.min(5)).min(60);
        self.failures = self.failures.saturating_add(1);
        self.next = now + Duration::from_secs(seconds);
    }
}
impl RecoveryClock {
    pub fn new(now: Instant, wall: SystemTime) -> Self {
        Self { health: now, wall }
    }
    pub fn due(&mut self, now: Instant, wall: SystemTime, interval: Duration, dead: bool) -> bool {
        let resumed = wall.duration_since(self.wall).unwrap_or_default() >= Duration::from_secs(20);
        self.wall = wall;
        let due = dead || resumed || now.saturating_duration_since(self.health) >= interval;
        if due {
            self.health = now;
        }
        due
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn newer_user_intent_wins_over_late_failure_and_close_seals_requests() {
        use std::sync::atomic::Ordering::SeqCst;
        let intent = ConnectionIntent::default();
        let old = intent.request().unwrap();
        intent.cancel();
        assert!(!intent.current(old));
        assert!(!intent.load(SeqCst));
        let new = intent.request().unwrap();
        intent.fail_current(old);
        intent.finish_current(old);
        assert!(intent.pending(new));
        intent.finish_current(new);
        assert!(!intent.pending(new));
        assert!(intent.current(new));
        assert!(intent.load(SeqCst));
        intent.close();
        assert!(intent.request().is_err());
        assert!(!intent.load(SeqCst));
        intent.reopen();
        assert!(intent.request().is_ok());
        let startup = ConnectionIntent::default();
        startup.cancel();
        assert!(startup.request_startup().is_none());
    }
    #[test]
    fn retries_back_off_and_success_or_cancel_resets_the_deadline() {
        let now = Instant::now();
        let mut retry = RetryBackoff::new(now);
        let mut current = now;
        for wait in [3, 6, 12, 24, 48, 60, 60] {
            retry.failed(current);
            assert!(!retry.ready(current + Duration::from_secs(wait - 1)));
            current += Duration::from_secs(wait);
            assert!(retry.ready(current));
        }
        retry.reset(current);
        assert!(retry.ready(current));
        retry.failed(current);
        assert!(retry.ready(current + Duration::from_secs(3)));
    }
    #[test]
    fn crash_is_immediate_and_failed_retries_remain_spaced() {
        let now = Instant::now();
        let wall = SystemTime::now();
        let mut clock = RecoveryClock::new(now, wall);
        let interval = Duration::from_secs(30);
        assert!(clock.due(now, wall, interval, true));
        assert!(!clock.due(
            now + Duration::from_secs(2),
            wall + Duration::from_secs(2),
            interval,
            false
        ));
        assert!(clock.due(now + interval, wall + interval, interval, false));
    }
    #[test]
    fn wake_triggers_health_even_when_monotonic_time_did_not_advance() {
        let now = Instant::now();
        let wall = SystemTime::now();
        let mut clock = RecoveryClock::new(now, wall);
        assert!(clock.due(
            now,
            wall + Duration::from_secs(60),
            Duration::from_secs(30),
            false
        ));
        assert!(!clock.due(
            now + Duration::from_secs(2),
            wall + Duration::from_secs(62),
            Duration::from_secs(30),
            false
        ));
    }
    #[test]
    fn backwards_wall_clock_does_not_trigger_a_retry_storm() {
        let now = Instant::now();
        let wall = SystemTime::now();
        let mut clock = RecoveryClock::new(now, wall);
        assert!(!clock.due(
            now,
            wall - Duration::from_secs(60),
            Duration::from_secs(30),
            false
        ));
    }
}
