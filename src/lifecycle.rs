use std::time::{Duration, Instant, SystemTime};

/// Health checks remain spaced out after failures, but a dead child or a long
/// wall-clock gap (sleep/wake, process suspension) schedules a prompt check.
pub struct RecoveryClock {
    health: Instant,
    wall: SystemTime,
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
