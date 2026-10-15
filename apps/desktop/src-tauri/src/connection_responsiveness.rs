//! The UI-facing snapshot must yield while a network worker owns its mutexes.
//! These tests deliberately block real State mutexes, without starting a VPN
//! or opening the system keyring.
use super::{runtime_impl, snapshot_in_background, ActiveCore, State};
use smart_vpn_engine::{
    lifecycle::ConnectionIntent,
    settings::{Profile, Vault},
};
use std::{
    sync::{atomic::AtomicBool, mpsc, Arc, Mutex},
    time::Duration,
};

fn fixture(path: std::path::PathBuf) -> State {
    State {
        installing: Arc::new(AtomicBool::new(false)),
        profile: Arc::new(Mutex::new(Profile::default())),
        vault: Arc::new(Vault::test_fixture(path, [42; 32])),
        core: Arc::new(Mutex::new(None)),
        binary: std::path::PathBuf::from("unused"),
        status: Arc::new(Mutex::new("connecting".into())),
        gate: Arc::new(Mutex::new(())),
        measurements: Arc::new(Mutex::new(())),
        proxy_error: Arc::new(Mutex::new(None)),
        wanted: Arc::new(ConnectionIntent::default()),
    }
}

fn remote_status() -> smart_vpn_engine::network_helper::Status {
    smart_vpn_engine::network_helper::Status {
        protocol: smart_vpn_engine::network_helper::PROTOCOL,
        helper_version: "0.1.29".into(),
        running: true,
        wanted: true,
        core_alive: true,
        dns_active: true,
        proxy_port: 2080,
        ..Default::default()
    }
}

#[test]
fn delayed_helper_status_and_logs_leave_core_available_and_cannot_revive_a_stopped_connection() {
    use smart_vpn_engine::network_helper::{Request, Response};
    // Exercise both serialized helper operations: waiting for logs must not
    // keep a stale connected Status eligible after a newer disconnect either.
    for block_logs in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let state = fixture(directory.path().join("profile.enc"));
        state.profile.lock().unwrap().settings.tun = true;
        let ticket = state.wanted.request().unwrap();
        state.wanted.finish_current(ticket);
        *state.status.lock().unwrap() = "connected".into();
        *state.core.lock().unwrap() = Some(ActiveCore::remote(remote_status()));
        let worker_state = state.clone();
        let (waiting_tx, waiting_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            runtime_impl(&worker_state, block_logs, |request| {
                if matches!(request, Request::Logs) == block_logs {
                    waiting_tx.send(()).unwrap();
                    let _ = release_rx.recv_timeout(Duration::from_secs(3));
                }
                Ok(Response {
                    status: remote_status(),
                    logs: vec!["stale helper logs".into()],
                    error: None,
                })
            })
        });
        waiting_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let core_available = state.core.try_lock().is_ok();
        let profile_available = state.profile.try_lock().is_ok();
        state.wanted.cancel();
        // This is the state a completed newer Stop publishes. Old RPC replies
        // may still arrive, but must not recreate its remote handle or logs.
        *state.status.lock().unwrap() = "disconnected".into();
        if core_available {
            *state.core.lock().unwrap() = None;
        }
        release_tx.send(()).unwrap();
        let result = worker.join().unwrap().unwrap();
        assert!(core_available, "helper IPC must not hold the core mutex");
        assert!(
            profile_available,
            "helper IPC must not hold the profile mutex"
        );
        assert_eq!(result.status, "disconnected");
        assert!(result.proxy_port.is_none());
        assert!(result.active_server_id.is_none());
        assert!(state.core.lock().unwrap().is_none());
        if block_logs {
            assert_eq!(result.logs, Some(vec![]));
        }
    }
}

#[test]
fn pending_connection_uses_cached_state_without_queueing_helper_requests() {
    let directory = tempfile::tempdir().unwrap();
    let state = fixture(directory.path().join("profile.enc"));
    state.profile.lock().unwrap().settings.tun = true;
    let ticket = state.wanted.request().unwrap();
    assert!(state.wanted.pending(ticket));
    let result = runtime_impl(&state, true, |_| {
        panic!("a pending Start must not queue Status or Logs behind itself")
    })
    .unwrap();
    assert_eq!(result.status, "connecting");
    assert!(result.proxy_port.is_none());
    assert_eq!(result.logs, Some(vec![]));
}

#[tokio::test(flavor = "current_thread")]
async fn snapshot_leaves_the_event_executor_responsive_while_connection_mutexes_are_busy() {
    // A single-thread executor exposes accidental synchronous work: a timer
    // cannot run if polling the snapshot blocks on either connection mutex.
    for lock_profile in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let state = fixture(directory.path().join("profile.enc"));
        let busy = state.clone();
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            if lock_profile {
                let _guard = busy.profile.lock().unwrap();
                held_tx.send(()).unwrap();
                // A bounded fallback also lets a broken implementation finish
                // and report a test failure instead of hanging the test suite.
                let _ = release_rx.recv_timeout(Duration::from_secs(2));
            } else {
                let _guard = busy.core.lock().unwrap();
                held_tx.send(()).unwrap();
                let _ = release_rx.recv_timeout(Duration::from_secs(2));
            }
        });
        held_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let pending = snapshot_in_background(state);
        tokio::pin!(pending);
        let (responsive, already_finished) = tokio::select! {
            biased;
            result = &mut pending => (false, Some(result)),
            _ = tokio::time::sleep(Duration::from_millis(50)) => (true, None),
        };
        let _ = release_tx.send(());
        let snapshot = match already_finished {
            Some(result) => result,
            None => tokio::time::timeout(Duration::from_secs(8), &mut pending)
                .await
                .expect("snapshot must finish after the connection mutex is released"),
        };
        worker.join().unwrap();
        assert!(
            responsive,
            "snapshot blocked the event executor while {} was busy",
            if lock_profile { "profile" } else { "core" }
        );
        let snapshot = snapshot.unwrap();
        assert_eq!(snapshot.status, "connecting");
        assert!(snapshot.proxy_port.is_none());
    }
}

#[test]
fn startup_adoption_finishes_pending_intent_and_does_not_undo_a_stop() {
    let dir = tempfile::tempdir().unwrap();
    let state = fixture(dir.path().join("profile.enc"));
    super::adopt_startup_status(&state, 0, remote_status());
    let ticket = state.wanted.ticket();
    assert!(state.wanted.load(std::sync::atomic::Ordering::SeqCst));
    assert!(!state.wanted.pending(ticket));
    assert_eq!(state.status.lock().unwrap().as_str(), "connected");
    state.wanted.cancel();
    *state.core.lock().unwrap() = None;
    *state.status.lock().unwrap() = "disconnected".into();
    super::adopt_startup_status(&state, ticket, remote_status());
    assert_eq!(state.status.lock().unwrap().as_str(), "disconnected");
    assert!(state.core.lock().unwrap().is_none());
}
#[test]
fn a_running_helper_with_failed_dns_is_never_displayed_as_connected() {
    let dir = tempfile::tempdir().unwrap();
    let state = fixture(dir.path().join("profile.enc"));
    state.profile.lock().unwrap().settings.tun = true;
    let mut failed = remote_status();
    failed.dns_active = false;
    let result = runtime_impl(&state, false, |_| {
        Ok(smart_vpn_engine::network_helper::Response {
            status: failed.clone(),
            logs: vec![],
            error: None,
        })
    })
    .unwrap();
    assert_eq!(result.status, "unknown");
    assert!(result.connection_error.is_some());
    assert!(state.core.lock().unwrap().is_none());
    super::adopt_startup_status(&state, 0, failed);
    assert_eq!(state.status.lock().unwrap().as_str(), "unknown");
    assert!(state.core.lock().unwrap().is_none());
}
