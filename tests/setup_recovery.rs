#![cfg(feature = "test-support")]
use smart_vpn_engine::{
    settings::{Profile, Vault},
    setup_recovery::{Phase, Record},
};
use std::{
    path::{Path, PathBuf},
    process::Command,
};
fn vault(path: &Path) -> Vault {
    Vault::test_fixture(path.join("profile.enc"), [42; 32])
}
fn profiles() -> (Profile, Profile) {
    let before = Profile::default();
    let mut after = before.clone();
    after.settings.dns_provider = "google".into();
    (before, after)
}
fn record() -> Record {
    let (before, after) = profiles();
    Record::new(&uuid::Uuid::new_v4().to_string(), &before, &after, false).unwrap()
}
#[test]
fn authenticated_record_roundtrip_nonce_tamper_wrong_key_and_purpose_separation() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    let r = record();
    v.save_setup_recovery(&r).unwrap();
    let file = dir.path().join("setup-recovery.enc");
    let first = std::fs::read(&file).unwrap();
    assert!(!first.windows(6).any(|v| v == b"google"));
    assert_eq!(
        v.load_setup_recovery().unwrap().unwrap().operation_id,
        r.operation_id
    );
    v.save_setup_recovery(&r).unwrap();
    let next = std::fs::read(&file).unwrap();
    assert_ne!(first, next);
    let wrong = Vault::test_fixture(dir.path().join("profile.enc"), [7; 32]);
    assert!(wrong.load_setup_recovery().is_err());
    let mut changed = next.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    std::fs::write(&file, changed).unwrap();
    assert!(v.load_setup_recovery().is_err());
    v.save(&r.before).unwrap();
    std::fs::copy(dir.path().join("profile.enc"), &file).unwrap();
    assert!(v.load_setup_recovery().is_err());
    std::fs::write(&file, first).unwrap();
    v.clear_setup_recovery().unwrap();
    assert!(v.load_setup_recovery().unwrap().is_none());
}
#[test]
fn lock_is_exclusive_confined_and_released_after_drop() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    let same = vault(dir.path());
    let otherdir = tempfile::tempdir().unwrap();
    let other = vault(otherdir.path());
    let lock = v.lock_configuration().unwrap();
    assert!(same.lock_configuration().is_err());
    assert!(same.save(&Profile::default()).is_err());
    assert!(other.save_locked(&Profile::default(), &lock).is_err());
    v.save_locked(&Profile::default(), &lock).unwrap();
    drop(lock);
    same.save(&Profile::default()).unwrap();
    assert!(same.lock_configuration().is_ok());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(dir.path().join("profile.enc"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
#[test]
fn pending_record_accepts_only_before_or_after_and_never_subsequent_user_changes() {
    let mut r = record();
    let (before, after) = profiles();
    assert!(r.accepts(&before).unwrap());
    assert!(r.accepts(&after).unwrap());
    let mut later = after.clone();
    later.settings.auto_connect = true;
    assert!(!r.accepts(&later).unwrap());
    assert!(r.pending());
    r.phase = Phase::Committed;
    assert!(!r.pending());
    r.phase = Phase::Restored;
    assert!(!r.pending());
    r.before.settings.dns_provider = "quad9".into();
    assert!(r.validate().is_err());
}
#[test]
#[ignore = "public subprocess fixture, invoked only by the crash harness"]
fn crash_worker() {
    let dir = PathBuf::from(std::env::var_os("FOXVPN_PUBLIC_CRASH_DIR").unwrap());
    let phase = std::env::var("FOXVPN_PUBLIC_CRASH_PHASE").unwrap();
    let v = vault(&dir);
    let _lock = v.lock_configuration().unwrap();
    let (before, after) = profiles();
    v.save_locked(&before, &_lock).unwrap();
    let mut r = Record::new(&uuid::Uuid::new_v4().to_string(), &before, &after, false).unwrap();
    v.save_setup_recovery(&r).unwrap();
    match phase.as_str() {
        "prepared" => (),
        "saving" => {
            r.phase = Phase::Saving;
            v.save_setup_recovery(&r).unwrap();
        }
        "saved" | "starting" | "verifying" | "committed" => {
            r.phase = Phase::Saving;
            v.save_setup_recovery(&r).unwrap();
            v.save_locked(&after, &_lock).unwrap();
            r.phase = match phase.as_str() {
                "starting" => Phase::Starting,
                "verifying" => Phase::Verifying,
                "committed" => Phase::Committed,
                _ => Phase::Saving,
            };
            v.save_setup_recovery(&r).unwrap();
        }
        _ => panic!("invalid public fixture"),
    }
    // _exit/ExitProcess skips Rust Drop and cleanup like an unexpected termination.
    std::process::exit(61);
}
#[test]
fn new_process_reads_authenticated_checkpoints_and_regains_lock_after_abrupt_exit() {
    for phase in [
        "prepared",
        "saving",
        "saved",
        "starting",
        "verifying",
        "committed",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "crash_worker", "--ignored", "--test-threads=1"])
            .env("FOXVPN_PUBLIC_CRASH_DIR", dir.path())
            .env("FOXVPN_PUBLIC_CRASH_PHASE", phase)
            .output()
            .unwrap()
            .status;
        assert_eq!(status.code(), Some(61), "{phase}");
        let v = vault(dir.path());
        let _lock = v.lock_configuration().unwrap();
        let current = v.load().unwrap();
        let r = v.load_setup_recovery().unwrap().unwrap();
        assert!(r.accepts(&current).unwrap());
        assert_eq!(r.pending(), phase != "committed");
        let expected = if phase == "prepared" || phase == "saving" {
            "cloudflare"
        } else {
            "google"
        };
        assert_eq!(current.settings.dns_provider, expected);
    }
}
#[cfg(unix)]
#[test]
fn symlink_and_nonregular_journals_are_rejected_without_reading_other_files() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("public.txt");
    std::fs::write(&target, "untouched").unwrap();
    let p = dir.path().join("setup-recovery.enc");
    std::os::unix::fs::symlink(&target, &p).unwrap();
    let v = vault(dir.path());
    assert!(v.load_setup_recovery().is_err());
    v.clear_setup_recovery().unwrap();
    assert_eq!(std::fs::read_to_string(target).unwrap(), "untouched");
    std::fs::create_dir(&p).unwrap();
    assert!(v.load_setup_recovery().is_err());
    assert!(v.clear_setup_recovery().is_err());
}

#[test]
fn missing_profile_stays_default_and_oversized_private_files_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    assert!(v.load().unwrap().servers.is_empty());
    assert!(v.load_setup_recovery().unwrap().is_none());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    v.save(&Profile::default()).unwrap();
    v.save_setup_recovery(&record()).unwrap();
    for name in ["profile.enc", "setup-recovery.enc"] {
        let path = dir.path().join(name);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(32 * 1024 * 1024 + 33)
            .unwrap();
        if name == "profile.enc" {
            assert!(v.load().is_err())
        } else {
            assert!(v.load_setup_recovery().is_err())
        }
    }
}
#[cfg(unix)]
#[test]
fn private_profile_journal_and_lock_reject_broader_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    v.save(&Profile::default()).unwrap();
    v.save_setup_recovery(&record()).unwrap();
    for name in ["profile.enc", "setup-recovery.enc", "configuration.lock"] {
        let path = dir.path().join(name);
        let bytes = std::fs::read(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        match name {
            "profile.enc" => assert!(v.load().is_err()),
            "setup-recovery.enc" => assert!(v.load_setup_recovery().is_err()),
            _ => assert!(v.lock_configuration().is_err()),
        }
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    v.load().unwrap();
    v.load_setup_recovery().unwrap();
    v.lock_configuration().unwrap();
}
#[cfg(unix)]
#[test]
fn profile_links_and_linked_parent_never_load_defaults_or_mutate_other_files() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    std::fs::create_dir(&store).unwrap();
    let v = vault(&store);
    v.save(&Profile::default()).unwrap();
    let profile = store.join("profile.enc");
    let target = store.join("preserved.enc");
    std::fs::rename(&profile, &target).unwrap();
    let bytes = std::fs::read(&target).unwrap();
    std::os::unix::fs::symlink(&target, &profile).unwrap();
    assert!(v.load().is_err());
    std::fs::remove_file(&profile).unwrap();
    std::os::unix::fs::symlink(store.join("missing.enc"), &profile).unwrap();
    assert!(v.load().is_err());
    std::fs::remove_file(&profile).unwrap();
    std::fs::rename(&target, &profile).unwrap();
    let link = dir.path().join("linked");
    std::os::unix::fs::symlink(&store, &link).unwrap();
    let linked = vault(&link);
    assert!(linked.load().is_err());
    assert!(linked.save(&Profile::default()).is_err());
    assert_eq!(std::fs::read(&profile).unwrap(), bytes);
}
#[cfg(unix)]
#[test]
fn replaced_configuration_lock_cannot_overwrite_a_later_profile() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    let original = Profile::default();
    v.save(&original).unwrap();
    let old = v.lock_configuration().unwrap();
    std::fs::remove_file(dir.path().join("configuration.lock")).unwrap();
    let newer = vault(dir.path());
    let mut latest = original.clone();
    latest.settings.dns_provider = "google".into();
    newer.save(&latest).unwrap();
    let bytes = std::fs::read(dir.path().join("profile.enc")).unwrap();
    assert!(v.save_locked(&original, &old).is_err());
    assert_eq!(
        std::fs::read(dir.path().join("profile.enc")).unwrap(),
        bytes
    );
    assert_eq!(newer.load().unwrap().settings.dns_provider, "google");
    drop(old);
    newer.lock_configuration().unwrap();
}
#[cfg(windows)]
#[test]
fn windows_configuration_lock_cannot_be_deleted_until_lease_drops() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    v.save(&Profile::default()).unwrap();
    let lock = v.lock_configuration().unwrap();
    assert!(std::fs::remove_file(dir.path().join("configuration.lock")).is_err());
    assert!(v.save(&Profile::default()).is_err());
    v.save_locked(&Profile::default(), &lock).unwrap();
    drop(lock);
    std::fs::remove_file(dir.path().join("configuration.lock")).unwrap();
    v.save(&Profile::default()).unwrap();
}
#[cfg(unix)]
#[test]
#[ignore = "public subprocess fixture for nonblocking private IO"]
fn nonregular_private_worker() {
    let dir = PathBuf::from(std::env::var_os("FOXVPN_PUBLIC_PRIVATE_IO_DIR").unwrap());
    let kind = std::env::var("FOXVPN_PUBLIC_PRIVATE_IO_KIND").unwrap();
    let v = vault(&dir);
    match kind.as_str() {
        "profile.enc" => assert!(v.load().is_err()),
        "setup-recovery.enc" => assert!(v.load_setup_recovery().is_err()),
        _ => assert!(v.lock_configuration().is_err()),
    }
    std::process::exit(61);
}
#[cfg(unix)]
#[test]
fn nonregular_private_files_are_rejected_without_blocking_a_recovery_operation() {
    use std::{
        ffi::CString,
        os::unix::ffi::OsStrExt,
        time::{Duration, Instant},
    };
    for name in ["profile.enc", "setup-recovery.enc", "configuration.lock"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        let native = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(native.as_ptr(), 0o600) }, 0);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "nonregular_private_worker",
                "--ignored",
                "--test-threads=1",
            ])
            .env("FOXVPN_PUBLIC_PRIVATE_IO_DIR", dir.path())
            .env("FOXVPN_PUBLIC_PRIVATE_IO_KIND", name)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert_eq!(status.code(), Some(61), "{name}");
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("private IO blocked on {name}")
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
