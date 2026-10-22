use smart_vpn_engine::{
    app_routes::{self, Application},
    routing::{Mode, Rule},
    servers::Server,
    settings::{Profile, Settings},
    vpn,
};
fn app(path: &str) -> Application {
    Application {
        name: "Windows App".into(),
        path: path.into(),
    }
}

#[test]
fn bundle_scope_is_bounded_escaped_and_preserved_in_profile_digest() {
    let a = app("/Applications/Windows App (Preview)+[1].app");
    app_routes::validate(std::slice::from_ref(&a)).unwrap();
    assert_eq!(
        app_routes::bundle_pattern(&a),
        r"^/Applications/Windows App \(Preview\)\+\[1\]\.app/"
    );
    for path in [
        "",
        "/",
        "Windows.app",
        "/Applications/../Safari.app",
        "/Applications//Foo.app",
        "/Applications/Foo.app/",
        "/Applications/Foo.app/Contents/MacOS/Foo",
        "/Applications/Bad\n.app",
        "/Applications/Bad\\.app",
    ] {
        assert!(
            app_routes::validate(&[app(path)]).is_err(),
            "accepted {path:?}"
        );
    }
    assert!(app_routes::validate(&[a.clone(), a.clone()]).is_err());
    assert!(app_routes::validate(&vec![a.clone(); 101]).is_err());
    let mut profile = Profile::default();
    let before = smart_vpn_engine::settings::configuration_digest(&profile).unwrap();
    profile.settings.excluded_apps.push(a.clone());
    assert_ne!(
        before,
        smart_vpn_engine::settings::configuration_digest(&profile).unwrap()
    );
    let copied: Profile = serde_json::from_slice(&serde_json::to_vec(&profile).unwrap()).unwrap();
    assert_eq!(copied.settings.excluded_apps, vec![a]);
    let legacy: Settings = serde_json::from_str("{}").unwrap();
    assert!(legacy.excluded_apps.is_empty());
}

#[test]
fn only_mac_tun_applies_app_exclusions_before_domain_rules_without_bypassing_dns() {
    let server =
        Server::parse("vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls")
            .unwrap();
    for mode in [Mode::Smart, Mode::Vpn, Mode::Custom, Mode::Direct] {
        let mut settings = Settings {
            mode,
            excluded_apps: vec![app("/Applications/Windows App.app")],
            ..Default::default()
        };
        let rules = vec![Rule {
            domain: "example.com".into(),
            route: "vpn".into(),
        }];
        let cfg = vpn::config(&server, &settings, &rules, 2080, 2081, "public-fixture").unwrap();
        if cfg!(target_os = "macos") {
            assert_eq!(cfg["route"]["find_process"], true);
            assert_eq!(cfg["route"]["rules"][1]["action"], "hijack-dns");
            assert_eq!(cfg["route"]["rules"][2]["outbound"], "direct");
            assert_eq!(
                cfg["route"]["rules"][2]["process_path_regex"][0],
                r"^/Applications/Windows App\.app/"
            );
        } else {
            assert!(cfg["route"]["find_process"].is_null());
        }
        settings.tun = false;
        let proxy = vpn::config(&server, &settings, &rules, 2080, 2081, "public-fixture").unwrap();
        assert!(proxy["route"]["find_process"].is_null());
        assert!(proxy["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["process_path_regex"].is_null()));
    }
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires disposable root runner and final privilege-drop core"]
fn actual_core_matches_bundle_and_nested_helper_but_not_sibling_name() {
    use std::{
        io::{Read, Write},
        process::{Command, Stdio},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    };
    let Ok(binary) = std::env::var("SMARTVPN_TEST_CORE") else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let app_uid: u32 = std::env::var("FOXVPN_TEST_APP_UID")
        .expect("non-root fixture owner")
        .parse()
        .unwrap();
    assert!(app_uid >= 501 && app_uid != 62077);
    use std::os::unix::{fs::PermissionsExt, process::CommandExt};
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let bundle = dir
        .path()
        .canonicalize()
        .unwrap()
        .join("Windows App [Fixture].app");
    let main = bundle.join("Contents/MacOS/Fixture");
    let helper = bundle.join("Contents/Frameworks/Helper.app/Contents/MacOS/Helper");
    let sibling = bundle
        .with_extension("app.evil")
        .join("Contents/MacOS/Fixture");
    let outside = dir.path().join("other-client");
    for path in [&main, &helper, &sibling, &outside] {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::copy("/usr/bin/curl", path).unwrap();
        // A relocated Apple platform binary must lose its platform signature.
        assert!(Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-"])
            .arg(path)
            .output()
            .unwrap()
            .status
            .success());
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let http_port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let done = stop.clone();
    let http = std::thread::spawn(move || {
        let mut count = 0;
        let deadline = Instant::now() + Duration::from_secs(30);
        while !done.load(Ordering::SeqCst) && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut client, _)) => {
                    client
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut bytes = [0; 4096];
                    if client.read(&mut bytes).unwrap_or(0) > 0 {
                        count += 1;
                        let _=client.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nDIRECT");
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("HTTP fixture: {e}"),
            }
        }
        count
    });
    // An unavailable loopback VPN makes an incorrect fallback observable.
    let unavailable_vpn = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let server = Server::parse(&format!(
        "vless://11111111-1111-4111-8111-111111111111@127.0.0.1:{}?security=none",
        unavailable_vpn.local_addr().unwrap().port()
    ))
    .unwrap();
    let settings = Settings {
        mode: Mode::Vpn,
        kill_switch: false,
        excluded_apps: vec![app(bundle.to_str().unwrap())],
        ..Default::default()
    };
    let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = proxy.local_addr().unwrap().port();
    let mut cfg = vpn::config(&server, &settings, &[], port, 0, "public-app-fixture").unwrap();
    // Keep production process routing, but remove TUN to isolate the test from
    // the host network. Separate system acceptance covers real TUN routing.
    cfg["inbounds"]
        .as_array_mut()
        .unwrap()
        .retain(|i| i["type"] != "tun");
    // The loopback direct inbound preserves the real socket destination for
    // macOS process lookup, unlike an HTTP proxy's logical destination.
    cfg["inbounds"][0] = serde_json::json!({"type":"direct","tag":"fixture-in","listen":"127.0.0.1","listen_port":port,"override_address":"127.0.0.1","override_port":http_port});
    cfg.as_object_mut().unwrap().remove("experimental");
    cfg["log"]["level"] = serde_json::json!("debug");
    let log_path = dir.path().join("core.log");
    let path = dir.path().join("config.json");
    std::fs::write(&path, serde_json::to_vec(&cfg).unwrap()).unwrap();
    drop(proxy);
    let mut command = Command::new(binary);
    command
        .args(["run", "-c"])
        .arg(path)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log_path).unwrap());
    let (_broker, child_fd) =
        smart_vpn_engine::app_process_broker::Broker::attach(&mut command, &settings.excluded_apps)
            .unwrap();
    command.env("FOXVPN_CORE_UID", "62077");
    struct Core(std::process::Child);
    impl Drop for Core {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let _core = Core(command.spawn().unwrap());
    drop(child_fd);
    let mut ready = false;
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        ready,
        "core did not listen: {}",
        std::fs::read_to_string(&log_path).unwrap()
    );
    std::thread::sleep(Duration::from_millis(100));
    let uid = Command::new("/bin/ps")
        .args(["-o", "uid=", "-p", &_core.0.id().to_string()])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&uid.stdout).trim(), "62077");
    let results = [&main, &helper, &sibling, &outside].map(|client| {
        let mut command = Command::new(client);
        unsafe {
            command.pre_exec(move || {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(20) != 0
                    || libc::setuid(app_uid) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command
            .args([
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "3",
                "--noproxy",
                "*",
                &format!("http://127.0.0.1:{port}/verified"),
            ])
            .output()
            .unwrap()
    });
    stop.store(true, Ordering::SeqCst);
    let count = http.join().unwrap();
    for result in &results[..2] {
        assert!(
            result.status.success(),
            "bundle route failed: {}\n{}",
            String::from_utf8_lossy(&result.stderr),
            std::fs::read_to_string(&log_path).unwrap()
        );
        assert_eq!(result.stdout, b"DIRECT");
    }
    for result in &results[2..] {
        assert!(!result.status.success(), "unselected client bypassed VPN");
    }
    assert_eq!(
        count, 2,
        "only the two selected bundle executables may connect directly"
    );
}
