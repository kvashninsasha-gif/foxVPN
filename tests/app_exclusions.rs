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
fn explicit_domain_rules_precede_mac_app_exclusions_without_bypassing_dns() {
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
            assert_eq!(cfg["route"]["rules"][2]["outbound"], "vpn");
            assert_eq!(cfg["route"]["rules"][2]["domain"][0], "example.com");
            assert_eq!(cfg["route"]["rules"][3]["outbound"], "direct");
            assert_eq!(
                cfg["route"]["rules"][3]["process_path_regex"][0],
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
    let dir = tempfile::Builder::new()
        .prefix("foxvpn-public-apps-")
        .tempdir_in("/private/tmp")
        .unwrap();
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
        for parent in path.parent().unwrap().ancestors() {
            if !parent.starts_with(dir.path()) {
                break;
            }
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
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
    let tun = std::env::var("FOXVPN_TEST_APP_TUN").as_deref() == Ok("1");
    let target = if tun { "198.18.0.2" } else { "127.0.0.1" };
    let target_port = if tun { http_port } else { port };
    if tun {
        // Only the documentation benchmark subnet is routed on this disposable
        // runner. DNS and the default route are unchanged; no laptop is touched.
        cfg["inbounds"][1]["address"] = serde_json::json!(["172.29.0.1/30"]);
        cfg["inbounds"][1]["route_address"] = serde_json::json!(["198.18.0.0/15"]);
        cfg["inbounds"][1]["dns_mode"] = serde_json::json!("disabled");
        cfg["route"]["rules"][2]["override_address"] = serde_json::json!("127.0.0.1");
        cfg["route"]["rules"][2]["override_port"] = serde_json::json!(http_port);
    } else {
        cfg["inbounds"]
            .as_array_mut()
            .unwrap()
            .retain(|i| i["type"] != "tun");
        cfg["inbounds"][0] = serde_json::json!({"type":"direct","tag":"fixture-in","listen":"127.0.0.1","listen_port":port,"override_address":"127.0.0.1","override_port":http_port});
    }
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
    let mut dropped = false;
    for _ in 0..80 {
        let uid = Command::new("/bin/ps")
            .args(["-o", "uid=", "-p", &_core.0.id().to_string()])
            .output()
            .unwrap();
        if String::from_utf8_lossy(&uid.stdout).trim() == "62077" {
            dropped = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        dropped,
        "core did not drop privileges: {}",
        std::fs::read_to_string(&log_path).unwrap()
    );
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
                &format!("http://{target}:{target_port}/verified"),
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
    if tun {
        let echo = std::net::UdpSocket::bind(("127.0.0.1", http_port)).unwrap();
        echo.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let finished = Arc::new(AtomicBool::new(false));
        let end = finished.clone();
        let worker = std::thread::spawn(move || {
            let mut count = 0;
            let mut buf = [0; 64];
            while !end.load(Ordering::SeqCst) {
                if let Ok((size, peer)) = echo.recv_from(&mut buf) {
                    count += 1;
                    echo.send_to(&buf[..size], peer).unwrap();
                }
            }
            count
        });
        let udp_main = bundle.join("Contents/MacOS/UdpFixture");
        let udp_outside = dir.path().join("udp-other-client");
        let results = [&udp_main, &udp_outside].map(|path| {
            std::fs::copy(std::env::current_exe().unwrap(), path).unwrap();
            assert!(Command::new("/usr/bin/codesign")
                .args(["--force", "--sign", "-"])
                .arg(path)
                .output()
                .unwrap()
                .status
                .success());
            let mut command = Command::new(path);
            command
                .args(["--exact", "public_app_udp_client", "--ignored"])
                .env("FOXVPN_TEST_UDP_TARGET", format!("{target}:{target_port}"));
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
            command.output().unwrap()
        });
        finished.store(true, Ordering::SeqCst);
        let received = worker.join().unwrap();
        assert!(
            results[0].status.success(),
            "selected UDP app: {}\n{}",
            String::from_utf8_lossy(&results[0].stdout),
            std::fs::read_to_string(&log_path).unwrap()
        );
        assert!(
            !results[1].status.success(),
            "unselected UDP client bypassed VPN"
        );
        assert_eq!(received, 1);
    }
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "public subprocess fixture for the disposable TUN test"]
fn public_app_udp_client() {
    let target = std::env::var("FOXVPN_TEST_UDP_TARGET").expect("public UDP target");
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect(target).unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    socket.send(b"APP-DIRECT").unwrap();
    let mut buf = [0; 64];
    let size = socket.recv(&mut buf).unwrap();
    assert_eq!(&buf[..size], b"APP-DIRECT");
}

#[test]
fn windows_exe_paths_are_portable_exact_and_validated() {
    use smart_vpn_engine::app_routes::{validate_windows, windows_pattern};
    let selected = app(r"C:\Program Files\Browser\browser.exe");
    validate_windows(std::slice::from_ref(&selected)).unwrap();
    assert_eq!(
        windows_pattern(&selected),
        r"(?i)^C:\\Program Files\\Browser\\browser\.exe$"
    );
    let mut profile = Profile::default();
    profile
        .settings
        .windows_excluded_apps
        .push(selected.clone());
    let copied: Profile = serde_json::from_slice(&serde_json::to_vec(&profile).unwrap()).unwrap();
    assert_eq!(
        copied.settings.windows_excluded_apps,
        vec![selected.clone()]
    );
    assert!(Settings::default().windows_excluded_apps.is_empty());
    let mut duplicate = selected.clone();
    duplicate.path = duplicate.path.to_lowercase();
    assert!(validate_windows(&[selected, duplicate]).is_err());
    for path in [
        r"browser.exe",
        r"C:browser.exe",
        r"\\server\app.exe",
        r"C:\Apps\..\app.exe",
        r"C:\Apps\app.exe:stream",
        r"C:\Apps\*.exe",
        r"C:\Apps\app.exe\",
        r"C:\Apps\app.app",
        r"C:\Apps.\app.exe",
    ] {
        assert!(validate_windows(&[app(path)]).is_err(), "{path}");
    }
}
