use smart_vpn_engine::{
    routing::Mode,
    servers::Server,
    settings::Settings,
    vpn::{free_port, CoreProcess},
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    time::Duration,
};

fn profile() -> (Server, Settings) {
    (Server::parse("vless://11111111-1111-4111-8111-111111111111@127.0.0.1:9?security=none&type=tcp#public-stability-test").unwrap(),
     Settings { mode: Mode::Direct, tun: false, kill_switch: false, ..Default::default() })
}
fn request(core: &CoreProcess) {
    let http = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = http.local_addr().unwrap();
    let thread = std::thread::spawn(move || {
        let (mut stream, _) = http.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buffer = [0u8; 4096];
        let mut request = Vec::new();
        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            let count = stream.read(&mut buffer).unwrap();
            assert!(count > 0);
            request.extend_from_slice(&buffer[..count]);
            assert!(request.len() <= 8192);
        }
        assert!(String::from_utf8_lossy(&request).contains("/stability"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nSTABLE OK",
            )
            .unwrap();
    });
    let result = smart_vpn_engine::latency::client(core.proxy_port)
        .unwrap()
        .get(format!("http://{address}/stability"))
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert_eq!(result, "STABLE OK");
    thread.join().unwrap();
}
#[test]
fn repeated_stop_crash_and_restart_reuses_port_without_touching_other_listener() {
    let Ok(binary) = std::env::var("SMARTVPN_TEST_CORE") else {
        return;
    };
    let (server, settings) = profile();
    let port = free_port().unwrap();
    let occupied = TcpListener::bind(("127.0.0.1", port)).unwrap();
    assert!(CoreProcess::start_on_port(Path::new(&binary), &server, &settings, &[], port).is_err());
    assert!(TcpStream::connect(("127.0.0.1", port)).is_ok());
    drop(occupied);
    for cycle in 0..8 {
        let mut core =
            CoreProcess::start_on_port(Path::new(&binary), &server, &settings, &[], port).unwrap();
        let dir = core.dir.clone();
        request(&core);
        if cycle % 2 == 0 {
            core.child.kill().unwrap();
            core.child.wait().unwrap();
            assert!(!core.alive());
        }
        core.stop_checked().unwrap();
        core.stop_checked().unwrap();
        drop(core);
        assert!(!dir.exists());
        let rebound = TcpListener::bind(("127.0.0.1", port)).unwrap();
        drop(rebound);
    }
}

#[cfg(windows)]
#[test]
#[ignore = "Internal subprocess probe used only by windows_parent_death_reaps_core"]
fn windows_core_lifetime_probe() {
    let binary = std::env::var("SMARTVPN_TEST_CORE").unwrap();
    let (server, settings) = profile();
    let core = CoreProcess::start(Path::new(&binary), &server, &settings, &[]).unwrap();
    let output = std::path::PathBuf::from(std::env::var("FOXVPN_LIFETIME_PROBE").unwrap());
    let staging = output.with_extension("tmp");
    std::fs::write(
        &staging,
        serde_json::to_vec(
            &serde_json::json!({"port":core.proxy_port,"pid":core.child.id(),"dir":core.dir}),
        )
        .unwrap(),
    )
    .unwrap();
    std::fs::rename(staging, output).unwrap();
    // The test parent deliberately kills this process, bypassing Rust Drop.
    std::thread::sleep(Duration::from_secs(60));
    drop(core);
}

#[cfg(windows)]
#[test]
fn windows_parent_death_reaps_core() {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::{
        process::{Command, Stdio},
        time::Instant,
    };
    use windows_sys::Win32::{
        Foundation::WAIT_OBJECT_0,
        System::Threading::{
            OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_SYNCHRONIZE,
        },
    };
    if std::env::var("SMARTVPN_TEST_CORE").is_err() {
        return;
    }
    let output =
        std::env::temp_dir().join(format!("foxvpn-lifetime-{}.json", uuid::Uuid::new_v4()));
    let mut parent = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "windows_core_lifetime_probe"])
        .env("FOXVPN_LIFETIME_PROBE", &output)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while !output.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    if !output.exists() {
        let _ = parent.kill();
        let _ = parent.wait();
        panic!("lifetime probe did not start");
    }
    let data: serde_json::Value = serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            data["pid"].as_u64().unwrap() as u32,
        )
    };
    assert!(!raw.is_null());
    let core = unsafe { OwnedHandle::from_raw_handle(raw) };
    parent.kill().unwrap();
    parent.wait().unwrap();
    assert_eq!(
        unsafe { WaitForSingleObject(core.as_raw_handle(), 5000) },
        WAIT_OBJECT_0,
        "core survived parent termination"
    );
    assert!(TcpStream::connect(("127.0.0.1", data["port"].as_u64().unwrap() as u16)).is_err());
    std::fs::remove_dir_all(data["dir"].as_str().unwrap()).unwrap();
    std::fs::remove_file(output).unwrap();
}
