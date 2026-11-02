//! Small HTTPS checks. One unavailable check site must not tear down a tunnel.
use std::time::Duration;
const URLS: [&str; 2] = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
];
fn check(client: &reqwest::blocking::Client, urls: &[&str]) -> Result<(), String> {
    for url in urls {
        if client
            .get(*url)
            .send()
            .is_ok_and(|r| r.status().as_u16() == 204)
        {
            return Ok(());
        }
    }
    Err("Контрольные HTTPS-запросы не прошли. Проверьте доступ к интернету и VPN-серверу".into())
}
/// No environment proxy, redirects, certificate bypass, direct/VPN fallback or file download.
/// The second URL uses the SAME requested route as the first one.
fn client(port: Option<u16>) -> Result<reqwest::blocking::Client, String> {
    let mut builder = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(4));
    if let Some(port) = port {
        builder = builder.proxy(
            reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))
                .map_err(|_| "Не удалось проверить локальный прокси")?,
        );
    }
    builder
        .build()
        .map_err(|_| "Не удалось подготовить проверку соединения".into())
}
#[derive(Debug, PartialEq, Eq)]
pub struct Inspection {
    pub passed: usize,
    pub total: usize,
}
impl Inspection {
    pub fn connected(&self) -> bool {
        self.passed > 0
    }
    pub fn partial(&self) -> bool {
        self.passed > 0 && self.passed < self.total
    }
}
fn inspect_with(client: &reqwest::blocking::Client, urls: &[&str]) -> Inspection {
    Inspection {
        passed: urls
            .iter()
            .filter(|url| {
                client
                    .get(**url)
                    .send()
                    .is_ok_and(|r| r.status().as_u16() == 204)
            })
            .count(),
        total: urls.len(),
    }
}
/// Explicit user check inspects every small endpoint. Background recovery keeps
/// the cheaper fallback probe and never restarts on one unavailable website.
pub fn inspect(port: Option<u16>) -> Result<Inspection, String> {
    Ok(inspect_with(&client(port)?, &URLS))
}
pub fn probe(port: Option<u16>) -> Result<(), String> {
    check(&client(port)?, &URLS)
}

#[cfg(any(target_os = "macos", test))]
fn route_uses_tunnel(text: &str) -> bool {
    text.lines().any(|line| {
        line.trim()
            .split_once(':')
            .is_some_and(|(key, value)| key == "interface" && value.trim() == "utun99")
    })
}
/// Check the OS route, not just whether HTTPS is reachable through some path.
/// The fixed numeric destination avoids DNS and does not send traffic to it.
#[cfg(target_os = "macos")]
pub fn system_tunnel_route() -> bool {
    use std::{
        io::Read,
        process::{Command, Stdio},
        time::Instant,
    };
    let Ok(mut child) = Command::new("/sbin/route")
        .args(["-n", "get", "8.8.4.4"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut bytes = vec![];
                if let Some(stdout) = child.stdout.take() {
                    let _ = stdout.take(8192).read_to_end(&mut bytes);
                }
                return status.success() && route_uses_tunnel(&String::from_utf8_lossy(&bytes));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
            _ => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}
#[cfg(not(target_os = "macos"))]
pub fn system_tunnel_route() -> bool {
    false
}
/// A failed sample makes readiness unknown immediately. Two consecutive failed
/// rounds are required before a healthy, already-running core is restarted.
#[derive(Default)]
pub struct Health {
    pub ready: bool,
    failures: u8,
}
impl Health {
    pub fn observe(&mut self, passed: bool) {
        self.ready = passed;
        self.failures = if passed {
            0
        } else {
            self.failures.saturating_add(1)
        };
    }
    pub fn needs_restart(&self) -> bool {
        self.failures >= 2
    }
    pub fn interval(&self, normal: Duration) -> Duration {
        if self.failures > 0 {
            normal.min(Duration::from_secs(2))
        } else {
            normal
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };
    fn endpoint(status: &str) -> (String, std::thread::JoinHandle<()>, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/check", listener.local_addr().unwrap());
        let response =
            format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let hits = Arc::new(AtomicUsize::new(0));
        let count = hits.clone();
        let task = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .unwrap();
                        let mut data = [0; 2048];
                        let _ = stream.read(&mut data);
                        count.fetch_add(1, Ordering::SeqCst);
                        let _ = stream.write_all(response.as_bytes());
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        });
        (url, task, hits)
    }
    fn test_client() -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(500))
            .build()
            .unwrap()
    }
    #[test]
    fn unavailable_primary_uses_a_second_site_and_a_portal_does_not_count_as_internet() {
        let (bad, a, _) = endpoint("503 Service Unavailable");
        let (good, b, _) = endpoint("204 No Content");
        assert!(check(&test_client(), &[&bad, &good]).is_ok());
        a.join().unwrap();
        b.join().unwrap();
        let (portal, a, _) = endpoint("302 Found\r\nLocation: http://127.0.0.1:1/login");
        let (page, b, _) = endpoint("200 OK");
        assert!(check(&test_client(), &[&portal, &page]).is_err());
        a.join().unwrap();
        b.join().unwrap();
    }
    #[test]
    fn working_primary_does_not_generate_a_second_request() {
        let (good, a, _) = endpoint("204 No Content");
        let (unused, b, hits) = endpoint("204 No Content");
        assert!(check(&test_client(), &[&good, &unused]).is_ok());
        a.join().unwrap();
        b.join().unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn explicit_inspection_reports_partial_reachability_without_calling_it_a_total_outage() {
        let (good, a, _) = endpoint("204 No Content");
        let (bad, b, _) = endpoint("503 Service Unavailable");
        let result = inspect_with(&test_client(), &[&good, &bad]);
        a.join().unwrap();
        b.join().unwrap();
        assert!(result.connected());
        assert!(result.partial());
        assert_eq!(result.passed, 1);
        assert_eq!(result.total, 2);
    }
    #[test]
    fn direct_or_other_vpn_routes_cannot_confirm_our_system_tunnel() {
        assert!(route_uses_tunnel(
            "route to: 8.8.4.4\n  interface: utun99\n"
        ));
        for value in [
            "interface: en0",
            "interface: utun5",
            "gateway: utun99",
            "interface: utun990",
            "",
        ] {
            assert!(!route_uses_tunnel(value));
        }
    }
    #[test]
    fn transient_failure_recovers_without_a_restart_and_sustained_outage_is_retried_soon() {
        let mut h = Health::default();
        h.observe(true);
        h.observe(false);
        assert!(!h.ready);
        assert!(!h.needs_restart());
        assert_eq!(h.interval(Duration::from_secs(30)), Duration::from_secs(2));
        h.observe(true);
        assert!(h.ready);
        assert!(!h.needs_restart());
        assert_eq!(h.interval(Duration::from_secs(30)), Duration::from_secs(30));
        h.observe(false);
        h.observe(false);
        assert!(h.needs_restart());
        h.observe(true);
        assert!(!h.needs_restart());
    }
}
