//! Read-only socket ownership lookup for the privilege-dropped macOS core.
//! An anonymous inherited socket grants no filesystem or command authority.
//! Only paths inside the explicitly excluded bundles are returned.
use crate::app_routes::Application;
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown},
    os::{
        fd::AsRawFd,
        unix::{net::UnixStream, process::CommandExt},
    },
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

pub struct Broker {
    control: UnixStream,
    closing: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Broker {
    pub fn attach(
        command: &mut Command,
        apps: &[Application],
    ) -> Result<(Self, UnixStream), String> {
        crate::app_routes::validate(apps)?;
        if unsafe { libc::geteuid() } != 0 || apps.is_empty() {
            return Err("Нет прав для определения приложений VPN".into());
        }
        let (mut server, child) =
            UnixStream::pair().map_err(|_| "Не удалось подготовить проверку приложений")?;
        server
            .set_read_timeout(Some(Duration::from_millis(500)))
            .map_err(|_| "Не удалось подготовить проверку приложений")?;
        server
            .set_write_timeout(Some(Duration::from_millis(500)))
            .map_err(|_| "Не удалось подготовить проверку приложений")?;
        let control = server
            .try_clone()
            .map_err(|_| "Не удалось подготовить проверку приложений")?;
        let fd = child.as_raw_fd();
        command.env("FOXVPN_PROCESS_FD", fd.to_string());
        // Only the child copy is inherited. The root parent closes its copy
        // immediately after spawn; neither endpoint has a public pathname.
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let closing = Arc::new(AtomicBool::new(false));
        let stopped = closing.clone();
        let apps = apps.to_vec();
        let worker = std::thread::Builder::new()
            .name("foxvpn-app-query".into())
            .spawn(move || {
                while !stopped.load(Ordering::SeqCst) {
                    let mut request = [0u8; 44];
                    match server.read(&mut request[..1]) {
                        Ok(0) => break,
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            continue
                        }
                        Err(_) => break,
                        Ok(_) => {}
                    }
                    if server.read_exact(&mut request[1..]).is_err() {
                        break;
                    }
                    let Some(query) = Query::parse(&request) else {
                        break;
                    };
                    let result = lookup(&query, &apps);
                    let mut header = [0u8; 7];
                    if let Some((uid, path)) = &result {
                        header[0] = 1;
                        header[1..5].copy_from_slice(&uid.to_be_bytes());
                        header[5..7].copy_from_slice(&(path.len() as u16).to_be_bytes());
                    }
                    if server.write_all(&header).is_err() {
                        break;
                    }
                    if let Some((_, path)) = result {
                        if server.write_all(path.as_bytes()).is_err() {
                            break;
                        }
                    }
                }
            })
            .map_err(|_| "Не удалось запустить проверку приложений")?;
        Ok((
            Self {
                control,
                closing,
                worker: Some(worker),
            },
            child,
        ))
    }
}
impl Drop for Broker {
    fn drop(&mut self) {
        self.closing.store(true, Ordering::SeqCst);
        let _ = self.control.shutdown(Shutdown::Both);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
struct Query {
    network: u8,
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    destination_port: u16,
}
impl Query {
    fn parse(bytes: &[u8; 44]) -> Option<Self> {
        if &bytes[..4] != b"FXP1" || ![1, 2].contains(&bytes[4]) || bytes[42..] != [0, 0] {
            return None;
        }
        let address = |raw: &[u8]| match bytes[5] {
            4 if raw[..12] == [0; 12] => Some(IpAddr::V4(Ipv4Addr::new(
                raw[12], raw[13], raw[14], raw[15],
            ))),
            6 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(raw).ok()?))),
            _ => None,
        };
        let source_port = u16::from_be_bytes(bytes[38..40].try_into().ok()?);
        if source_port == 0 {
            return None;
        }
        Some(Self {
            network: bytes[4],
            source: address(&bytes[6..22])?,
            destination: address(&bytes[22..38])?,
            source_port,
            destination_port: u16::from_be_bytes(bytes[40..42].try_into().ok()?),
        })
    }
}
fn lookup(query: &Query, apps: &[Application]) -> Option<(u32, String)> {
    let data = snapshot(query.network)?;
    let stride = if query.network == 1 { 616 } else { 408 };
    let mut fallback = None;
    for entry in data.get(24..)?.chunks_exact(stride) {
        let local_port = u16::from_be_bytes(entry[18..20].try_into().ok()?);
        if local_port != query.source_port {
            continue;
        }
        let address = |offset: usize| -> Option<IpAddr> {
            if entry[44] & 1 != 0 {
                Some(IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(&entry[offset + 12..offset + 16]).ok()?,
                )))
            } else if entry[44] & 2 != 0 {
                Some(IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&entry[offset..offset + 16]).ok()?,
                )))
            } else {
                None
            }
        };
        let local = address(64)?;
        let remote = address(48)?;
        let remote_port = u16::from_be_bytes(entry[16..18].try_into().ok()?);
        let uid = u32::from_ne_bytes(entry[168..172].try_into().ok()?);
        let pid = u32::from_ne_bytes(entry[172..176].try_into().ok()?);
        if local == query.source
            && remote == query.destination
            && remote_port == query.destination_port
        {
            return allowed_path(pid, uid, apps);
        }
        // An unconnected UDP socket is legitimately bound to a local/wildcard
        // address. Never reuse a connected socket for a different destination.
        if query.network == 2
            && remote_port == 0
            && remote.is_unspecified()
            && local.is_ipv4() == query.source.is_ipv4()
            && (local == query.source || local.is_unspecified())
        {
            if fallback.is_some() {
                return None;
            } // Ambiguous SO_REUSEPORT: fail closed.
            fallback = Some((pid, uid));
        }
    }
    fallback.and_then(|(pid, uid)| allowed_path(pid, uid, apps))
}
fn allowed_path(pid: u32, uid: u32, apps: &[Application]) -> Option<(u32, String)> {
    if pid < 2 || pid > i32::MAX as u32 || uid < 501 || uid == crate::network_helper::CORE_UID {
        return None;
    }
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of_val(&info);
    if unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size as i32,
        )
    } != size as i32
        || info.pbi_uid != uid
        || info.pbi_ruid != uid
    {
        return None;
    }
    unsafe extern "C" {
        fn proc_pidpath(pid: i32, buffer: *mut std::ffi::c_void, size: u32) -> i32;
    }
    let mut bytes = [0u8; 4096];
    let size = unsafe { proc_pidpath(pid as i32, bytes.as_mut_ptr().cast(), bytes.len() as u32) };
    if size <= 0 {
        return None;
    }
    let end = bytes.iter().position(|v| *v == 0)?;
    let path = std::str::from_utf8(&bytes[..end]).ok()?;
    apps.iter()
        .any(|app| {
            path.strip_prefix(&app.path)
                .is_some_and(|tail| tail.starts_with('/'))
        })
        .then(|| (uid, path.to_owned()))
}
fn snapshot(network: u8) -> Option<Vec<u8>> {
    let name = if network == 1 {
        c"net.inet.tcp.pcblist_n"
    } else {
        c"net.inet.udp.pcblist_n"
    };
    let mut size = 0;
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || size > 8 * 1024 * 1024
    {
        return None;
    }
    let mut data = vec![0u8; size];
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            data.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || size > data.len()
    {
        return None;
    }
    data.truncate(size);
    Some(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unknown_frames_and_zero_ports_without_any_system_lookup() {
        let mut frame = [0u8; 44];
        frame[..4].copy_from_slice(b"FXP1");
        frame[4] = 1;
        frame[5] = 4;
        frame[38..40].copy_from_slice(&2080u16.to_be_bytes());
        assert!(Query::parse(&frame).is_some());
        frame[42] = 1;
        assert!(Query::parse(&frame).is_none());
        frame[42] = 0;
        frame[4] = 3;
        assert!(Query::parse(&frame).is_none());
        frame[4] = 1;
        frame[38..40].fill(0);
        assert!(Query::parse(&frame).is_none());
    }
}
