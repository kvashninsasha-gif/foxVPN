//! Read-only Windows browser-proxy diagnostics. Never changes proxy settings.
use serde::Serialize;

#[derive(Serialize)]
pub struct Status {
    pub supported: bool,
    pub enabled: bool,
    pub matches: bool,
    pub script_configured: bool,
}

pub fn matches_server(value: &str, port: u16) -> bool {
    let expected = format!("127.0.0.1:{port}");
    if !value.contains('=') {
        return value.trim().eq_ignore_ascii_case(&expected);
    }
    let entries: Vec<_> = value
        .split(';')
        .filter_map(|entry| entry.trim().split_once('='))
        .collect();
    ["http", "https"].iter().all(|scheme| {
        entries.iter().any(|(key, address)| {
            key.trim().eq_ignore_ascii_case(scheme)
                && address.trim().eq_ignore_ascii_case(&expected)
        })
    })
}

#[cfg(windows)]
pub fn read(port: u16) -> Result<Status, String> {
    read_from(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        port,
    )
}

#[cfg(windows)]
fn read_from(subkey: &str, port: u16) -> Result<Status, String> {
    use windows_sys::Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS},
        System::Registry::*,
    };
    fn value(subkey: &str, name: &str, flags: u32) -> Result<Option<Vec<u8>>, String> {
        let key: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let mut buffer = vec![0u8; 16_384];
        let mut size = buffer.len() as u32;
        let result = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                name.as_ptr(),
                flags,
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut size,
            )
        };
        match result {
            ERROR_SUCCESS => {
                buffer.truncate(size as usize);
                Ok(Some(buffer))
            }
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(None),
            _ => Err("Не удалось прочитать параметры прокси Windows".into()),
        }
    }
    fn string(bytes: Option<Vec<u8>>) -> Result<String, String> {
        let Some(bytes) = bytes else {
            return Ok(String::new());
        };
        if bytes.len() % 2 != 0 {
            return Err("Некорректные параметры прокси Windows".into());
        }
        let wide: Vec<_> = bytes
            .chunks_exact(2)
            .map(|v| u16::from_le_bytes([v[0], v[1]]))
            .collect();
        String::from_utf16(&wide)
            .map(|s| s.trim_end_matches('\0').to_string())
            .map_err(|_| "Некорректные параметры прокси Windows".into())
    }
    let enabled = value(subkey, "ProxyEnable", RRF_RT_REG_DWORD)?
        .is_some_and(|v| v.len() == 4 && u32::from_le_bytes([v[0], v[1], v[2], v[3]]) != 0);
    let server = string(value(subkey, "ProxyServer", RRF_RT_REG_SZ)?)?;
    let script_configured = !string(value(subkey, "AutoConfigURL", RRF_RT_REG_SZ)?)?.is_empty();
    Ok(Status {
        supported: true,
        enabled,
        matches: enabled && matches_server(&server, port),
        script_configured,
    })
}

#[cfg(not(windows))]
pub fn read(_: u16) -> Result<Status, String> {
    Ok(Status {
        supported: false,
        enabled: false,
        matches: false,
        script_configured: false,
    })
}

#[cfg(windows)]
pub fn open_settings() -> Result<(), String> {
    use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL};
    let uri: Vec<u16> = "ms-settings:network-proxy\0".encode_utf16().collect();
    let verb: Vec<u16> = "open\0".encode_utf16().collect();
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            uri.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if result as isize <= 32 {
        return Err("Не удалось открыть параметры прокси Windows".into());
    }
    Ok(())
}
#[cfg(not(windows))]
pub fn open_settings() -> Result<(), String> {
    Err("Эта настройка доступна только в Windows".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    #[test]
    fn reads_windows_registry_without_changing_user_proxy() {
        use windows_sys::Win32::{Foundation::ERROR_SUCCESS, System::Registry::*};
        let path = format!("Software\\foxVPN-test-{}", uuid::Uuid::new_v4());
        let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        let mut key = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    wide.as_ptr(),
                    0,
                    std::ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_SET_VALUE,
                    std::ptr::null(),
                    &mut key,
                    std::ptr::null_mut(),
                )
            },
            ERROR_SUCCESS
        );
        struct Fixture(Vec<u16>, HKEY);
        impl Drop for Fixture {
            fn drop(&mut self) {
                unsafe {
                    RegCloseKey(self.1);
                    RegDeleteTreeW(HKEY_CURRENT_USER, self.0.as_ptr());
                }
            }
        }
        let fixture = Fixture(wide, key);
        let set = |name: &str, kind, bytes: &[u8]| {
            let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            assert_eq!(
                unsafe {
                    RegSetValueExW(
                        fixture.1,
                        name.as_ptr(),
                        0,
                        kind,
                        bytes.as_ptr(),
                        bytes.len() as u32,
                    )
                },
                ERROR_SUCCESS
            );
        };
        assert!(!read_from(&path, 2080).unwrap().enabled);
        set("ProxyEnable", REG_DWORD, &1u32.to_le_bytes());
        let server: Vec<u8> = "http=127.0.0.1:2080;https=127.0.0.1:2080\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        set("ProxyServer", REG_SZ, &server);
        assert!(read_from(&path, 2080).unwrap().matches);
        assert!(!read_from(&path, 2081).unwrap().matches);
        let script: Vec<u8> = "https://example.invalid/proxy.pac\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        set("AutoConfigURL", REG_SZ, &script);
        let status = read_from(&path, 2080).unwrap();
        assert!(status.matches && status.script_configured);
        set("ProxyEnable", REG_DWORD, &0u32.to_le_bytes());
        assert!(!read_from(&path, 2080).unwrap().matches);
    }
    #[test]
    fn checks_both_browser_protocols_and_exact_local_port() {
        assert!(matches_server("127.0.0.1:2080", 2080));
        assert!(matches_server(
            "http=127.0.0.1:2080;https=127.0.0.1:2080",
            2080
        ));
        assert!(!matches_server(
            "http=127.0.0.1:2080;https=another.example:2080",
            2080
        ));
        assert!(!matches_server("socks=127.0.0.1:2080", 2080));
        assert!(!matches_server("127.0.0.1:2081", 2080));
    }
}
