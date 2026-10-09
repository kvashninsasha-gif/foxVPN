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

/// Complete LAN/WinINet proxy configuration; kept private to local recovery files.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Configuration {
    pub flags: u32,
    pub server: String,
    pub bypass: String,
    pub auto_url: String,
}
impl Configuration {
    pub fn managed(&self, port: u16) -> Self {
        Self {
            flags: 3,
            server: format!("127.0.0.1:{port}"),
            ..self.clone()
        }
    }
}
#[cfg(windows)]
pub fn configuration() -> Result<Configuration, String> {
    use windows_sys::Win32::{Foundation::GlobalFree, Networking::WinInet::*};
    let mut options = [
        INTERNET_PER_CONN_FLAGS_UI,
        INTERNET_PER_CONN_PROXY_SERVER,
        INTERNET_PER_CONN_PROXY_BYPASS,
        INTERNET_PER_CONN_AUTOCONFIG_URL,
    ]
    .map(|dwOption| INTERNET_PER_CONN_OPTIONW {
        dwOption,
        ..Default::default()
    });
    let mut list = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        dwOptionCount: options.len() as u32,
        pOptions: options.as_mut_ptr(),
        ..Default::default()
    };
    let mut size = list.dwSize;
    if unsafe {
        InternetQueryOptionW(
            std::ptr::null(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            (&mut list as *mut INTERNET_PER_CONN_OPTION_LISTW).cast(),
            &mut size,
        )
    } == 0
    {
        return Err("Не удалось прочитать системный прокси Windows".into());
    }
    // WinINet allocates strings with GlobalAlloc; always release every returned buffer.
    fn string(pointer: *mut u16) -> Result<String, String> {
        if pointer.is_null() {
            return Ok(String::new());
        }
        let result = unsafe {
            let mut len = 0;
            while len < 16384 && *pointer.add(len) != 0 {
                len += 1;
            }
            if len == 16384 {
                Err("Слишком длинные параметры прокси Windows".into())
            } else {
                String::from_utf16(std::slice::from_raw_parts(pointer, len))
                    .map_err(|_| "Некорректные параметры прокси Windows".into())
            }
        };
        unsafe {
            GlobalFree(pointer.cast());
        }
        result
    }
    let server = string(unsafe { options[1].Value.pszValue });
    let bypass = string(unsafe { options[2].Value.pszValue });
    let auto_url = string(unsafe { options[3].Value.pszValue });
    Ok(Configuration {
        flags: unsafe { options[0].Value.dwValue },
        server: server?,
        bypass: bypass?,
        auto_url: auto_url?,
    })
}
#[cfg(windows)]
pub fn set_configuration(config: &Configuration) -> Result<(), String> {
    use windows_sys::Win32::Networking::WinInet::*;
    if [&config.server, &config.bypass, &config.auto_url]
        .iter()
        .any(|v| v.contains('\0') || v.len() > 16384)
        || config.flags & !15 != 0
    {
        return Err("Некорректные параметры прокси Windows".into());
    }
    let mut server: Vec<u16> = config.server.encode_utf16().chain(Some(0)).collect();
    let mut bypass: Vec<u16> = config.bypass.encode_utf16().chain(Some(0)).collect();
    let mut auto_url: Vec<u16> = config.auto_url.encode_utf16().chain(Some(0)).collect();
    let mut options = [
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_FLAGS,
            Value: INTERNET_PER_CONN_OPTIONW_0 {
                dwValue: config.flags,
            },
        },
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_PROXY_SERVER,
            Value: INTERNET_PER_CONN_OPTIONW_0 {
                pszValue: server.as_mut_ptr(),
            },
        },
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_PROXY_BYPASS,
            Value: INTERNET_PER_CONN_OPTIONW_0 {
                pszValue: bypass.as_mut_ptr(),
            },
        },
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_AUTOCONFIG_URL,
            Value: INTERNET_PER_CONN_OPTIONW_0 {
                pszValue: auto_url.as_mut_ptr(),
            },
        },
    ];
    let list = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        dwOptionCount: options.len() as u32,
        pOptions: options.as_mut_ptr(),
        ..Default::default()
    };
    if unsafe {
        InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            (&list as *const INTERNET_PER_CONN_OPTION_LISTW).cast(),
            list.dwSize,
        )
    } == 0
    {
        return Err("Не удалось изменить системный прокси Windows".into());
    }
    let changed = unsafe {
        InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null(),
            0,
        )
    };
    let refreshed = unsafe {
        InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null(),
            0,
        )
    };
    if changed == 0 || refreshed == 0 {
        return Err("Windows не подтвердила обновление параметров прокси".into());
    }
    Ok(())
}
