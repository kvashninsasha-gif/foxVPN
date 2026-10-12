//! Native SCM and local named-pipe transport. Every request reads one bounded
//! frame, authenticates both token and held process handle, then dispatches.
use super::*;
use sha2::{Digest, Sha256};
use std::{
    ffi::c_void,
    fs::File,
    io::Read,
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{Pipes::*, Services::*, Threading::*, IO::*},
};
static STOP: AtomicBool = AtomicBool::new(false);
fn wide(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}
fn fail() -> String {
    "Windows service authentication or transport failed".into()
}
fn handle(raw: HANDLE) -> Result<OwnedHandle, String> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        Err(fail())
    } else {
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    }
}
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn sid_text(sid: PSID) -> Result<String, String> {
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(fail());
    }
    let _memory = Local(text.cast());
    let mut len = 0;
    while unsafe { *text.add(len) } != 0 {
        len += 1;
        if len > 256 {
            return Err(fail());
        }
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(text, len) }).map_err(|_| fail())
}
fn token_sid(token: HANDLE) -> Result<String, String> {
    let mut len = 0;
    unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
    }
    if len == 0 || len > 16384 {
        return Err(fail());
    }
    // usize gives TOKEN_USER its required alignment.
    let mut bytes = vec![0usize; (len as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe { GetTokenInformation(token, TokenUser, bytes.as_mut_ptr().cast(), len, &mut len) }
        == 0
    {
        return Err(fail());
    }
    sid_text(unsafe { (*(bytes.as_ptr().cast::<TOKEN_USER>())).User.Sid })
}
fn process_sid(process: HANDLE) -> Result<String, String> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(fail());
    }
    token_sid(handle(token)?.as_raw_handle())
}
/// Deny reparse points and any ACL permitting unprivileged modification. This
/// is checked on both protected directories and every opened executable/file.
fn protected(path: &Path) -> Result<(), String> {
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|_| fail())?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(fail());
        }
    }
    let meta = std::fs::symlink_metadata(path).map_err(|_| fail())?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(fail());
    }
    let mut owner = std::ptr::null_mut();
    let mut acl = std::ptr::null_mut();
    let mut sd = std::ptr::null_mut();
    if unsafe {
        GetNamedSecurityInfoW(
            wide(path).as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut acl,
            std::ptr::null_mut(),
            &mut sd,
        )
    } != 0
    {
        return Err(fail());
    }
    let _memory = Local(sd);
    if !["S-1-5-18", "S-1-5-32-544"].contains(&sid_text(owner)?.as_str()) || acl.is_null() {
        return Err(fail());
    }
    let mut info = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            acl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of_val(&info) as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(fail());
    }
    for index in 0..info.AceCount {
        let mut raw = std::ptr::null_mut();
        if unsafe { GetAce(acl, index, &mut raw) } == 0 {
            return Err(fail());
        }
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        if header.AceType == 1 {
            continue;
        } // ACCESS_DENIED_ACE_TYPE
        if header.AceType != 0 {
            return Err(fail());
        } // refuse unfamiliar/object/callback grants
        let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        let writer = ace.Mask
            & (0x10000000
                | 0x40000000
                | DELETE
                | WRITE_DAC
                | WRITE_OWNER
                | FILE_WRITE_DATA
                | FILE_APPEND_DATA
                | FILE_WRITE_EA
                | FILE_WRITE_ATTRIBUTES
                | FILE_DELETE_CHILD)
            != 0;
        let sid = sid_text((&ace.SidStart as *const u32).cast_mut().cast())?;
        if writer && !["S-1-5-18", "S-1-5-32-544"].contains(&sid.as_str()) {
            return Err(fail());
        }
    }
    Ok(())
}
fn trusted_file(path: &Path) -> Result<File, String> {
    protected(path)?;
    // No write/delete sharing: preserve bytes and pathname across verification.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| fail())?;
    if file.metadata().map_err(|_| fail())?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(fail());
    }
    Ok(file)
}
fn hash(file: &mut File) -> Result<String, String> {
    let size = file.metadata().map_err(|_| fail())?.len();
    if size == 0 || size > 200_000_000 {
        return Err(fail());
    }
    let mut digest = Sha256::new();
    let mut bytes = [0u8; 65536];
    loop {
        let len = file.read(&mut bytes).map_err(|_| fail())?;
        if len == 0 {
            break;
        }
        digest.update(&bytes[..len]);
    }
    Ok(format!("{:x}", digest.finalize()))
}
fn binding() -> Result<(Binding, File), String> {
    protected(Path::new(SLOT))?;
    protected(Path::new(CLIENT).parent().ok_or_else(fail)?)?;
    let mut bytes = Vec::new();
    trusted_file(&Path::new(SLOT).join("binding.json"))?
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| fail())?;
    if bytes.len() > 4096 {
        return Err(fail());
    }
    let binding: Binding = serde_json::from_slice(&bytes).map_err(|_| fail())?;
    binding.validate()?;
    let mut service = trusted_file(&Path::new(SLOT).join("foxvpn-windows-service.exe"))?;
    if hash(&mut service)? != binding.service_sha256
        || std::env::current_exe().map_err(|_| fail())?
            != Path::new(SLOT).join("foxvpn-windows-service.exe")
    {
        return Err(fail());
    }
    Ok((binding, service)) // keep executable lock throughout service lifetime
}
fn authenticate(pipe: HANDLE, binding: &Binding) -> Result<OwnedHandle, String> {
    let mut pid = 0;
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } == 0 || pid == 0 {
        return Err(fail());
    }
    let process =
        handle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) })?;
    if process_sid(process.as_raw_handle())? != binding.owner_sid {
        return Err(fail());
    }
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(fail());
    }
    let mut token = std::ptr::null_mut();
    let result = if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0
    {
        Err(fail())
    } else {
        handle(token).and_then(|token| token_sid(token.as_raw_handle()))
    };
    if unsafe { RevertToSelf() } == 0 {
        // Continuing LocalSystem work while impersonating would cross the boundary.
        std::process::abort();
    }
    if result? != binding.owner_sid {
        return Err(fail());
    }
    let mut image = [0u16; 32768];
    let mut len = image.len() as u32;
    if unsafe {
        QueryFullProcessImageNameW(process.as_raw_handle(), 0, image.as_mut_ptr(), &mut len)
    } == 0
    {
        return Err(fail());
    }
    let path = String::from_utf16(&image[..len as usize]).map_err(|_| fail())?;
    if !path.eq_ignore_ascii_case(CLIENT)
        || hash(&mut trusted_file(Path::new(CLIENT))?)? != binding.client_sha256
        || unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } != WAIT_TIMEOUT
    {
        return Err(fail());
    }
    Ok(process) // retained to prevent PID reuse during dispatch
}
fn pipe(binding: &Binding) -> Result<OwnedHandle, String> {
    // Owner gets only file read/write data. Do not grant create-pipe-instance.
    let acl = wide(format!(
        "D:P(A;;GA;;;SY)(A;;0x00100003;;;{})",
        binding.owner_sid
    ));
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            acl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(fail());
    }
    let _memory = Local(descriptor);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    handle(unsafe {
        CreateNamedPipeW(
            wide(PIPE).as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            (MAX_FRAME + 4) as u32,
            (MAX_FRAME + 4) as u32,
            1000,
            &attributes,
        )
    })
}
fn transfer(raw: HANDLE, bytes: &mut [u8], write: bool, deadline: Instant) -> Result<(), String> {
    let mut offset = 0;
    while offset < bytes.len() {
        if STOP.load(Ordering::SeqCst) || Instant::now() >= deadline {
            return Err(fail());
        }
        let mut count = 0;
        let ok = unsafe {
            if write {
                WriteFile(
                    raw,
                    bytes[offset..].as_ptr(),
                    (bytes.len() - offset) as u32,
                    &mut count,
                    std::ptr::null_mut(),
                )
            } else {
                ReadFile(
                    raw,
                    bytes[offset..].as_mut_ptr(),
                    (bytes.len() - offset) as u32,
                    &mut count,
                    std::ptr::null_mut(),
                )
            }
        };
        if ok == 0 && ![ERROR_NO_DATA, ERROR_PIPE_LISTENING].contains(&unsafe { GetLastError() }) {
            return Err(fail());
        }
        if count == 0 {
            std::thread::sleep(Duration::from_millis(10));
        } else {
            offset += count as usize;
        }
    }
    Ok(())
}
fn receive(raw: HANDLE, deadline: Instant) -> Result<Vec<u8>, String> {
    let mut prefix = [0u8; 4];
    transfer(raw, &mut prefix, false, deadline)?;
    let len = u32::from_le_bytes(prefix) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(fail());
    }
    let mut bytes = vec![0u8; len];
    transfer(raw, &mut bytes, false, deadline)?;
    Ok(bytes)
}
fn send(raw: HANDLE, bytes: &[u8], deadline: Instant) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(fail());
    }
    let mut frame = (bytes.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(bytes);
    transfer(raw, &mut frame, true, deadline)
}
fn serve(status_handle: SERVICE_STATUS_HANDLE) -> Result<(), String> {
    let (binding, _executable_lock) = binding()?;
    let pipe = pipe(&binding)?;
    let running = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: SERVICE_RUNNING,
        dwControlsAccepted: SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    if unsafe { SetServiceStatus(status_handle, &running) } == 0 {
        return Err(fail());
    }
    while !STOP.load(Ordering::SeqCst) {
        let connected = unsafe { ConnectNamedPipe(pipe.as_raw_handle(), std::ptr::null_mut()) }
            != 0
            || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
        if !connected {
            std::thread::sleep(Duration::from_millis(25));
            continue;
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        let answer = receive(pipe.as_raw_handle(), deadline).and_then(|bytes| {
            let _process = authenticate(pipe.as_raw_handle(), &binding)?;
            let request = decode(&bytes)?;
            serde_json::to_vec(&dispatch(request)).map_err(|_| fail())
        });
        if let Ok(answer) = answer {
            if send(pipe.as_raw_handle(), &answer, deadline).is_ok() {
                // DisconnectNamedPipe discards unread bytes. Wait for the client
                // to acknowledge its complete response, within the same deadline.
                let mut acknowledgement = [0u8; 1];
                let _ = transfer(pipe.as_raw_handle(), &mut acknowledgement, false, deadline);
            }
        }
        unsafe {
            DisconnectNamedPipe(pipe.as_raw_handle());
        }
    }
    Ok(())
}
unsafe extern "system" fn control(code: u32, _: u32, _: *mut c_void, _: *mut c_void) -> u32 {
    if code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN {
        STOP.store(true, Ordering::SeqCst);
    }
    NO_ERROR
}
unsafe extern "system" fn service_main(_: u32, _: *mut *mut u16) {
    let status_handle = unsafe {
        RegisterServiceCtrlHandlerExW(wide(SERVICE_NAME).as_ptr(), Some(control), std::ptr::null())
    };
    if status_handle.is_null() {
        return;
    }
    let mut status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: SERVICE_START_PENDING,
        dwControlsAccepted: 0,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 1,
        dwWaitHint: 10000,
    };
    unsafe {
        SetServiceStatus(status_handle, &status);
    }
    let result = serve(status_handle);
    status.dwCurrentState = SERVICE_STOPPED;
    status.dwControlsAccepted = 0;
    if result.is_err() {
        status.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        status.dwServiceSpecificExitCode = 1;
    }
    unsafe {
        SetServiceStatus(status_handle, &status);
    }
}
pub fn run_service() -> Result<(), String> {
    let mut name = wide(SERVICE_NAME);
    let entries = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    if unsafe { StartServiceCtrlDispatcherW(entries.as_ptr()) } == 0 {
        return Err(fail());
    }
    Ok(())
}
/// GUI/test entry. A malicious pipe server is rejected before writing a profile:
/// LocalSystem token, fixed path, protected ACL, and pinned binary must all match.
pub fn request(request: &Request) -> Result<Status, String> {
    let (binding, _service_lock) = {
        let mut bytes = Vec::new();
        trusted_file(&Path::new(SLOT).join("binding.json"))?
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| fail())?;
        if bytes.len() > 4096 {
            return Err(fail());
        }
        let binding: Binding = serde_json::from_slice(&bytes).map_err(|_| fail())?;
        binding.validate()?;
        let mut lock = trusted_file(&Path::new(SLOT).join("foxvpn-windows-service.exe"))?;
        if hash(&mut lock)? != binding.service_sha256 {
            return Err(fail());
        }
        (binding, lock)
    };
    let pipe = handle(unsafe {
        CreateFileW(
            wide(PIPE).as_ptr(),
            FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | FILE_FLAG_OVERLAPPED,
            std::ptr::null_mut(),
        )
    })?;
    let mut pid = 0;
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } == 0 {
        return Err(fail());
    }
    let process =
        handle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) })?;
    if process_sid(process.as_raw_handle())? != "S-1-5-18" {
        return Err(fail());
    }
    let mut image = [0u16; 32768];
    let mut len = image.len() as u32;
    if unsafe {
        QueryFullProcessImageNameW(process.as_raw_handle(), 0, image.as_mut_ptr(), &mut len)
    } == 0
    {
        return Err(fail());
    }
    if !String::from_utf16(&image[..len as usize])
        .map_err(|_| fail())?
        .eq_ignore_ascii_case(&format!("{SLOT}\\foxvpn-windows-service.exe"))
    {
        return Err(fail());
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let bytes = serde_json::to_vec(request).map_err(|_| fail())?;
    if bytes.len() > MAX_FRAME {
        return Err(fail());
    }
    let mut frame = (bytes.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&bytes);
    client_transfer(pipe.as_raw_handle(), &mut frame, true, deadline)?;
    let mut prefix = [0u8; 4];
    client_transfer(pipe.as_raw_handle(), &mut prefix, false, deadline)?;
    let len = u32::from_le_bytes(prefix) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(fail());
    }
    let mut response = vec![0u8; len];
    client_transfer(pipe.as_raw_handle(), &mut response, false, deadline)?;
    let status: Status = serde_json::from_slice(&response).map_err(|_| fail())?;
    if status.protocol != binding.protocol {
        return Err(fail());
    }
    client_transfer(pipe.as_raw_handle(), &mut [1u8], true, deadline)?;
    Ok(status)
}

fn client_transfer(
    raw: HANDLE,
    bytes: &mut [u8],
    write: bool,
    deadline: Instant,
) -> Result<(), String> {
    let event = handle(unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) })?;
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .as_millis();
        if remaining == 0 {
            return Err(fail());
        }
        unsafe {
            ResetEvent(event.as_raw_handle());
        }
        let mut operation = OVERLAPPED {
            hEvent: event.as_raw_handle(),
            ..Default::default()
        };
        let ok = unsafe {
            if write {
                WriteFile(
                    raw,
                    bytes[offset..].as_ptr(),
                    (bytes.len() - offset) as u32,
                    std::ptr::null_mut(),
                    &mut operation,
                )
            } else {
                ReadFile(
                    raw,
                    bytes[offset..].as_mut_ptr(),
                    (bytes.len() - offset) as u32,
                    std::ptr::null_mut(),
                    &mut operation,
                )
            }
        };
        if ok == 0 && unsafe { GetLastError() } != ERROR_IO_PENDING {
            return Err(fail());
        }
        if unsafe {
            WaitForSingleObject(
                event.as_raw_handle(),
                remaining.min(u32::MAX as u128) as u32,
            )
        } != WAIT_OBJECT_0
        {
            unsafe {
                CancelIoEx(raw, &operation);
            }
            let mut ignored = 0;
            // OVERLAPPED/buffer must stay alive until cancellation completes.
            unsafe {
                GetOverlappedResult(raw, &operation, &mut ignored, 1);
            }
            return Err(fail());
        }
        let mut count = 0;
        if unsafe { GetOverlappedResult(raw, &operation, &mut count, 0) } == 0 || count == 0 {
            return Err(fail());
        }
        offset += count as usize;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "Requires explicitly provisioned disposable Windows service fixture"]
    fn same_owner_untrusted_process_and_pipe_instance_are_denied() {
        assert_eq!(
            std::env::var("FOXVPN_TEST_ALLOW_SERVICE").as_deref(),
            Ok("1")
        );
        // This Rust test process shares the installed owner's SID but its image
        // is not the pinned desktop client, so it must receive no Status.
        assert!(request(&Request::Status).is_err());
        for length in [(MAX_FRAME + 1) as u32, 1024] {
            let pipe = handle(unsafe {
                CreateFileW(
                    wide(PIPE).as_ptr(),
                    FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | FILE_FLAG_OVERLAPPED,
                    std::ptr::null_mut(),
                )
            })
            .expect("Owner must be able to open the pipe before process authentication");
            let started = Instant::now();
            let deadline = started + Duration::from_secs(5);
            client_transfer(
                pipe.as_raw_handle(),
                &mut length.to_le_bytes(),
                true,
                deadline,
            )
            .unwrap();
            let mut response = [0u8; 1];
            assert!(client_transfer(pipe.as_raw_handle(), &mut response, false, deadline).is_err());
            assert!(started.elapsed() < Duration::from_secs(5));
            // Allow server to rearm its one instance after disconnect.
            std::thread::sleep(Duration::from_millis(100));
        }
        let hostile = unsafe {
            CreateNamedPipeW(
                wide(PIPE).as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_NOWAIT,
                2,
                1024,
                1024,
                1000,
                std::ptr::null(),
            )
        };
        assert_eq!(hostile, INVALID_HANDLE_VALUE);
    }
}
