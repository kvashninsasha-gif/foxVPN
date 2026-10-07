//! A non-inheritable Windows job owns only this application's core process.
#[cfg(windows)]
pub(crate) struct ProcessJob {
    _handle: std::os::windows::io::OwnedHandle,
}

#[cfg(windows)]
impl ProcessJob {
    pub fn attach(child: &std::process::Child) -> Result<Self, String> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use windows_sys::Win32::System::JobObjects::*;
        let error = || crate::text("process_guard_failed").to_string();
        // Null security attributes keep the job handle out of the child's handles.
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err(error());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                handle.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&info) as u32,
            )
        } == 0
        {
            return Err(error());
        }
        if unsafe { AssignProcessToJobObject(handle.as_raw_handle(), child.as_raw_handle()) } == 0 {
            return Err(error());
        }
        Ok(Self { _handle: handle })
    }
}
