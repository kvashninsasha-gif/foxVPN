//! Current-owner private ACLs and durable replacement for the fixed recovery store.
use std::{
    fs,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::Threading::*,
};
const ERROR: &str = "Каталог восстановления Windows не прошёл проверку владельца и прав.";
fn wide(path: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    path.as_ref().encode_wide().chain(Some(0)).collect()
}
fn sid_text(sid: PSID) -> Result<String, String> {
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(ERROR.into());
    }
    let mut len = 0;
    while unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    let result = String::from_utf16(unsafe { std::slice::from_raw_parts(text, len) })
        .map_err(|_| ERROR.into());
    unsafe {
        LocalFree(text.cast());
    }
    result
}
fn owner() -> Result<String, String> {
    let mut raw = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(ERROR.into());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut size = 0;
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut size,
        );
    }
    if size == 0 || size > 16384 {
        return Err(ERROR.into());
    }
    let mut bytes = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            bytes.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    } == 0
    {
        return Err(ERROR.into());
    }
    sid_text(unsafe { (*(bytes.as_ptr().cast::<TOKEN_USER>())).User.Sid })
}
fn attributes(path: &Path) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    for p in path.ancestors() {
        if fs::symlink_metadata(p)
            .map_err(|_| ERROR)?
            .file_attributes()
            & FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(ERROR.into());
        }
    }
    Ok(())
}
fn security(path: &Path, validate_acl: bool) -> Result<(), String> {
    attributes(path)?;
    let user = owner()?;
    let mut sid = std::ptr::null_mut();
    let mut acl = std::ptr::null_mut();
    let mut sd = std::ptr::null_mut();
    if unsafe {
        GetNamedSecurityInfoW(
            wide(path).as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut sid,
            std::ptr::null_mut(),
            &mut acl,
            std::ptr::null_mut(),
            &mut sd,
        )
    } != 0
    {
        return Err(ERROR.into());
    }
    let result = (|| {
        if sid_text(sid)? != user || acl.is_null() {
            return Err(ERROR.into());
        }
        if validate_acl {
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
                return Err(ERROR.into());
            }
            for i in 0..info.AceCount {
                let mut raw = std::ptr::null_mut();
                if unsafe { GetAce(acl, i, &mut raw) } == 0 {
                    return Err(ERROR.into());
                }
                let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
                if ace.Header.AceType == 1 {
                    continue;
                }
                if ace.Header.AceType != 0
                    || ![user.as_str(), "S-1-5-18"].contains(
                        &sid_text((&ace.SidStart as *const u32).cast_mut().cast())?.as_str(),
                    )
                {
                    return Err(ERROR.into());
                }
            }
        }
        Ok(())
    })();
    unsafe {
        LocalFree(sd);
    }
    result
}
pub(super) fn initialize(path: &Path) -> Result<(), String> {
    attributes(path)?;
    apply(path)
}
fn apply(path: &Path) -> Result<(), String> {
    let user = owner()?;
    let mut sd = std::ptr::null_mut();
    let acl = wide(format!("O:{user}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{user})"));
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            acl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(ERROR.into());
    }
    let ok = unsafe {
        SetFileSecurityW(
            wide(path).as_ptr(),
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            sd,
        )
    };
    unsafe {
        LocalFree(sd);
    }
    if ok == 0 {
        return Err(ERROR.into());
    }
    check(path)
}
pub(super) fn protect(path: &Path) -> Result<(), String> {
    security(path, false)?;
    apply(path)
}
pub(super) fn check(path: &Path) -> Result<(), String> {
    security(path, true)
}
pub(super) fn replace(from: &Path, target: &Path) -> Result<(), String> {
    if unsafe {
        MoveFileExW(
            wide(from).as_ptr(),
            wide(target).as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(ERROR.into());
    }
    check(target)
}
