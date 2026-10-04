//! Bounded reads of regular files chosen by a native dialog. These functions
//! must never be exposed as path-taking commands to an untrusted WebView.
use std::{fs::OpenOptions, io::Read, path::Path};
pub fn read_selected(path: &Path) -> Result<String, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options
        .open(path)
        .map_err(|_| crate::text("selected_file_error"))?;
    let meta = file
        .metadata()
        .map_err(|_| crate::text("selected_file_error"))?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(crate::text("selected_file_error").into());
        }
    }
    if !meta.is_file() || meta.len() > 4_000_000 {
        return Err(crate::text("selected_file_error").into());
    }
    let mut bytes = Vec::new();
    file.take(4_000_001)
        .read_to_end(&mut bytes)
        .map_err(|_| crate::text("selected_file_error"))?;
    if bytes.len() > 4_000_000 {
        return Err(crate::text("selected_file_error").into());
    }
    String::from_utf8(bytes).map_err(|_| crate::text("selected_file_error").into())
}
