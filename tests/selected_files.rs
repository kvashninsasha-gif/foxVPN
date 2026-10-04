use smart_vpn_engine::user_files::read_selected;
use std::{fs, path::PathBuf};
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("foxvpn-selected-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn chosen_regular_utf8_file_is_bounded_and_directories_are_rejected() {
    let root = Scratch::new();
    let path = root.0.join("profile.json");
    fs::write(&path, "test fixture").unwrap();
    assert_eq!(read_selected(&path).unwrap(), "test fixture");
    assert!(read_selected(&root.0).is_err());
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(4_000_001)
        .unwrap();
    assert!(read_selected(&path).is_err());
    fs::write(&path, [0xff, 0xff]).unwrap();
    assert!(read_selected(&path).is_err());
}
#[cfg(unix)]
#[test]
fn symlink_and_fifo_cannot_disclose_or_block_the_backend() {
    let root = Scratch::new();
    let target = root.0.join("private.json");
    fs::write(&target, "private test fixture").unwrap();
    let link = root.0.join("selected.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(read_selected(&link).is_err());
    let fifo = root.0.join("pipe");
    let name = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(read_selected(&fifo).is_err());
}
