#[cfg(windows)]
fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("This service accepts no command-line operations");
        std::process::exit(2);
    }
    if let Err(error) = smart_vpn_engine::windows_service::native::run_service() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
#[cfg(not(windows))]
fn main() {
    eprintln!("foxVPN network service requires Windows");
    std::process::exit(1);
}
