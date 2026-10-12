//! Public, credential-free accepted-caller fixture for a disposable runner.
#[cfg(windows)]
fn main() {
    match smart_vpn_engine::windows_service::native::request(
        &smart_vpn_engine::windows_service::Request::Status,
    ) {
        Ok(status)
            if !status.core_alive && !status.tun_supported && !status.kill_switch_supported =>
        {
            println!("{}", serde_json::to_string(&status).unwrap())
        }
        _ => std::process::exit(1),
    }
}
#[cfg(not(windows))]
fn main() {
    std::process::exit(1);
}
