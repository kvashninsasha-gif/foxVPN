#[cfg(target_os = "macos")]
#[test]
#[ignore = "Uses an isolated entry in macOS Keychain"]
fn actual_keychain_encrypted_profile_roundtrip() {
    use smart_vpn_engine::{
        servers::Server,
        settings::{Profile, Vault},
    };
    let service = format!("ru.smartvpn.router.test.{}", uuid::Uuid::new_v4());
    let path = std::path::PathBuf::from(std::env::var_os("HOME").unwrap())
        .join("Library/Application Support")
        .join(&service);
    struct Cleanup(String, std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Ok(e) = keyring::Entry::new(&self.0, "master-key") {
                let _ = e.delete_credential();
            }
            let _ = std::fs::remove_dir_all(&self.1);
        }
    }
    let _guard = Cleanup(service.clone(), path.clone());
    let vault = Vault::new(&service);
    let mut profile = Profile::default();
    profile.servers.push(
        Server::parse(
            "vless://123e4567-e89b-12d3-a456-426614174000@127.0.0.1:443?security=tls#Vault-test",
        )
        .unwrap(),
    );
    profile.selected = Some(profile.servers[0].id.clone());
    vault.save(&profile).unwrap();
    let raw = std::fs::read(path.join("profile.enc")).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("123e4567-e89b-12d3-a456-426614174000"));
    assert_eq!(
        vault.load().unwrap().servers[0].uuid,
        profile.servers[0].uuid
    );
}
