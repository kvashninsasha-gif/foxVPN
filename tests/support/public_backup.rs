use smart_vpn_engine::settings::{Profile, Vault};
use std::path::PathBuf;

pub const FIXTURE: &str = include_str!("../fixtures/public-backup-v1.json");
pub fn profile() -> Profile {
    let p: Profile = serde_json::from_str(FIXTURE).expect("public backup fixture");
    p.validate().expect("valid public backup fixture");
    p
}
pub fn assert_complete(actual: &Profile) {
    actual.validate().expect("valid restored profile");
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(profile()).unwrap()
    );
}
pub struct Work(pub PathBuf);
impl Work {
    pub fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("foxvpn-public-backup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    pub fn vault(&self, label: &str, key: u8) -> Vault {
        Vault::test_fixture(self.0.join(label).join("profile.enc"), [key; 32])
    }
}
impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
