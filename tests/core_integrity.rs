use sha2::{Digest, Sha256};
use smart_vpn_engine::core_integrity;

#[test]
fn packaged_core_rejects_tampering_and_wrong_platform() {
    let dir = std::env::temp_dir().join(format!("foxvpn-integrity-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let binary = dir.join("core");
    let metadata = dir.join("version.json");
    std::fs::write(&binary, b"public-test-binary").unwrap();
    std::fs::write(&metadata, serde_json::to_vec(&serde_json::json!({
        "platform": "windows-amd64", "binary_sha256": format!("{:x}", Sha256::digest(b"public-test-binary"))
    })).unwrap()).unwrap();
    assert!(core_integrity::verify(&binary, &metadata, "windows-amd64").is_ok());
    assert!(core_integrity::verify(&binary, &metadata, "darwin-arm64").is_err());
    std::fs::write(&binary, b"modified-test-binary").unwrap();
    assert!(core_integrity::verify(&binary, &metadata, "windows-amd64").is_err());
    std::fs::write(&metadata, vec![b'x'; 16_385]).unwrap();
    assert!(core_integrity::verify(&binary, &metadata, "windows-amd64").is_err());
    std::fs::remove_dir_all(dir).unwrap();
}
