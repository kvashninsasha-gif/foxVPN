//! The root service verifies the same version-bound publisher signature as the
//! desktop updater. GUI approval alone is never authority to install root code.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const BASE: &str = "/Library/PrivilegedHelperTools/foxVPN";
pub const SLOT: &str = "/Library/PrivilegedHelperTools/foxVPN/component";
pub const UPLOADS: &str = "/var/run/foxvpn/uploads";
pub const MAX_ARCHIVE: u64 = 256 * 1024 * 1024;
const INVALID: &str =
    "Обновление сетевого компонента не прошло проверку. Прежняя сборка сохранена.";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallRequest {
    pub archive: String,
    pub signature: String,
    pub version: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub protocol: u32,
    pub version: String,
    pub owner: u32,
    pub current: String,
    pub previous: Option<String>,
    pub archive_sha256: String,
}
impl Binding {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol != crate::network_helper::PROTOCOL
            || !crate::network_helper::valid_owner(self.owner)
            || !hash_valid(&self.current)
            || self.previous.as_deref().is_some_and(|v| !hash_valid(v))
            || (!self.archive_sha256.is_empty() && !digest_valid(&self.archive_sha256))
            || release_version(&self.version).is_err()
            || release_version(&self.version).is_ok_and(|v| v < semver::Version::new(0, 1, 23))
        {
            return Err(INVALID.into());
        }
        Ok(())
    }
    pub fn accepts(&self, hash: &str, owner: u32) -> bool {
        self.validate().is_ok()
            && self.owner == owner
            && (self.current == hash || self.previous.as_deref() == Some(hash))
    }
}
fn hash_valid(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn digest_valid(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn release_version(s: &str) -> Result<semver::Version, String> {
    let v = semver::Version::parse(s).map_err(|_| INVALID)?;
    if s.len() > 64 || !v.pre.is_empty() || !v.build.is_empty() {
        return Err(INVALID.into());
    }
    Ok(v)
}
/// Key is compiled into the root executable, never supplied through IPC.
pub fn verify_archive(bytes: &[u8], signature: &str, version: &str) -> Result<String, String> {
    if bytes.len() as u64 > MAX_ARCHIVE
        || signature.len() > 4096
        || !bytes.starts_with(&[0x1f, 0x8b])
    {
        return Err(INVALID.into());
    }
    let config: serde_json::Value = serde_json::from_str(include_str!(
        "../apps/desktop/src-tauri/tauri.macos.conf.json"
    ))
    .map_err(|_| INVALID)?;
    let decode = |s: &str| -> Result<String, String> {
        String::from_utf8(STANDARD.decode(s.trim()).map_err(|_| INVALID)?)
            .map_err(|_| INVALID.into())
    };
    let key = minisign_verify::PublicKey::decode(&decode(
        config["plugins"]["updater"]["pubkey"]
            .as_str()
            .ok_or(INVALID)?,
    )?)
    .map_err(|_| INVALID)?;
    let sig = minisign_verify::Signature::decode(&decode(signature)?).map_err(|_| INVALID)?;
    key.verify(bytes, &sig, false).map_err(|_| INVALID)?;
    let versions = sig
        .trusted_comment()
        .split('\t')
        .filter_map(|s| s.strip_prefix("version:"))
        .collect::<Vec<_>>();
    if versions.len() != 1 || release_version(versions[0])? != release_version(version)? {
        return Err(INVALID.into());
    }
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Floor {
    pub version: String,
    pub sha256: String,
}
pub fn check_version(floor: &Floor, version: &str, digest: &str) -> Result<(), String> {
    let new = release_version(version)?;
    let old = release_version(&floor.version)?;
    if !digest_valid(digest)
        || (!floor.sha256.is_empty() && !digest_valid(&floor.sha256))
        || new < old
        || (new == old && floor.sha256 != digest)
    {
        return Err("Откат версии или замена уже проверенного обновления запрещены.".into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> Binding {
        Binding {
            protocol: crate::network_helper::PROTOCOL,
            version: "0.1.23".into(),
            owner: 501,
            current: "a".repeat(40),
            previous: Some("b".repeat(40)),
            archive_sha256: "c".repeat(64),
        }
    }
    #[test]
    fn names_and_other_users_never_authorize_a_component_update() {
        let b = binding();
        assert!(b.accepts(&"a".repeat(40), 501));
        assert!(b.accepts(&"b".repeat(40), 501));
        for uid in [0, 500, 502, u32::MAX] {
            assert!(!b.accepts(&b.current, uid));
        }
        assert!(!b.accepts("ru.smartvpn.router", 501));
        let mut corrupt = b;
        corrupt.protocol += 1;
        assert!(!corrupt.accepts(&corrupt.current, 501));
    }
    #[test]
    fn a_version_cannot_be_replayed_or_replaced_with_other_bytes() {
        let floor = Floor {
            version: "0.1.24".into(),
            sha256: "b".repeat(64),
        };
        assert!(check_version(&floor, "0.1.23", &"a".repeat(64)).is_err());
        assert!(check_version(&floor, "0.1.24", &"a".repeat(64)).is_err());
        assert!(check_version(&floor, "0.1.24", &"b".repeat(64)).is_ok());
        assert!(check_version(&floor, "0.1.25", &"c".repeat(64)).is_ok());
        for version in ["0.1.25-beta", "0.1.25+fake", "0.01.25", "invalid"] {
            assert!(check_version(&floor, version, &"c".repeat(64)).is_err());
        }
    }
    #[test]
    fn bootstrap_cannot_accept_an_unsigned_same_version_archive() {
        let floor = Floor {
            version: "0.1.23".into(),
            sha256: String::new(),
        };
        assert!(check_version(&floor, "0.1.23", &"a".repeat(64)).is_err());
        assert!(verify_archive(&[0x1f, 0x8b, 0], "unsigned", "0.1.24").is_err());
        assert!(verify_archive(b"MZfake", "unsigned", "0.1.24").is_err());
    }
    #[test]
    #[ignore = "Run explicitly with FOXVPN_COMPONENT_TEST_ARCHIVE after signing"]
    fn the_root_verifier_accepts_only_the_original_signed_bytes_and_version() {
        let path = std::env::var("FOXVPN_COMPONENT_TEST_ARCHIVE").unwrap();
        let version = std::env::var("FOXVPN_COMPONENT_TEST_VERSION").unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let signature = std::fs::read_to_string(format!("{path}.sig")).unwrap();
        assert!(verify_archive(&bytes, &signature, &version).is_ok());
        assert!(verify_archive(&bytes, &signature, "999.0.0").is_err());
        let mut bad = bytes;
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(verify_archive(&bad, &signature, &version).is_err());
    }
}
