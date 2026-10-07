//! Check packaged files without exposing paths or launching an unverified core.
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};

#[derive(Deserialize)]
struct Metadata {
    binary_sha256: String,
    platform: String,
}

pub fn verify(binary: &Path, metadata: &Path, platform: &str) -> Result<(), String> {
    let error = || crate::text("core_integrity_error").to_string();
    for path in [binary, metadata] {
        if !std::fs::symlink_metadata(path)
            .map_err(|_| error())?
            .is_file()
        {
            return Err(error());
        }
    }
    let mut bytes = Vec::new();
    File::open(metadata)
        .and_then(|f| f.take(16_385).read_to_end(&mut bytes))
        .map_err(|_| error())?;
    if bytes.len() > 16_384 {
        return Err(error());
    }
    let expected: Metadata = serde_json::from_slice(&bytes).map_err(|_| error())?;
    if expected.platform != platform || expected.binary_sha256.len() != 64 {
        return Err(error());
    }
    let mut file = File::open(binary).map_err(|_| error())?;
    let size = file.metadata().map_err(|_| error())?;
    if !size.is_file() || size.len() == 0 || size.len() > 160_000_000 {
        return Err(error());
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65_536];
    let mut total = 0u64;
    loop {
        let count = file.read(&mut buffer).map_err(|_| error())?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > 160_000_000 {
            return Err(error());
        }
        digest.update(&buffer[..count]);
    }
    if format!("{:x}", digest.finalize()) != expected.binary_sha256 {
        return Err(error());
    }
    Ok(())
}

pub fn platform() -> String {
    let os = if cfg!(target_os = "macos") {
        "darwin"
    } else {
        std::env::consts::OS
    };
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        value => value,
    };
    format!("{os}-{arch}")
}
