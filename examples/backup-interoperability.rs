//! Native CI artifact exchange. Only the compiled public fixture is accepted;
//! never touches an installed app, OS credentials, or an external VPN server.
#[cfg(feature = "test-support")]
#[path = "../tests/support/public_backup.rs"]
mod public;

#[cfg(feature = "test-support")]
fn main() {
    if let Err(error) = run() {
        eprintln!("Public backup gate: {error}");
        std::process::exit(1);
    }
}
#[cfg(not(feature = "test-support"))]
fn main() {
    eprintln!("Requires --features test-support");
    std::process::exit(1);
}

#[cfg(feature = "test-support")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};
    use smart_vpn_engine::{settings::Profile, user_files::read_selected};
    use std::path::PathBuf;
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 || !["export", "import"].contains(&args[0].as_str()) {
        return Err("Usage: backup-interoperability export|import DIRECTORY".into());
    }
    let directory = PathBuf::from(&args[1]);
    let report = directory.join(format!("import-{}.json", std::env::consts::OS));
    if args[0] == "import" {
        let _ = std::fs::remove_file(&report);
    }
    let work = public::Work::new();
    let vault = work.vault("vault", if cfg!(windows) { 29 } else { 17 });
    let backup = directory.join("public-backup.json");
    if args[0] == "export" {
        vault.save(&public::profile())?;
        let profile = vault.load()?;
        public::assert_complete(&profile);
        let bytes = serde_json::to_vec_pretty(&profile)?;
        std::fs::create_dir_all(&directory)?;
        std::fs::write(&backup, &bytes)?;
        let manifest = serde_json::json!({"schema":1,"source_os":std::env::consts::OS,"source_arch":std::env::consts::ARCH,"engine_version":env!("CARGO_PKG_VERSION"),"sha256":format!("{:x}", Sha256::digest(&bytes)),"fixture":"public-backup-v1","scope":"production Profile JSON + isolated encrypted Vault; OS credential dialogs excluded"});
        std::fs::write(
            directory.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest)?,
        )?;
    } else {
        let bytes = read_selected(&backup)?;
        let manifest: serde_json::Value =
            serde_json::from_str(&read_selected(&directory.join("manifest.json"))?)?;
        let source = manifest["source_os"].as_str().ok_or("Missing source OS")?;
        if manifest["schema"] != 1
            || manifest["fixture"] != "public-backup-v1"
            || manifest["engine_version"] != env!("CARGO_PKG_VERSION")
            || !["macos", "windows"].contains(&source)
        {
            return Err("Wrong fixture/version/native source manifest".into());
        }
        if source == std::env::consts::OS {
            return Err("Cross-platform import requires the other native OS artifact".into());
        }
        if manifest["sha256"] != format!("{:x}", Sha256::digest(bytes.as_bytes())) {
            return Err("Backup hash mismatch".into());
        }
        let profile: Profile = serde_json::from_str(&bytes)?;
        public::assert_complete(&profile);
        vault.save(&profile)?;
        public::assert_complete(
            &work
                .vault("vault", if cfg!(windows) { 29 } else { 17 })
                .load()?,
        );
        let result = serde_json::json!({"passed":true,"engine_version":env!("CARGO_PKG_VERSION"),"source_os":source,"destination_os":std::env::consts::OS,"sha256":manifest["sha256"],"preserved":["server identifiers/credentials/parameters/IPv6/Unicode","favorites/groups/selection","ordered rules","subscriptions and observations","all settings including platform flags","latency/speed/counters"],"physical_gui_acceptance":false,"keychain_credential_manager_acceptance":false});
        std::fs::write(&report, serde_json::to_vec_pretty(&result)?)?;
    }
    println!(
        "Public backup {} passed on {}",
        args[0],
        std::env::consts::OS
    );
    Ok(())
}
