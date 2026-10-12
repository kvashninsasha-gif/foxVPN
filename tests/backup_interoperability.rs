#![cfg(feature = "test-support")]
#[path = "support/public_backup.rs"]
mod public;
use smart_vpn_engine::{settings::Profile, user_files::read_selected};

#[test]
fn complete_backup_moves_between_independent_encrypted_vaults_both_directions() {
    for (source_key, destination_key) in [(17, 29), (29, 17)] {
        let work = public::Work::new();
        let source = work.vault("source", source_key);
        source.save(&public::profile()).unwrap();
        let backup = work.0.join("public.json");
        std::fs::write(
            &backup,
            serde_json::to_string_pretty(&source.load().unwrap()).unwrap(),
        )
        .unwrap();
        let restored: Profile = serde_json::from_str(&read_selected(&backup).unwrap()).unwrap();
        let dest = work.vault("destination", destination_key);
        dest.save(&restored).unwrap();
        public::assert_complete(&work.vault("destination", destination_key).load().unwrap());
        assert!(work.vault("destination", source_key).load().is_err());
        assert_ne!(
            std::fs::read(work.0.join("source/profile.enc")).unwrap(),
            std::fs::read(work.0.join("destination/profile.enc")).unwrap()
        );
    }
}

#[test]
fn windows_crlf_unicode_and_bom_behavior_matches_native_import() {
    let work = public::Work::new();
    let backup = work.0.join("public.json");
    std::fs::write(&backup, public::FIXTURE.replace('\n', "\r\n")).unwrap();
    let restored: Profile = serde_json::from_str(&read_selected(&backup).unwrap()).unwrap();
    public::assert_complete(&restored);
    // Production import rejects a BOM; never silently claim arbitrary exports work.
    std::fs::write(&backup, format!("\u{feff}{}", public::FIXTURE)).unwrap();
    assert!(serde_json::from_str::<Profile>(&read_selected(&backup).unwrap()).is_err());
}

#[test]
fn invalid_transfer_cannot_replace_destination_profile() {
    let work = public::Work::new();
    let vault = work.vault("destination", 29);
    vault.save(&public::profile()).unwrap();
    for alteration in ["version", "selected", "dns", "duplicate"] {
        let mut changed = public::profile();
        match alteration {
            "version" => changed.version = 999,
            "selected" => changed.selected = Some("missing".into()),
            "dns" => changed.settings.dns_provider = "untrusted".into(),
            _ => changed.servers.push(changed.servers[0].clone()),
        }
        assert!(vault.save(&changed).is_err());
        public::assert_complete(&vault.load().unwrap());
    }
}
