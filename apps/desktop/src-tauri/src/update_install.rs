//! Install only verified updater bytes. Stage beside the app so all renames stay
//! on the same filesystem; atomically exchange bundles and retain the previous app.
use flate2::read::GzDecoder;
use std::{
    fs,
    io::Cursor,
    path::{Component, Path, PathBuf},
    process::Command,
};

pub struct Prepared {
    stage: tempfile::TempDir,
    target: PathBuf,
}
pub fn app_path(executable: &Path) -> Result<PathBuf, String> {
    let macos = executable.parent().ok_or("Не найден каталог приложения.")?;
    let contents = macos.parent().ok_or("Не найден каталог приложения.")?;
    let app = contents.parent().ok_or("Не найден каталог приложения.")?;
    if macos.file_name().is_none_or(|s| s != "MacOS")
        || contents.file_name().is_none_or(|s| s != "Contents")
        || app.extension().is_none_or(|s| s != "app")
        || app.to_string_lossy().contains("/AppTranslocation/")
    {
        return Err("Для обновления запустите установленный foxVPN из папки «Программы», а не из образа диска или режима разработки.".into());
    }
    Ok(app.to_owned())
}
pub fn prepare(bytes: &[u8], target: &Path, version: &str) -> Result<Prepared, String> {
    let parent = target.parent().ok_or("Не найден каталог приложения.")?;
    let stage = tempfile::Builder::new().prefix(".foxVPN-update-").tempdir_in(parent).map_err(|_| "Нет доступа для обновления этой копии. Установите foxVPN в ~/Applications или обновите приложение вручную.")?;
    let mut archive = tar::Archive::new(GzDecoder::new(Cursor::new(bytes)));
    let mut expanded = 0u64;
    for entry in archive
        .entries()
        .map_err(|_| "Неверный архив обновления.")?
    {
        let mut entry = entry.map_err(|_| "Повреждён архив обновления.")?;
        expanded = expanded.saturating_add(entry.size());
        if expanded > 512 * 1024 * 1024 {
            return Err("Архив обновления превышает допустимый размер.".into());
        }
        let path = entry
            .path()
            .map_err(|_| "Неверное имя файла обновления.")?
            .into_owned();
        let mut parts = path.components();
        if !matches!(parts.next(), Some(Component::Normal(s)) if s == "foxVPN.app")
            || parts.clone().any(|c| !matches!(c, Component::Normal(_)))
            || !matches!(
                entry.header().entry_type(),
                tar::EntryType::Regular | tar::EntryType::Directory
            )
        {
            return Err("Архив содержит недопустимые пути или ссылки.".into());
        }
        let relative: PathBuf = parts.collect();
        if relative.as_os_str().is_empty() {
            continue;
        }
        if !entry
            .unpack_in(stage.path())
            .map_err(|_| "Не удалось распаковать обновление.")?
        {
            return Err("Неверный путь обновления.".into());
        }
    }
    let app = stage.path().join("foxVPN.app");
    let info = plist::Value::from_file(app.join("Contents/Info.plist"))
        .map_err(|_| "Нет метаданных приложения в обновлении.")?;
    let info = info
        .as_dictionary()
        .ok_or("Неверные метаданные обновления.")?;
    if info
        .get("CFBundleIdentifier")
        .and_then(plist::Value::as_string)
        != Some("ru.smartvpn.router")
        || info
            .get("CFBundleShortVersionString")
            .and_then(plist::Value::as_string)
            != Some(version)
        || info
            .get("CFBundleExecutable")
            .and_then(plist::Value::as_string)
            != Some("smart-vpn-desktop")
    {
        return Err("Версия или идентификатор приложения не совпадают с обновлением.".into());
    }
    let status = Command::new("/usr/bin/codesign")
        .args(["--verify", "--deep", "--strict"])
        .arg(&app)
        .output()
        .map_err(|_| "Не удалось проверить подпись macOS.")?;
    if !status.status.success() {
        return Err("Подпись приложения macOS недействительна.".into());
    }
    for name in [
        "core/sing-box",
        "network/foxvpn-helper",
        "network/foxvpn-network-core",
        "network/network-version.json",
    ] {
        if !app.join("Contents/Resources").join(name).is_file() {
            return Err("Обновление не содержит ядро или сетевой компонент.".into());
        }
    }
    Ok(Prepared {
        stage,
        target: target.to_owned(),
    })
}
impl Prepared {
    pub fn commit(self) -> Result<PathBuf, String> {
        let backup = self
            .target
            .with_file_name(format!(".foxVPN-previous-{}.app", uuid::Uuid::new_v4()));
        // Keep before the exchange: even termination between swap and backup rename
        // must not cause TempDir's destructor to delete the previous application.
        let stage = self.stage.keep();
        let result = replace(&self.target, &stage.join("foxVPN.app"), &backup);
        match &result {
            Err(_) => {
                let _ = fs::remove_dir_all(&stage);
            }
            Ok(path) if path == &backup => {
                let _ = fs::remove_dir(&stage);
            }
            _ => (), // Backup rename failed: retain the old app inside staging.
        }
        result
    }
}
fn rename_native(from: &Path, to: &Path, flags: u32) -> std::io::Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    unsafe extern "C" {
        fn renamex_np(
            from: *const std::ffi::c_char,
            to: *const std::ffi::c_char,
            flags: u32,
        ) -> i32;
    }
    let from = CString::new(from.as_os_str().as_bytes()).map_err(std::io::Error::other)?;
    let to = CString::new(to.as_os_str().as_bytes()).map_err(std::io::Error::other)?;
    // SDK sys/stdio.h: RENAME_SWAP=2, RENAME_EXCL=4. Both paths remain alive.
    if unsafe { renamex_np(from.as_ptr(), to.as_ptr(), flags) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
fn replace(target: &Path, new: &Path, backup: &Path) -> Result<PathBuf, String> {
    for path in [target, new] {
        if !fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir()) {
            return Err(
                "Не найдено приложение или каталог заменён ссылкой. Обновление не установлено."
                    .into(),
            );
        }
    }
    // No two-rename fallback: a crash must never leave the installed path absent.
    rename_native(new, target, 2).map_err(|_| "Не удалось атомарно заменить приложение. Прежняя копия остаётся на месте; проверьте права и файловую систему.".to_string())?;
    if rename_native(new, backup, 4).is_ok() {
        Ok(backup.to_owned())
    } else {
        // Installation succeeded. Keep the old bundle at its current location.
        Ok(new.to_owned())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_installed_bundle_is_supported() {
        assert_eq!(
            app_path(Path::new(
                "/Applications/foxVPN.app/Contents/MacOS/smart-vpn-desktop"
            ))
            .unwrap(),
            PathBuf::from("/Applications/foxVPN.app")
        );
        assert!(app_path(Path::new("/tmp/smart-vpn-desktop")).is_err());
        assert!(app_path(Path::new(
            "/tmp/AppTranslocation/x/foxVPN.app/Contents/MacOS/smart-vpn-desktop"
        ))
        .is_err());
    }
    #[test]
    fn failed_exchange_keeps_old_app_in_place() {
        let root = tempfile::tempdir().unwrap();
        let app = root.path().join("foxVPN.app");
        let backup = root.path().join("old.app");
        fs::create_dir(&app).unwrap();
        fs::write(app.join("original"), "kept").unwrap();
        assert!(replace(&app, &root.path().join("missing.app"), &backup).is_err());
        assert_eq!(fs::read_to_string(app.join("original")).unwrap(), "kept");
        assert!(!backup.exists());
    }
    #[test]
    fn successful_replacement_retains_backup() {
        let root = tempfile::tempdir().unwrap();
        let app = root.path().join("foxVPN.app");
        let new = root.path().join("new.app");
        let backup = root.path().join("old.app");
        for (path, text) in [(&app, "old"), (&new, "new")] {
            fs::create_dir(path).unwrap();
            fs::write(path.join("version"), text).unwrap();
        }
        replace(&app, &new, &backup).unwrap();
        assert_eq!(fs::read_to_string(app.join("version")).unwrap(), "new");
        assert_eq!(fs::read_to_string(backup.join("version")).unwrap(), "old");
    }
    #[test]
    fn failed_backup_move_keeps_both_apps_and_never_overwrites_backup() {
        let root = tempfile::tempdir().unwrap();
        let app = root.path().join("foxVPN.app");
        let new = root.path().join("new.app");
        let backup = root.path().join("existing.app");
        for (path, text) in [(&app, "old"), (&new, "new"), (&backup, "unrelated")] {
            fs::create_dir(path).unwrap();
            fs::write(path.join("version"), text).unwrap();
        }
        assert_eq!(replace(&app, &new, &backup).unwrap(), new);
        assert_eq!(fs::read_to_string(app.join("version")).unwrap(), "new");
        assert_eq!(fs::read_to_string(new.join("version")).unwrap(), "old");
        assert_eq!(
            fs::read_to_string(backup.join("version")).unwrap(),
            "unrelated"
        );
    }
    #[test]
    fn symlink_target_is_rejected_without_modifying_other_copy() {
        let root = tempfile::tempdir().unwrap();
        let app = root.path().join("foxVPN.app");
        let other = root.path().join("other.app");
        let new = root.path().join("new.app");
        fs::create_dir(&other).unwrap();
        fs::create_dir(&new).unwrap();
        fs::write(other.join("original"), "kept").unwrap();
        std::os::unix::fs::symlink(&other, &app).unwrap();
        assert!(replace(&app, &new, &root.path().join("backup.app")).is_err());
        assert!(fs::symlink_metadata(&app).unwrap().file_type().is_symlink());
        assert_eq!(fs::read_to_string(other.join("original")).unwrap(), "kept");
    }
    #[test]
    fn wrong_archive_never_replaces_app() {
        let root = tempfile::tempdir().unwrap();
        let app = root.path().join("foxVPN.app");
        fs::create_dir(&app).unwrap();
        fs::write(app.join("original"), "kept").unwrap();
        assert!(prepare(b"invalid gzip", &app, "0.1.8").is_err());
        assert!(app.join("original").exists());
    }
}

#[cfg(test)]
mod artifact_test {
    use super::*;
    use std::io::{Read, Write};
    use tauri_plugin_updater::UpdaterExt;
    fn artifact_version() -> String {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        config["version"].as_str().unwrap().to_owned()
    }
    #[tokio::test]
    #[ignore = "Run explicitly after publishing release and HTTPS feed"]
    async fn live_github_release_download_verifies_signature() {
        let path = PathBuf::from(
            std::env::var("FOXVPN_TEST_UPDATE_ARTIFACT").expect("local signed release artifact"),
        );
        let expected = fs::read(path).unwrap();
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.macos.conf.json")).unwrap();
        let mut context = tauri::test::mock_context(tauri::test::noop_assets());
        context.package_info_mut().version = "0.1.8".parse().unwrap();
        context
            .config_mut()
            .plugins
            .0
            .insert("updater".into(), config["plugins"]["updater"].clone());
        let app = tauri::test::mock_builder()
            .plugin(tauri_plugin_updater::Builder::new().build())
            .build(context)
            .unwrap();
        let updater = app
            .updater_builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap();
        let mut update = updater.check().await.unwrap().unwrap();
        assert_eq!(update.version, artifact_version());
        assert!(update.download_url.as_str().ends_with(&format!(
            "/v{0}/foxVPN-{0}-macOS-arm64.app.tar.gz",
            artifact_version()
        )));
        update.timeout = Some(std::time::Duration::from_secs(180));
        let downloaded = update.download(|_, _| {}, || {}).await.unwrap();
        assert_eq!(downloaded, expected);
    }
    #[tokio::test]
    #[ignore = "Run explicitly with FOXVPN_TEST_UPDATE_ARTIFACT after signing the release"]
    async fn real_signed_artifact_install_and_tamper_rejection() {
        let path = PathBuf::from(
            std::env::var("FOXVPN_TEST_UPDATE_ARTIFACT").expect("signed release artifact"),
        );
        let bytes = fs::read(&path).unwrap();
        let signature = fs::read_to_string(format!("{}.sig", path.display())).unwrap();
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.macos.conf.json")).unwrap();
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("foxVPN.app");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("old-copy"), b"preserved").unwrap();
        let previous_version = if let Ok(previous) = std::env::var("FOXVPN_TEST_PREVIOUS_ARTIFACT")
        {
            let previous_version = "0.1.8";
            prepare(&fs::read(previous).unwrap(), &target, previous_version)
                .unwrap()
                .commit()
                .unwrap();
            Some(previous_version)
        } else {
            None
        };
        for mode in ["valid", "corrupt", "wrong-version", "cancel"] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let mut payload = bytes.clone();
            if mode == "corrupt" {
                payload[0] ^= 1;
            }
            let version = artifact_version();
            let mut wrong = semver::Version::parse(&version).unwrap();
            wrong.patch += 1;
            let wrong = wrong.to_string();
            let announced = if mode == "wrong-version" {
                &wrong
            } else {
                &version
            };
            let manifest=serde_json::json!({"version":announced,"platforms":{"darwin-aarch64":{"url":format!("http://{address}/artifact"),"signature":signature.trim()}}}).to_string();
            let server = std::thread::spawn(move || {
                for _ in 0..2 {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut request = [0; 4096];
                    let read = stream.read(&mut request).unwrap();
                    let metadata =
                        String::from_utf8_lossy(&request[..read]).starts_with("GET /manifest");
                    let body = if metadata {
                        manifest.as_bytes()
                    } else {
                        &payload
                    };
                    let headers=format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",body.len());
                    if stream.write_all(headers.as_bytes()).is_err() {
                        continue;
                    }
                    if !metadata && mode == "cancel" {
                        let _ = stream.write_all(&body[..1024]);
                        std::thread::sleep(std::time::Duration::from_millis(200));
                    } else {
                        let _ = stream.write_all(body);
                    }
                }
            });
            let mut context = tauri::test::mock_context(tauri::test::noop_assets());
            context.package_info_mut().version = "0.1.8".parse().unwrap();
            context
                .config_mut()
                .plugins
                .0
                .insert("updater".into(), config["plugins"]["updater"].clone());
            let app = tauri::test::mock_builder()
                .plugin(tauri_plugin_updater::Builder::new().build())
                .build(context)
                .unwrap();
            let updater = app
                .updater_builder()
                .endpoints(vec![format!("http://{address}/manifest").parse().unwrap()])
                .unwrap()
                .timeout(std::time::Duration::from_secs(3))
                .build()
                .unwrap();
            let update = updater.check().await.unwrap().unwrap();
            assert_eq!(update.current_version, "0.1.8");
            if mode == "cancel" {
                let mut future = Box::pin(update.download(|_, _| {}, || {}));
                tokio::select! { _=tokio::time::sleep(std::time::Duration::from_millis(50))=>{}, result=&mut future=>panic!("unexpected early completion {result:?}") }
                drop(future);
                assert!(target.join("Contents").exists());
            } else {
                let result = update.download(|_, _| {}, || {}).await;
                if mode == "valid" {
                    let downloaded = result.unwrap();
                    assert_eq!(downloaded, bytes);
                    let prepared = prepare(&downloaded, &target, &version).unwrap();
                    if let Some(previous) = previous_version {
                        let info =
                            plist::Value::from_file(target.join("Contents/Info.plist")).unwrap();
                        assert_eq!(
                            info.as_dictionary().unwrap()["CFBundleShortVersionString"].as_string(),
                            Some(previous)
                        );
                    } else {
                        assert!(target.join("old-copy").exists());
                    }
                    let backup = prepared.commit().unwrap();
                    assert!(target.join("Contents/MacOS/smart-vpn-desktop").exists());
                    if let Some(previous) = previous_version {
                        let info =
                            plist::Value::from_file(backup.join("Contents/Info.plist")).unwrap();
                        assert_eq!(
                            info.as_dictionary().unwrap()["CFBundleShortVersionString"].as_string(),
                            Some(previous)
                        );
                        assert!(Command::new("/usr/bin/codesign")
                            .args(["--verify", "--deep", "--strict"])
                            .arg(&backup)
                            .status()
                            .unwrap()
                            .success());
                    } else {
                        assert!(backup.join("old-copy").exists());
                    }
                    assert!(prepare(&downloaded, &target, &wrong).is_err());
                } else {
                    assert!(result.is_err(), "{mode} accepted");
                    assert!(target.join("Contents/MacOS/smart-vpn-desktop").exists());
                }
            }
            server.join().unwrap();
        }
    }
}
