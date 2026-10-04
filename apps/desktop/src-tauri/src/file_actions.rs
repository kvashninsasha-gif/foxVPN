//! Paths originate only from native Rust dialogs. No IPC command accepts a path.
use super::{edit, import_servers_state, write_private, State};
use smart_vpn_engine::{
    servers::ImportReport,
    settings::{Profile, Settings},
    vpn::config,
};
use std::sync::atomic::{AtomicBool, Ordering};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
static OPEN: AtomicBool = AtomicBool::new(false);
struct DialogGuard;
impl DialogGuard {
    fn acquire() -> Result<Self, String> {
        OPEN.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| Self)
            .map_err(|_| smart_vpn_engine::text("file_dialog_busy").into())
    }
}
impl Drop for DialogGuard {
    fn drop(&mut self) {
        OPEN.store(false, Ordering::SeqCst);
    }
}
fn text(key: &str) -> &'static str {
    smart_vpn_engine::text(key)
}
#[tauri::command]
pub async fn import_file(
    app: tauri::AppHandle,
    s: tauri::State<'_, State>,
) -> Result<Option<ImportReport>, String> {
    let state = s.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _dialog = DialogGuard::acquire()?;
        let Some(file) = app
            .dialog()
            .file()
            .set_title(text("file_import"))
            .add_filter(text("file_ext"), &["txt", "conf"])
            .blocking_pick_file()
        else {
            return Ok(None);
        };
        let path = file.into_path().map_err(|_| text("selected_file_error"))?;
        import_servers_state(smart_vpn_engine::user_files::read_selected(&path)?, &state).map(Some)
    })
    .await
    .map_err(|_| text("selected_file_error"))?
}
#[tauri::command]
pub async fn import_backup(
    app: tauri::AppHandle,
    s: tauri::State<'_, State>,
) -> Result<bool, String> {
    let state = s.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _dialog = DialogGuard::acquire()?;
        let Some(file) = app
            .dialog()
            .file()
            .set_title(text("backup_restore_title"))
            .add_filter(text("json_ext"), &["json"])
            .blocking_pick_file()
        else {
            return Ok(false);
        };
        let path = file.into_path().map_err(|_| text("selected_file_error"))?;
        let profile: Profile =
            serde_json::from_str(&smart_vpn_engine::user_files::read_selected(&path)?)
                .map_err(|_| text("message_342"))?;
        profile.validate()?;
        if !app
            .dialog()
            .message(text("confirm_backup"))
            .title(text("backup_restore_title"))
            .buttons(MessageDialogButtons::OkCancelCustom(
                text("restore_action").into(),
                text("cancel").into(),
            ))
            .blocking_show()
        {
            return Ok(false);
        }
        edit(&state, |current| {
            if state
                .core
                .lock()
                .map_err(|_| text("message_338"))?
                .is_some()
                || state
                    .status
                    .lock()
                    .map_err(|_| text("message_338"))?
                    .as_str()
                    != "disconnected"
            {
                return Err(text("disconnect_first").into());
            }
            *current = profile;
            Ok(())
        })?;
        Ok(true)
    })
    .await
    .map_err(|_| text("selected_file_error"))?
}
async fn export(app: tauri::AppHandle, state: State, backup: bool) -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let _dialog = DialogGuard::acquire()?;
        let title = text(if backup {
            "backup_export_title"
        } else {
            "config_export_title"
        });
        let Some(file) = app
            .dialog()
            .file()
            .set_title(title)
            .set_file_name(if backup {
                "foxvpn-backup.json"
            } else {
                "foxvpn-tun.json"
            })
            .add_filter(text("json_ext"), &["json"])
            .blocking_save_file()
        else {
            return Ok(false);
        };
        let path = file.into_path().map_err(|_| text("selected_file_error"))?;
        let profile = state
            .profile
            .lock()
            .map_err(|_| text("message_335"))?
            .clone();
        let contents = if backup {
            serde_json::to_string_pretty(&profile).map_err(|_| text("message_335"))?
        } else {
            let server = profile
                .servers
                .iter()
                .find(|v| Some(&v.id) == profile.selected.as_ref())
                .ok_or(text("message_343"))?;
            let settings = Settings {
                tun: true,
                ..profile.settings.clone()
            };
            serde_json::to_string_pretty(&config(
                server,
                &settings,
                &profile.rules,
                2080,
                2081,
                &uuid::Uuid::new_v4().to_string(),
            )?)
            .map_err(|_| text("message_335"))?
        };
        write_private(&path, &contents)?;
        Ok(true)
    })
    .await
    .map_err(|_| text("selected_file_error"))?
}
#[tauri::command]
pub async fn export_backup(
    app: tauri::AppHandle,
    s: tauri::State<'_, State>,
) -> Result<bool, String> {
    export(app, s.inner().clone(), true).await
}
#[tauri::command]
pub async fn export_config(
    app: tauri::AppHandle,
    s: tauri::State<'_, State>,
) -> Result<bool, String> {
    export(app, s.inner().clone(), false).await
}
