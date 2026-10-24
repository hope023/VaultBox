mod commands;
mod crypto;
mod hide;
mod store;
mod vault;

use std::time::Duration;
use tauri::{Emitter, RunEvent};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::session_roots,
            commands::vault_status,
            commands::vault_create,
            commands::vault_unlock,
            commands::vault_lock,
            commands::vault_import,
            commands::vault_list,
            commands::vault_dissolve,
            commands::vault_activity,
            commands::set_auto_lock,
            commands::get_auto_lock,
            commands::idle_seconds,
            commands::hide_toggle,
            commands::hide_is_hidden,
            commands::hide_list_dir,
            commands::vault_meta_info,
            commands::version,
            commands::force_exit,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    // 空闲自动上锁 watcher：每 5 秒检查一次（阈值 0 = 关闭，见 set_auto_lock）
    {
        let handle = app.handle().clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(5));
            for root in commands::auto_lock_tick() {
                let _ = handle.emit("vault-auto-locked", serde_json::json!({ "root": root }));
            }
        });
    }

    app.run(|handle, event| {
        if let RunEvent::ExitRequested { api, .. } = event {
            // 退出（关窗/关机正常退出）前：上锁全部会话。
            // 上锁失败（罕见：密封错误等；占用文件已被容错处理）→ 阻止退出，
            // 通知前端弹窗让用户选择「重试 / 强制退出」。
            let failed = commands::lock_all_for_exit();
            if !failed.is_empty() {
                api.prevent_exit();
                let _ = handle.emit(
                    "vault-exit-lock-failed",
                    serde_json::json!({ "roots": failed }),
                );
            }
        }
    });
}
