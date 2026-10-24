//! Tauri 命令门面：前端唯一入口。
//!
//! 会话模型：解锁成功后密钥驻留本进程内存（AppState::sessions），
//! 上锁/导入/移除保险箱复用该密钥（无需反复输密码）；空闲自动上锁
//! 由后台线程执行（lib.rs 的 watcher），上锁后密钥 drop（zeroize）。
//!
//! 性能模型：重 IO 命令（解锁/上锁/导入/列表/隐藏）一律 async +
//! spawn_blocking 在工作线程执行 —— 同步命令跑在主线程会阻塞事件循环，
//! 文件多时窗口"未响应"。进度经 "vault-progress" 事件推送前端。

use crate::crypto::VaultKey;
use crate::vault::{self, VaultStatus};
use crate::{hide, store};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::Emitter;

struct Session {
    root: PathBuf,
    key: VaultKey,
    last_activity: Instant,
}

struct AppState {
    /// 多箱并发：每个已解锁的保险箱一个会话
    sessions: std::collections::HashMap<PathBuf, Session>,
    /// 自动上锁阈值（秒）；0 = 关闭（仅退出程序时上锁）。前端可调。
    auto_lock_secs: u64,
    /// 错误密码尝试计数与锁定窗口（防止暴力尝试）
    fail_count: u32,
    fail_lock_until: Option<Instant>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
            auto_lock_secs: 600,
            fail_count: 0,
            fail_lock_until: None,
        }
    }
}

const MAX_FAILS: u32 = 5;
const FAIL_LOCK_SECS: u64 = 30;

fn state() -> &'static Mutex<AppState> {
    static STATE: std::sync::OnceLock<Mutex<AppState>> = std::sync::OnceLock::new();
    STATE.get_or_init(|| Mutex::new(AppState::default()))
}

fn root_of(path: &str) -> Result<PathBuf, String> {
    let p = PathBuf::from(path);
    if p.as_os_str().is_empty() {
        return Err("路径为空".to_string());
    }
    Ok(p)
}

/// 会话中的根路径（前端恢复界面用）
#[tauri::command]
pub fn session_roots() -> Vec<String> {
    state()
        .lock()
        .unwrap()
        .sessions
        .keys()
        .map(|p| p.to_string_lossy().to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// 保险箱命令
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn vault_status(path: String) -> Result<VaultStatus, String> {
    let root = root_of(&path)?;
    let s = tauri::async_runtime::spawn_blocking(move || vault::status(&root))
        .await
        .map_err(|e| format!("任务执行失败: {e}"))?;
    Ok(s)
}

#[tauri::command]
pub async fn vault_create(path: String, password: String, force: bool) -> Result<(), String> {
    if password.chars().count() < 6 {
        return Err("密码至少 6 个字符".to_string());
    }
    let root = root_of(&path)?;
    let key = {
        let root2 = root.clone();
        tauri::async_runtime::spawn_blocking(move || {
            vault::create(&root2, &password, force)?;
            // 创建即解锁：直接建立会话（创建后立即可导入/上锁，无需再输一遍密码）
            let meta = store::read_meta(&root2)?;
            let key = store::derive_and_verify(&meta, &password)?;
            Ok::<VaultKey, String>(key)
        })
    }
    .await
    .map_err(|e| format!("任务执行失败: {e}"))??;
    let root2 = root_of(&path)?;
    state().lock().unwrap().sessions.insert(
        root2,
        Session { root, key, last_activity: Instant::now() },
    );
    Ok(())
}

/// 解锁并建立会话。返回 (文件数, 当前自动上锁秒数)。
#[tauri::command]
pub async fn vault_unlock(
    app: tauri::AppHandle,
    path: String,
    password: String,
) -> Result<(u32, u64), String> {
    let root = root_of(&path)?;
    {
        let mut s = state().lock().unwrap();
        if let Some(until) = s.fail_lock_until {
            if Instant::now() < until {
                let secs = (until - Instant::now()).as_secs() + 1;
                return Err(format!("尝试次数过多，请 {secs} 秒后再试"));
            }
            s.fail_lock_until = None;
            s.fail_count = 0;
        }
    }
    let app2 = app.clone();
    let root2 = root.clone();
    let res = tauri::async_runtime::spawn_blocking(move || {
        vault::unlock(&root2, &password, &|done, total| {
            let _ = app2.emit(
                "vault-progress",
                serde_json::json!({ "phase": "unlock", "done": done, "total": total }),
            );
        })
    })
    .await
    .map_err(|e| format!("任务执行失败: {e}"))?;
    match res {
        Ok((key, n)) => {
            let auto = {
                let mut s = state().lock().unwrap();
                s.fail_count = 0;
                s.fail_lock_until = None;
                // 多箱并存：同一路径重复解锁则刷新会话，不同路径各自独立
                s.sessions.insert(
                    root.clone(),
                    Session { root: root.clone(), key, last_activity: Instant::now() },
                );
                s.auto_lock_secs
            };
            Ok((n, auto))
        }
        Err(e) => {
            let mut s = state().lock().unwrap();
            s.fail_count += 1;
            if s.fail_count >= MAX_FAILS {
                s.fail_lock_until = Some(Instant::now() + Duration::from_secs(FAIL_LOCK_SECS));
                s.fail_count = 0;
            }
            Err(e)
        }
    }
}

/// 上锁：优先用现有会话；无会话（如程序重启后箱仍处于解锁态）则凭密码。
#[tauri::command]
pub async fn vault_lock(
    app: tauri::AppHandle,
    path: String,
    password: Option<String>,
) -> Result<vault::LockOutcome, String> {
    let root = root_of(&path)?;
    // 取会话（有则用密钥并摘除；无则用前端传来的密码）
    let session = state().lock().unwrap().sessions.remove(&root);
    let app2 = app.clone();
    let job = match &session {
        Some(sess) => {
            let root2 = sess.root.clone();
            let key = sess.key.clone();
            tauri::async_runtime::spawn_blocking(move || {
                vault::lock(&root2, &key, &|done, total| {
                    let _ = app2.emit(
                        "vault-progress",
                        serde_json::json!({ "phase": "lock", "done": done, "total": total }),
                    );
                })
            })
        }
        None => match password {
            Some(pw) if !pw.is_empty() => {
                let app3 = app2.clone();
                tauri::async_runtime::spawn_blocking(move || {
                    vault::lock_with_password(&root, &pw, &|done, total| {
                        let _ = app3.emit(
                            "vault-progress",
                            serde_json::json!({ "phase": "lock", "done": done, "total": total }),
                        );
                    })
                })
            }
            // 前端据该错误弹出密码框后带密码重试
            _ => {
                state().lock().unwrap().sessions.insert(root, session.unwrap());
                return Err("需要密码：当前没有该保险箱的解锁会话".to_string());
            }
        },
    };
    let outcome = job.await.map_err(|e| format!("任务执行失败: {e}"))?;
    match outcome {
        Ok(o) => Ok(o),
        Err(e) => {
            // 硬错误（journal/meta 损坏等）：恢复会话让用户可重试
            if let Some(sess) = session {
                state().lock().unwrap().sessions.insert(sess.root.clone(), sess);
            }
            Err(e)
        }
    }
}

#[tauri::command]
pub async fn vault_import(
    app: tauri::AppHandle,
    path: String,
    sources: Vec<String>,
) -> Result<u32, String> {
    let root = root_of(&path)?;
    let key = {
        let mut s = state().lock().unwrap();
        let sess = s.sessions.get_mut(&root).ok_or("尚未解锁（会话不存在）")?;
        sess.last_activity = Instant::now();
        sess.key.clone()
    };
    let app2 = app.clone();
    let root2 = root.clone();
    let n = tauri::async_runtime::spawn_blocking(move || {
        vault::import(&root2, &key, &sources, &|done, total| {
            let _ = app2.emit(
                "vault-progress",
                serde_json::json!({ "phase": "import", "done": done, "total": total }),
            );
        })
    })
    .await
    .map_err(|e| format!("任务执行失败: {e}"))??;
    Ok(n)
}

#[tauri::command]
pub async fn vault_list(path: String) -> Result<Vec<vault::FileRow>, String> {
    let root = root_of(&path)?;
    let r = tauri::async_runtime::spawn_blocking(move || vault::list_files(&root))
        .await
        .map_err(|e| format!("任务执行失败: {e}"))?;
    r
}

#[tauri::command]
pub async fn vault_dissolve(path: String) -> Result<(), String> {
    let root = root_of(&path)?;
    let session = state()
        .lock()
        .unwrap()
        .sessions
        .remove(&root)
        .ok_or("尚未解锁（会话不存在）")?;
    let root2 = root.clone();
    let key = session.key.clone();
    let res = tauri::async_runtime::spawn_blocking(move || vault::dissolve(&root2, &key))
        .await
        .map_err(|e| format!("任务执行失败: {e}"))?;
    if res.is_err() {
        // 恢复会话（箱还在）
        state().lock().unwrap().sessions.insert(root, session);
    }
    res
}

// ---------------------------------------------------------------------------
// 自动上锁（心跳/配置 + 供 watcher 调度）
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn vault_activity() -> bool {
    let mut s = state().lock().unwrap();
    let now = Instant::now();
    let any = !s.sessions.is_empty();
    for sess in s.sessions.values_mut() {
        sess.last_activity = now;
    }
    any
}

#[tauri::command]
pub fn set_auto_lock(seconds: u64) {
    state().lock().unwrap().auto_lock_secs = seconds;
}

#[tauri::command]
pub fn get_auto_lock() -> u64 {
    state().lock().unwrap().auto_lock_secs
}

#[tauri::command]
pub fn idle_seconds() -> u64 {
    let s = state().lock().unwrap();
    s.sessions
        .values()
        .map(|sess| sess.last_activity.elapsed().as_secs())
        .min()
        .unwrap_or(u64::MAX)
}

/// watcher 线程每 5 秒调用：空闲超时的会话逐个上锁。返回本次已上锁的路径列表。
/// 运行在独立线程，不阻塞主线程/UI。
pub fn auto_lock_tick() -> Vec<String> {
    let threshold = state().lock().unwrap().auto_lock_secs;
    if threshold == 0 {
        return Vec::new();
    }
    let due: Vec<(PathBuf, VaultKey)> = {
        let s = state().lock().unwrap();
        s.sessions
            .values()
            .filter(|sess| sess.last_activity.elapsed().as_secs() >= threshold)
            .map(|sess| (sess.root.clone(), sess.key.clone()))
            .collect()
    };
    let mut locked = Vec::new();
    for (root, key) in due {
        match vault::lock(&root, &key, &|_, _| {}) {
            Ok(_) => {
                state().lock().unwrap().sessions.remove(&root);
                locked.push(root.to_string_lossy().to_string());
            }
            Err(_) => {
                // 失败退避：刷新该会话活动时间，下个周期再试
                if let Some(sess) = state().lock().unwrap().sessions.get_mut(&root) {
                    sess.last_activity = Instant::now();
                }
            }
        }
    }
    locked
}

/// 退出收尾：上锁全部会话（容错语义——占用文件保持明文）。返回上锁失败列表。
pub fn lock_all_for_exit() -> Vec<String> {
    let sessions: Vec<(PathBuf, VaultKey)> = {
        let mut s = state().lock().unwrap();
        s.sessions.drain().map(|(_, sess)| (sess.root, sess.key)).collect()
    };
    let mut failed = Vec::new();
    for (root, key) in sessions {
        match vault::lock(&root, &key, &|_, _| {}) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("[vaultbox] 退出上锁失败 {}: {e}", root.display());
                failed.push(root.to_string_lossy().to_string());
            }
        }
    }
    failed
}

/// 强制退出（「锁受阻」弹窗中选择仍要退出时调用）
#[tauri::command]
pub fn force_exit() {
    std::process::exit(0);
}

// ---------------------------------------------------------------------------
// 快速隐藏命令
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn hide_toggle(path: String) -> Result<hide::HideResult, String> {
    let path = root_of(&path)?;
    let r = tauri::async_runtime::spawn_blocking(move || hide::toggle(&path))
        .await
        .map_err(|e| format!("任务执行失败: {e}"))?;
    r
}

#[tauri::command]
pub fn hide_is_hidden(path: String) -> Result<bool, String> {
    hide::is_hidden(&root_of(&path)?)
}

#[tauri::command]
pub async fn hide_list_dir(path: String) -> Result<Vec<hide::HideResult>, String> {
    let path = root_of(&path)?;
    let r = tauri::async_runtime::spawn_blocking(move || hide::list_dir_state(&path))
        .await
        .map_err(|e| format!("任务执行失败: {e}"))?;
    r
}

// ---------------------------------------------------------------------------
// 杂项
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn vault_meta_info(path: String) -> Result<serde_json::Value, String> {
    let root = root_of(&path)?;
    if !store::is_vault(&root) {
        return Err("不是保险箱".to_string());
    }
    let meta = store::read_meta(&root)?;
    Ok(serde_json::json!({
        "version": meta.version,
        "created_at": meta.created_at,
        "argon2": { "m_kib": meta.argon2.m_kib, "t": meta.argon2.t, "p": meta.argon2.p },
    }))
}

#[tauri::command]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_path_rejected() {
        assert!(root_of("").is_err());
    }
}
