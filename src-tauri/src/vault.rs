//! 保险箱生命周期编排：创建 / 解锁 / 上锁 / 导入 / 崩溃恢复。
//!
//! 各批次的事务顺序（配合 store::Journal 保证崩溃安全）：
//!
//! - **unlock**：验密 → 恢复残留批次（若有）→ 写 journal → 按索引把 blob
//!   解密回明文树（幂等覆盖）→ 清 journal。
//!   中断恢复：重跑一遍即可（解密覆盖是幂等的）。
//! - **lock**：写 journal → 遍历明文树：新文件/改动文件重新加密成新 blob，
//!   未改动的复用旧 blob，用户删除的条目移出索引 → 写 index.enc →
//!   清空明文树 → 清理无引用 blob → 清 journal。
//!   中断恢复：无论断在哪一步，重新执行一遍 lock 都收敛到一致状态
//!   （明文树是输入，索引与 blob 是输出）。
//! - **import**：逐文件加密成 blob（先不入索引）→ 全部完成后一次性写索引。
//!   中断恢复：多出的 blob 无索引引用 → GC 清掉即可。

use crate::crypto::VaultKey;
use crate::store::{
    self, FileEntry, Journal, VaultIndex, data_dir, is_vault, normalize_rel, read_index,
    read_journal, read_meta, shred_file, write_index, write_journal,
};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use walkdir::WalkDir;

/// 库内相对路径 → 磁盘明文绝对路径
fn plain_path(root: &Path, rel: &str) -> PathBuf {
    root.join(rel.replace('/', &std::path::MAIN_SEPARATOR.to_string()))
}

fn mtime_ms_of(path: &Path) -> u64 {
    path.metadata()
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 上锁结果：busy = 因被占用暂未加密（保持明文）的文件数
#[derive(serde::Serialize, Clone, Copy, Debug)]
pub struct LockOutcome {
    pub handled: u32,
    pub resealed_bytes: u64,
    pub busy: u32,
}

/// 供前端展示的文件行
#[derive(serde::Serialize, Clone, Debug)]
pub struct FileRow {
    pub path: String,
    pub size: u64,
    pub mtime_ms: u64,
    pub is_dir: bool,
}

// ---------------------------------------------------------------------------
// 创建
// ---------------------------------------------------------------------------

/// 把 root 变成保险箱。要求目录存在；若目录非空则要求 force=true（非空内容
/// 将在首次上锁时一并加密收纳）。
pub fn create(root: &Path, password: &str, force: bool) -> Result<(), String> {
    if is_vault(root) {
        return Err("该文件夹已经是保险箱".to_string());
    }
    if !root.is_dir() {
        return Err("文件夹不存在".to_string());
    }
    let non_vault_entries = fs::read_dir(root)
        .map_err(|e| format!("读取目录失败: {e}"))?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy() != store::DIR_NAME)
        .count();
    if non_vault_entries > 0 && !force {
        return Err("文件夹非空：继续会把现有内容一并纳入加密（重试并确认）".to_string());
    }
    // 注意：meta 的盐必须是随机的，与密码派生一致；create_meta 内部生成盐，
    // 但密钥派生也需要同一盐 —— 所以这里先生成盐、派生密钥、再写 meta。
    let salt = VaultKey::random_salt();
    let key = VaultKey::derive(password, &salt)?;
    store::create_meta_with_salt(root, &key, &salt)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 解锁 / 恢复
// ---------------------------------------------------------------------------

/// 解锁：验密 → 恢复残留批次 → 明文树物化。返回 (密钥, 文件数)。
/// 密钥由 commands 层在会话期持有（自动上锁时 zeroize 释放）。
pub fn unlock(root: &Path, password: &str, progress: &dyn Fn(usize, usize)) -> Result<(VaultKey, u32), String> {
    let meta = read_meta(root)?;
    let key = store::derive_and_verify(&meta, password)?;

    if let Some(j) = read_journal(root) {
        recover(root, &key, &j)?;
    }

    let mut index = read_index(root, &key)?;
    let rels: Vec<String> = index.files.keys().cloned().collect();
    write_journal(root, &Journal::new("unlock", rels, Vec::new()))?;

    let mut count = 0u32;
    let total = index.files.len();
    progress(0, total);
    for (i, (rel, entry)) in index.files.iter().enumerate() {
        let target = plain_path(root, rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("创建目录失败: {e}"))?;
        }
        // 幂等：已存在且大小一致时跳过（上次解锁中断的重跑会快很多）
        if let Ok(m) = target.metadata() {
            if m.len() == entry.size {
                count += 1;
                progress(i + 1, total);
                continue;
            }
        }
        key.open_file(&data_dir(root).join(&entry.blob), &target)
            .map_err(|e| format!("还原 {rel} 失败: {e}"))?;
        count += 1;
        progress(i + 1, total);
    }
    // 重建空目录（索引里记录的 dirs）
    for d in &index.dirs {
        let _ = fs::create_dir_all(plain_path(root, d));
    }

    store::clear_journal(root);
    Ok((key, count))
}

/// 残留批次恢复（需要先验密拿到 key）
fn recover(root: &Path, key: &VaultKey, j: &Journal) -> Result<(), String> {
    match j.kind.as_str() {
        // 解锁/导入中断：明文树可能不完整/多出无引用 blob → GC 兜底，下次 unlock/lock 收敛
        "unlock" | "import" => {
            gc_blobs(root, key)?;
            store::clear_journal(root);
            Ok(())
        }
        // 上锁中断：无论断在哪，重跑一遍 lock 语义（明文树为输入）即可收敛
        "lock" => {
            // 但前提是明文树还在；若已被清空且索引已写，就是已完成态
            let index = read_index(root, key)?;
            let plain_files = walk_plain_files(root)?;
            if plain_files.is_empty() {
                gc_blobs(root, key)?;
                store::clear_journal(root);
                return Ok(());
            }
            // 明文还在 → 完整重跑上锁
let _ = do_lock(root, key, &index, &|_, _| {})?;
            Ok(())
        }
        other => Err(format!("未知批次类型：{other}（元数据损坏）")),
    }
}

/// 删除 data/ 下未被索引引用的 blob
fn gc_blobs(root: &Path, key: &VaultKey) -> Result<u32, String> {
    let index = read_index(root, key)?;
    let referenced: BTreeSet<&String> = index.files.values().map(|e| &e.blob).collect();
    let mut removed = 0u32;
    if let Ok(entries) = fs::read_dir(data_dir(root)) {
        for e in entries.filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().to_string();
            if name.ends_with(".tmp-write") {
                let _ = fs::remove_file(e.path());
                continue;
            }
            if !referenced.contains(&name) {
                let _ = shred_file(&e.path());
                removed += 1;
            }
        }
    }
    Ok(removed)
}

// ---------------------------------------------------------------------------
// 上锁
// ---------------------------------------------------------------------------

/// 上锁（要求当前处于解锁态：明文树存在）。
/// 容错语义：被占用的文件（如正在运行的游戏）跳过删除、保持明文，
/// 其余照常加密；结果里的 busy 报告跳过数，下次上锁自动补齐。
pub fn lock(root: &Path, key: &VaultKey, progress: &dyn Fn(usize, usize)) -> Result<LockOutcome, String> {
    if let Some(j) = read_journal(root) {
        recover(root, key, &j)?;
    }
    let index = read_index(root, key)?;
    do_lock(root, key, &index, progress)
}

/// 无会话时的上锁：凭密码派生密钥（程序重启后箱仍处于解锁态时走这条路）
pub fn lock_with_password(root: &Path, password: &str, progress: &dyn Fn(usize, usize)) -> Result<LockOutcome, String> {
    let meta = read_meta(root)?;
    let key = store::derive_and_verify(&meta, password)?;
    lock(root, &key, progress)
}

fn do_lock(root: &Path, key: &VaultKey, old_index: &VaultIndex, progress: &dyn Fn(usize, usize)) -> Result<LockOutcome, String> {
    let plain = walk_plain_files(root)?;

    let rels: Vec<String> = plain.iter().map(|p| p.rel.clone()).collect();
    let blobs: Vec<String> = old_index.files.values().map(|e| e.blob.clone()).collect();
    write_journal(root, &Journal::new("lock", rels, blobs))?;

    let mut new_index = VaultIndex::default();
    let mut resealed_bytes: u64 = 0;
    let mut handled: u32 = 0;
    let mut busy: u32 = 0;
    let mut unsealable: BTreeSet<String> = BTreeSet::new();

    let total = plain.len();
    progress(0, total);
    for (i, item) in plain.iter().enumerate() {
        let abs = &item.abs;
        let old = old_index.files.get(&item.rel);
        let unchanged = old.map(|e| e.size == item.size && e.mtime_ms == item.mtime_ms);
        let blob = match (old, unchanged) {
            (Some(e), Some(true)) => Some(e.blob.clone()),
            _ => {
                // 新文件或已改动：重新加密（新 blob 名，避免与旧密文混淆）。
                // 加密失败（文件被独占，如游戏运行中）→ 容错：保持明文、不进索引，
                // 计入 busy；残留的半截 blob 由末尾 GC 清理，下次上锁视为新文件重试。
                let name = VaultKey::random_blob_name();
                let target = data_dir(root).join(&name);
                match key.seal_file(abs, &target) {
                    Ok(sealed_size) => {
                        resealed_bytes += sealed_size;
                        Some(name)
                    }
                    Err(_) => {
                        busy += 1;
                        unsealable.insert(item.rel.clone());
                        let _ = fs::remove_file(&target);
                        None
                    }
                }
            }
        };
        match blob {
            Some(blob) => {
                new_index.files.insert(
                    item.rel.clone(),
                    FileEntry { blob, size: item.size, mtime_ms: item.mtime_ms },
                );
                handled += 1;
        progress(i + 1, total);
            }
            None => {
                // 无法加密的文件留在明文树中（下次上锁重试）
                new_index.files.remove(&item.rel);
            }
        }
    }

    // 记录当前目录结构（含空目录），解锁时重建
    new_index.dirs = walk_plain_dirs(root)?;

    // 先写索引（此后索引即权威），再清明文。
    // 删除容错：被占用的文件（游戏运行中/编辑器打开）跳过、保持明文，
    // 条目保留在索引（密文已在库），下次上锁检测到未变 → 直接重试删除。
    new_index.updated_ms = VaultIndex::now_ms();
    write_index(root, key, &new_index)?;

    for item in &plain {
        if unsealable.contains(&item.rel) {
            continue; // 加密阶段已计数：文件按设计保持明文，下次上锁重试
        }
        if shred_file(&item.abs).is_err() {
            busy += 1;
        }
    }
    // 删除明文目录树（从深到浅），但保留 root 与 .vaultbox
    for d in new_index.dirs.iter().rev() {
        let _ = fs::remove_dir(plain_path(root, d)); // 仅空目录可删，失败忽略
    }

    // GC：清掉旧索引引用、新索引不再引用的 blob
    let referenced: BTreeSet<&String> = new_index.files.values().map(|e| &e.blob).collect();
    if let Ok(entries) = fs::read_dir(data_dir(root)) {
        for e in entries.filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().to_string();
            if !referenced.contains(&name) && !name.ends_with(".tmp-write") {
                let _ = shred_file(&e.path());
            }
        }
    }

    store::clear_journal(root);
    Ok(LockOutcome { handled, resealed_bytes, busy })
}

// ---------------------------------------------------------------------------
// 明文树枚举
// ---------------------------------------------------------------------------

struct PlainFile {
    rel: String,
    abs: PathBuf,
    size: u64,
    mtime_ms: u64,
}

/// 枚举明文树中的所有文件（跳过 .vaultbox、跳过符号链接）
fn walk_plain_files(root: &Path) -> Result<Vec<PlainFile>, String> {
    let mut out = Vec::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            name != store::DIR_NAME
        })
    {
        let entry = entry.map_err(|e| format!("遍历目录失败: {e}"))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(root)
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        let rel = normalize_rel(&rel)?;
        let meta = entry.metadata().map_err(|e| e.to_string())?;
        out.push(PlainFile {
            rel,
            abs: entry.path().to_path_buf(),
            size: meta.len(),
            mtime_ms: mtime_ms_of(entry.path()),
        });
    }
    Ok(out)
}

/// 枚举明文树中的目录（相对路径，父目录在前；用于解锁重建与上锁清理）
fn walk_plain_dirs(root: &Path) -> Result<Vec<String>, String> {
    let mut dirs: Vec<String> = Vec::new();
    for entry in WalkDir::new(root)
        .min_depth(1)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            name != store::DIR_NAME
        })
    {
        let entry = entry.map_err(|e| format!("遍历目录失败: {e}"))?;
        if !entry.file_type().is_dir() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(root)
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        if let Ok(norm) = normalize_rel(&rel) {
            dirs.push(norm);
        }
    }
    // WalkDir 默认深度优先父在前；排序保证父目录在前（浅路径先）
    dirs.sort_by_key(|d| d.matches('/').count() * 10000 + d.len());
    Ok(dirs)
}

// ---------------------------------------------------------------------------
// 导入 / 列表 / 状态
// ---------------------------------------------------------------------------

/// 导入（解锁态）：把外部文件/文件夹复制进明文树并立即加密成 blob。
/// 复制（保留原件）。返回导入文件数。
pub fn import(root: &Path, key: &VaultKey, sources: &[String], progress: &dyn Fn(usize, usize)) -> Result<u32, String> {
    if let Some(j) = read_journal(root) {
        recover(root, key, &j)?;
    }
    let mut index = read_index(root, &key)?;
    // 先枚举全部待导入文件（total 已知才能显示进度）
    let mut jobs: Vec<(String, PathBuf)> = Vec::new();
    for src in sources {
        let src = PathBuf::from(src);
        if !src.exists() {
            return Err(format!("源不存在：{}", src.display()));
        }
        let base_name = src
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .ok_or("源路径无文件名")?;
        if src.is_dir() {
            for entry in WalkDir::new(&src).follow_links(false).into_iter().filter_map(|e| e.ok()) {
                if !entry.file_type().is_file() {
                    continue;
                }
                let sub = entry
                    .path()
                    .strip_prefix(&src)
                    .map_err(|e| e.to_string())?
                    .to_string_lossy()
                    .replace('\\', "/");
                let rel = normalize_rel(&format!("{base_name}/{sub}"))?;
                jobs.push((rel, entry.path().to_path_buf()));
            }
        } else {
            let rel = normalize_rel(&base_name)?;
            jobs.push((rel, src));
        }
    }

    let total = jobs.len();
    progress(0, total);
    let mut imported: Vec<(String, String)> = Vec::new(); // (rel, blob)
    for (i, (rel, src_abs)) in jobs.iter().enumerate() {
        imported.push(import_one(root, key, &mut index, rel, src_abs)?);
        progress(i + 1, total);
    }

    write_journal(root, &Journal::new("import", Vec::new(), imported.iter().map(|(_, b)| b.clone()).collect()))?;
    index.dirs = walk_plain_dirs(root)?;
    index.updated_ms = VaultIndex::now_ms();
    write_index(root, key, &index)?;
    store::clear_journal(root);
    Ok(imported.len() as u32)
}

fn import_one(
    root: &Path,
    key: &VaultKey,
    index: &mut VaultIndex,
    rel: &str,
    src_abs: &Path,
) -> Result<(String, String), String> {
    // 1) 加密入库（新 blob；若覆盖同名旧文件，旧 blob 由上锁 GC 清理）
    let blob = VaultKey::random_blob_name();
    key.seal_file(src_abs, &data_dir(root).join(&blob))?;
    // 2) 复制明文进树（解锁态一致性）
    let target = plain_path(root, rel);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("创建目录失败: {e}"))?;
    }
    fs::copy(src_abs, &target).map_err(|e| format!("复制 {rel} 失败: {e}"))?;
    let size = fs::metadata(&target).map_err(|e| e.to_string())?.len();
    index.files.insert(
        rel.to_string(),
        FileEntry { blob: blob.clone(), size, mtime_ms: mtime_ms_of(&target) },
    );
    Ok((rel.to_string(), blob))
}

/// 磁盘状态（无需密码）
#[derive(serde::Serialize)]
pub struct VaultStatus {
    pub is_vault: bool,
    /// 明文树是否存在文件（存在 = 处于解锁态）
    pub unlocked: bool,
    pub file_count: u32,
    pub total_size: u64,
    pub has_journal: bool,
    pub meta_error: Option<String>,
}

pub fn status(root: &Path) -> VaultStatus {
    if !is_vault(root) {
        return VaultStatus {
            is_vault: false,
            unlocked: false,
            file_count: 0,
            total_size: 0,
            has_journal: false,
            meta_error: None,
        };
    }
    let (unlocked, file_count, total_size) = match walk_plain_files(root) {
        Ok(files) if !files.is_empty() => (true, files.len() as u32, files.iter().map(|f| f.size).sum()),
        _ => (false, 0, 0), // 空树或遍历失败（状态查询容错，不致命）
    };
    VaultStatus {
        is_vault: true,
        unlocked,
        file_count,
        total_size,
        has_journal: read_journal(root).is_some(),
        meta_error: read_meta(root).err(),
    }
}

/// 解锁态下的文件列表（无需密码；数据本就明文可见）
pub fn list_files(root: &Path) -> Result<Vec<FileRow>, String> {
    let mut rows: Vec<FileRow> = Vec::new();
    for d in walk_plain_dirs(root)? {
        rows.push(FileRow { path: d, size: 0, mtime_ms: 0, is_dir: true });
    }
    for item in walk_plain_files(root)? {
        rows.push(FileRow { path: item.rel, size: item.size, mtime_ms: item.mtime_ms, is_dir: false });
    }
    Ok(rows)
}

/// 彻底删除保险箱（解锁态，仅当明文树存在）：不删除任何明文，只移除 .vaultbox。
/// 调用方需先确认用户已把文件转移完毕。
pub fn dissolve(root: &Path, key: &VaultKey) -> Result<(), String> {
    let index = read_index(root, key)?;
    let blob_count = fs::read_dir(data_dir(root)).map(|d| d.filter_map(|e| e.ok()).count()).unwrap_or(0);
    if !index.files.is_empty() || blob_count > 0 {
        return Err("箱内还有加密数据：请先解锁并取出全部文件（删除明文后上锁），再移除保险箱".to_string());
    }
    fs::remove_dir_all(store::vault_dir(root)).map_err(|e| format!("删除保险箱结构失败: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const PW: &str = "测试密码123";

    /// 建箱并放入初始内容（解锁→写明文→上锁），返回 (临时目录, 箱路径)
    fn make_vault_with(files: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("箱");
        fs::create_dir_all(&root).unwrap();
        create(&root, PW, false).unwrap();
        let (key, _) = unlock(&root, PW, &|_, _| {}).unwrap();
        for (rel, content) in files {
            let p = plain_path(&root, rel);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&p, content).unwrap();
        }
        lock(&root, &key, &|_, _| {}).unwrap();
        (dir, root)
    }

    /// 解锁 → 操作明文 → 上锁 的一体化小工具
    fn with_unlocked(root: &Path, f: impl FnOnce(&Path)) {
        let (key, _) = unlock(root, PW, &|_, _| {}).unwrap();
        f(root);
        lock(root, &key, &|_, _| {}).unwrap();
    }

    fn disk_has_plaintext(root: &Path) -> bool {
        walk_plain_files(root).map(|v| !v.is_empty()).unwrap_or(false)
    }

    fn data_blob_names(root: &Path) -> Vec<String> {
        fs::read_dir(data_dir(root))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".bin"))
            .collect()
    }

    #[test]
    fn full_cycle_mixed_content() {
        let (_guard, root) = make_vault_with(&[
            ("工资.xlsx", "fake-xlsx-bytes"),
            ("合同/2026劳动合同.docx", "中文内容 合同内容"),
            ("合同/扫描件/deep.bin", "nested binary"),
            ("空目录占位.txt", ""),
        ]);
        assert!(!disk_has_plaintext(&root), "上锁后不应有明文");
        let blobs = data_blob_names(&root);
        assert_eq!(blobs.len(), 4);
        assert!(!blobs.join(" ").contains("合同"), "blob 名不应含原名");

        with_unlocked(&root, |r| {
            assert_eq!(
                fs::read_to_string(plain_path(r, "合同/2026劳动合同.docx")).unwrap(),
                "中文内容 合同内容"
            );
        });
        assert!(!disk_has_plaintext(&root));
    }

    #[test]
    fn wrong_password_cannot_unlock() {
        let (_guard, root) = make_vault_with(&[("a.txt", "x")]);
        assert!(unlock(&root, "错误密码", &|_, _| {}).is_err());
    }

    #[test]
    fn unchanged_files_reuse_blob() {
        let (_guard, root) = make_vault_with(&[
            ("大文件不动.bin", &"A".repeat(3000)),
            ("小文件会改.txt", "v1"),
        ]);
        let before = data_blob_names(&root).len();
        with_unlocked(&root, |r| {
            fs::write(plain_path(r, "小文件会改.txt"), "v2 改过了").unwrap();
        });
        let after = data_blob_names(&root);
        assert_eq!(after.len(), before, "未改动的文件应复用旧 blob");
        with_unlocked(&root, |r| {
            assert_eq!(fs::read_to_string(plain_path(r, "小文件会改.txt")).unwrap(), "v2 改过了");
        });
    }

    #[test]
    fn user_deletes_file_while_unlocked() {
        let (_guard, root) = make_vault_with(&[("要删的.txt", "x"), ("留着的.txt", "y")]);
        with_unlocked(&root, |r| {
            fs::remove_file(plain_path(r, "要删的.txt")).unwrap();
        });
        with_unlocked(&root, |r| {
            assert!(!plain_path(r, "要删的.txt").exists());
            assert!(plain_path(r, "留着的.txt").exists());
        });
        assert_eq!(data_blob_names(&root).len(), 1, "被删文件的 blob 应被清理");
    }

    #[test]
    fn import_and_lock() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("箱");
        fs::create_dir_all(&root).unwrap();
        create(&root, PW, false).unwrap();
        let (key, _) = unlock(&root, PW, &|_, _| {}).unwrap();

        let src = dir.path().join("外部资料");
        fs::create_dir_all(src.join("子目录")).unwrap();
        fs::write(src.join("子目录/资料.txt"), "导入内容").unwrap();
        fs::write(src.join("根文件.md"), "# md").unwrap();

        let n = import(&root, &key, &[src.to_string_lossy().to_string()], &|_, _| {}).unwrap();
        assert_eq!(n, 2);
        assert!(plain_path(&root, "外部资料/子目录/资料.txt").exists());

        lock(&root, &key, &|_, _| {}).unwrap();
        assert!(!disk_has_plaintext(&root));
        let (key2, _) = unlock(&root, PW, &|_, _| {}).unwrap();
        assert_eq!(
            fs::read_to_string(plain_path(&root, "外部资料/子目录/资料.txt")).unwrap(),
            "导入内容"
        );
        let _ = key2;
    }

    #[test]
    fn crash_during_lock_recovers() {
        let (_guard, root) = make_vault_with(&[("a.txt", "aaa"), ("b.txt", "bbb")]);
        // 模拟上锁中途崩溃：残留 journal
        let (key, _) = unlock(&root, PW, &|_, _| {}).unwrap();
        write_journal(&root, &Journal::new("lock", vec!["a.txt".into(), "b.txt".into()], vec![])).unwrap();
        // 下一次解锁触发恢复（明文树还在 → 重跑上锁语义）
        let _ = key;
        let (key2, _) = unlock(&root, PW, &|_, _| {}).unwrap();
        assert!(read_journal(&root).is_none());
        assert!(plain_path(&root, "a.txt").exists());
        lock(&root, &key2, &|_, _| {}).unwrap();
        assert!(!disk_has_plaintext(&root));
    }

    #[test]
    fn crash_during_import_gc_blobs() {
        let (_guard, root) = make_vault_with(&[("a.txt", "aaa")]);
        let (key, _) = unlock(&root, PW, &|_, _| {}).unwrap();
        let orphan = data_dir(&root).join(VaultKey::random_blob_name());
        fs::write(&orphan, b"garbage").unwrap();
        write_journal(&root, &Journal::new("import", vec![], vec![])).unwrap();
        lock(&root, &key, &|_, _| {}).unwrap();
        assert!(!orphan.exists(), "无引用 blob 应被 GC");
        assert_eq!(data_blob_names(&root).len(), 1);
    }

    #[test]
    fn empty_dir_survives_cycle() {
        let (_guard, root) = make_vault_with(&[("占位.txt", "x")]);
        with_unlocked(&root, |r| {
            fs::create_dir_all(plain_path(r, "空目录/更深")).unwrap();
        });
        with_unlocked(&root, |r| {
            assert!(plain_path(r, "空目录/更深").is_dir(), "空目录应跨加解锁保留");
        });
    }

    #[test]
    fn create_nonempty_requires_force() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("箱");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("已有.txt"), "x").unwrap();
        assert!(create(&root, PW, false).is_err());
        create(&root, PW, true).unwrap();
        with_unlocked(&root, |r| {
            assert!(plain_path(r, "已有.txt").exists());
        });
    }

    #[test]
    fn busy_file_tolerated_during_lock() {
        // Windows 上以独占方式打开的文件无法删除 —— 模拟“游戏正在运行”：
        // 上锁应容错跳过该文件（busy=1），其余文件正常加密，且不卡死后续解锁。
        let (_guard, root) = make_vault_with(&[("正常.txt", "ok"), ("游戏/exe主程序.exe", "GAME")]);
        let (key, _) = unlock(&root, PW, &|_, _| {}).unwrap();
        let busy = root.join("游戏/exe主程序.exe");
        // 独占打开（share_mode=0：不允许删除）
        use std::os::windows::fs::OpenOptionsExt;
        let _held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&busy)
            .expect("独占打开失败（测试环境异常）");
        let outcome = lock(&root, &key, &|_, _| {}).unwrap();
        assert_eq!(outcome.busy, 1, "占用文件应被跳过计数");
        assert!(busy.exists(), "被占用文件保持明文");
        assert!(!plain_path(&root, "正常.txt").exists(), "其余文件正常加密");
        drop(_held);
        // 关闭占用后再次上锁：补齐删除，全部入箱
        let (key2, _) = unlock(&root, PW, &|_, _| {}).unwrap();
        let out2 = lock(&root, &key2, &|_, _| {}).unwrap();
        assert_eq!(out2.busy, 0);
        assert!(!disk_has_plaintext(&root));
        // 数据完好
        let (key3, _) = unlock(&root, PW, &|_, _| {}).unwrap();
        assert_eq!(fs::read(plain_path(&root, "游戏/exe主程序.exe")).unwrap(), b"GAME");
        let _ = key3;
    }

    #[test]
    fn large_file_streaming_roundtrip() {
        // ~3MB：跨越多个 512KiB 分块
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("箱");
        fs::create_dir_all(&root).unwrap();
        create(&root, PW, false).unwrap();
        let (key, _) = unlock(&root, PW, &|_, _| {}).unwrap();
        let big_path = plain_path(&root, "大文件.bin");
        {
            let mut f = fs::File::create(&big_path).unwrap();
            let chunk = vec![0xABu8; 1024 * 1024];
            for i in 0..3 {
                let mut c = chunk.clone();
                c[0] = i as u8; // 每兆首字节不同，防内容重复被误判
                f.write_all(&c).unwrap();
            }
        }
        let expect = fs::read(&big_path).unwrap();
        lock(&root, &key, &|_, _| {}).unwrap();
        assert!(!disk_has_plaintext(&root));
        let (key2, _) = unlock(&root, PW, &|_, _| {}).unwrap();
        assert_eq!(fs::read(&big_path).unwrap(), expect, "3MB 文件逐字节一致");
        let _ = key2;
    }
}
