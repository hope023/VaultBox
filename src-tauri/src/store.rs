//! VaultBox 磁盘格式与保险箱状态管理。
//!
//! 保险箱目录结构：
//! ```text
//! <vault>/
//!   .vaultbox/
//!     meta.json        明文头：版本、盐、Argon2 参数、验证块
//!     index.enc        加密索引（原文件树 → blob 映射）
//!     journal.json     明文操作日志：进行中的批次，用于崩溃恢复
//!     data/
//!       <hex>.bin      逐文件密文（随机名，与原名无关）
//!   <你的文件...>       解锁期间存在的明文树（上锁后清空）
//! ```
//!
//! 状态机：`Locked`（磁盘只有密文）⇄ `Unlocked`（明文树存在，密钥在内存）。
//! journal 在每个多步批次（解锁/上锁/导入）开始时写、成功后删；
//! 下次任何操作前若发现残留 journal，先执行恢复（把半成品收尾到一致状态）。

use crate::crypto::{Argon2Params, VaultKey, VaultMeta, SALT_LEN};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DIR_NAME: &str = ".vaultbox";
const META_FILE: &str = "meta.json";
const INDEX_FILE: &str = "index.enc";
const JOURNAL_FILE: &str = "journal.json";
const DATA_DIR: &str = "data";
const INDEX_MAGIC: &[u8] = b"VBIDX1\n";

// ---------------------------------------------------------------------------
// 索引
// ---------------------------------------------------------------------------

/// 单文件条目：库内相对路径（正斜杠）→ blob 映射与元数据
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FileEntry {
    /// 密文文件名（data/ 下），不含路径
    pub blob: String,
    /// 明文大小（字节）
    pub size: u64,
    /// 修改时间（UNIX 毫秒）—— 上锁时用它判断文件是否被改过（未改的 blob 直接复用）
    pub mtime_ms: u64,
}

/// 加密索引：解锁/上锁后写入 index.enc 的内容（整体先 seal_bytes 再落盘）
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct VaultIndex {
    /// 相对路径（"合同/2026.docx"）→ 条目
    pub files: BTreeMap<String, FileEntry>,
    /// 空目录保留清单（相对路径，父在前）
    pub dirs: Vec<String>,
    /// 索引写入时间（UNIX 毫秒）
    pub updated_ms: u64,
}

impl VaultIndex {
    pub fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// journal（崩溃恢复）
// ---------------------------------------------------------------------------

/// 进行中的批次记录（明文，不含敏感信息——路径只出现在解锁批次，而解锁批次
/// 存在期间明文本就在盘上，无额外泄露）
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Journal {
    /// 批次种类：unlock / lock / import
    pub kind: String,
    /// 批次涉及的明文相对路径列表（恢复时按需重做/清理）
    pub paths: Vec<String>,
    /// 批次涉及的 blob 名列表
    pub blobs: Vec<String>,
    pub started_ms: u64,
}

impl Journal {
    pub fn new(kind: &str, paths: Vec<String>, blobs: Vec<String>) -> Self {
        Self { kind: kind.into(), paths, blobs, started_ms: VaultIndex::now_ms() }
    }
}

// ---------------------------------------------------------------------------
// 路径工具
// ---------------------------------------------------------------------------

pub fn vault_dir(root: &Path) -> PathBuf {
    root.join(DIR_NAME)
}
pub fn meta_path(root: &Path) -> PathBuf {
    vault_dir(root).join(META_FILE)
}
pub fn index_path(root: &Path) -> PathBuf {
    vault_dir(root).join(INDEX_FILE)
}
pub fn journal_path(root: &Path) -> PathBuf {
    vault_dir(root).join(JOURNAL_FILE)
}
pub fn data_dir(root: &Path) -> PathBuf {
    vault_dir(root).join(DATA_DIR)
}

/// 判断一个文件夹是否已是保险箱
pub fn is_vault(root: &Path) -> bool {
    meta_path(root).is_file() && index_path(root).is_file()
}

/// 相对路径规范化：正斜杠、拒绝 .. 与绝对路径、禁止以 .vaultbox 开头
pub fn normalize_rel(rel: &str) -> Result<String, String> {
    if rel.is_empty() {
        return Err("路径为空".to_string());
    }
    let normalized = rel.replace('\\', "/");
    if Path::new(&normalized).is_absolute() || normalized.starts_with('/') {
        return Err(format!("必须是库内相对路径：{rel}"));
    }
    for part in normalized.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(format!("路径段非法（{part}）：{rel}"));
        }
        if part.contains(':') || part.chars().any(|c| c.is_control()) {
            return Err(format!("路径含非法字符：{rel}"));
        }
    }
    if normalized == DIR_NAME || normalized.starts_with(&format!("{DIR_NAME}/")) {
        return Err("不允许操作 .vaultbox 内部结构".to_string());
    }
    Ok(normalized)
}

// ---------------------------------------------------------------------------
// meta / index / journal 读写
// ---------------------------------------------------------------------------

/// 创建保险箱骨架。盐由调用方生成（密钥必须派生自同一盐）。
pub fn create_meta_with_salt(root: &Path, key: &VaultKey, salt: &[u8]) -> Result<VaultMeta, String> {
    let vdir = vault_dir(root);
    fs::create_dir_all(&vdir).map_err(|e| format!("创建 {} 失败: {e}", vdir.display()))?;
    fs::create_dir_all(data_dir(root)).map_err(|e| format!("创建数据目录失败: {e}"))?;
    if meta_path(root).exists() {
        return Err("该文件夹已是保险箱".to_string());
    }
    let meta = VaultMeta {
        version: 1,
        salt_hex: hex::encode(salt),
        argon2: Argon2Params::default(),
        check_block_hex: hex::encode(key.make_check_block()),
        created_at: chrono_like_now(),
    };
    write_meta(root, &meta)?;
    // 空索引
    write_index(root, key, &VaultIndex::default())?;
    Ok(meta)
}

fn chrono_like_now() -> String {
    let ms = VaultIndex::now_ms();
    format!("unix-ms:{ms}")
}

pub fn write_meta(root: &Path, meta: &VaultMeta) -> Result<(), String> {
    let json = serde_json::to_string_pretty(meta).map_err(|e| e.to_string())?;
    atomic_write(&meta_path(root), json.as_bytes())
}

pub fn read_meta(root: &Path) -> Result<VaultMeta, String> {
    let raw = fs::read_to_string(meta_path(root))
        .map_err(|_| "不是保险箱（缺少 meta.json）".to_string())?;
    serde_json::from_str(&raw).map_err(|e| format!("meta.json 损坏: {e}"))
}

/// 由 meta 派生密钥并校验（解锁入口）
pub fn derive_and_verify(meta: &VaultMeta, password: &str) -> Result<VaultKey, String> {
    let salt = hex::decode(&meta.salt_hex).map_err(|_| "盐数据损坏".to_string())?;
    if salt.len() != SALT_LEN {
        return Err("盐数据损坏".to_string());
    }
    let key = VaultKey::derive(password, &salt)?;
    let check = hex::decode(&meta.check_block_hex).map_err(|_| "验证块损坏".to_string())?;
    key.verify_check_block(&check)?;
    Ok(key)
}

pub fn write_index(root: &Path, key: &VaultKey, index: &VaultIndex) -> Result<(), String> {
    let mut body = serde_json::to_string(index).map_err(|e| e.to_string())?;
    let mut plain = INDEX_MAGIC.to_vec();
    plain.extend_from_slice(body.as_bytes());
    body.zeroize();
    let sealed = key.seal_bytes(&plain)?;
    atomic_write(&index_path(root), &sealed)
}

pub fn read_index(root: &Path, key: &VaultKey) -> Result<VaultIndex, String> {
    let sealed = fs::read(index_path(root)).map_err(|_| "index.enc 缺失".to_string())?;
    let plain = key.open_bytes(&sealed)?;
    if !plain.starts_with(INDEX_MAGIC) {
        return Err("索引格式不正确".to_string());
    }
    serde_json::from_slice(&plain[INDEX_MAGIC.len()..]).map_err(|e| format!("索引损坏: {e}"))
}

pub fn write_journal(root: &Path, journal: &Journal) -> Result<(), String> {
    let json = serde_json::to_string(journal).map_err(|e| e.to_string())?;
    atomic_write(&journal_path(root), json.as_bytes())
}

pub fn read_journal(root: &Path) -> Option<Journal> {
    let raw = fs::read_to_string(journal_path(root)).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn clear_journal(root: &Path) {
    let _ = fs::remove_file(journal_path(root));
}

// ---------------------------------------------------------------------------
// 原子写 + 安全删除
// ---------------------------------------------------------------------------

/// 先写临时文件再 rename，避免半截文件
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp-write");
    fs::write(&tmp, bytes).map_err(|e| format!("写入 {} 失败: {e}", tmp.display()))?;
    match fs::rename(&tmp, path) {
        Ok(_) => Ok(()),
        Err(_) => {
            // Windows 上 rename 覆盖偶发失败：退化为直接写
            let r = fs::write(path, bytes);
            let _ = fs::remove_file(&tmp);
            r.map_err(|e| format!("写入 {} 失败: {e}", path.display()))
        }
    }
}

/// 删除文件内容后再删文件（普通删除 + 覆写一次；不做多轮擦除——NTFS 与 SSD
/// 上多轮擦除无意义，诚实说明即可）
pub fn shred_file(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let size = path.metadata().map(|m| m.len()).unwrap_or(0);
    if let Ok(mut f) = fs::OpenOptions::new().write(true).open(path) {
        use std::io::Write;
        let zeros = vec![0u8; 64 * 1024];
        let mut written: u64 = 0;
        while written < size {
            let n = std::cmp::min(zeros.len() as u64, size - written) as usize;
            if f.write_all(&zeros[..n]).is_err() {
                break; // 覆写失败不阻断删除
            }
            written += n as u64;
        }
        let _ = f.sync_all();
    }
    fs::remove_file(path).map_err(|e| format!("删除 {} 失败: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> VaultKey {
        VaultKey::derive("pw", &[seed; SALT_LEN]).unwrap()
    }

    #[test]
    fn rel_path_rules() {
        assert!(normalize_rel("合同/2026.docx").is_ok());
        assert!(normalize_rel("a\\b\\c.txt").is_ok());
        assert!(normalize_rel("../escape").is_err());
        assert!(normalize_rel("a/../../x").is_err());
        assert!(normalize_rel("/abs").is_err());
        assert!(normalize_rel("C:/x").is_err()); // 含冒号
        assert!(normalize_rel(".vaultbox").is_err());
        assert!(normalize_rel(".vaultbox/x").is_err());
        assert!(normalize_rel("a//b").is_err());
    }

    #[test]
    fn meta_index_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // 密钥必须派生自与 meta 相同的盐
        let salt = [9u8; SALT_LEN];
        let k = VaultKey::derive("pw", &salt).unwrap();
        create_meta_with_salt(root, &k, &salt).unwrap();
        assert!(is_vault(root));

        // 重复创建拒绝
        assert!(create_meta_with_salt(root, &k, &[9u8; SALT_LEN]).is_err());

        // 错误密码解锁失败
        let meta = read_meta(root).unwrap();
        assert!(derive_and_verify(&meta, "wrong").is_err());
        assert!(derive_and_verify(&meta, "pw").is_ok());

        // 索引往返
        let k2 = derive_and_verify(&meta, "pw").unwrap();
        let mut idx = VaultIndex::default();
        idx.files.insert(
            "工资 单.xlsx".into(),
            FileEntry { blob: "aabb.bin".into(), size: 12, mtime_ms: 99 },
        );
        write_index(root, &k2, &idx).unwrap();
        let back = read_index(root, &k2).unwrap();
        assert_eq!(back.files.len(), 1);
        assert_eq!(back.files["工资 单.xlsx"].blob, "aabb.bin");

        // 索引密文不含明文痕迹
        let raw = fs::read(index_path(root)).unwrap();
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(!raw_str.contains("工资"));
        assert!(!raw_str.contains("aabb"));
    }

    #[test]
    fn journal_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let k = key(2);
        create_meta_with_salt(root, &k, &[9u8; SALT_LEN]).unwrap();
        let j = Journal::new("unlock", vec!["a.txt".into()], vec!["b.bin".into()]);
        write_journal(root, &j).unwrap();
        let back = read_journal(root).unwrap();
        assert_eq!(back.kind, "unlock");
        assert_eq!(back.paths, vec!["a.txt".to_string()]);
        clear_journal(root);
        assert!(read_journal(root).is_none());
    }
}
