//! VaultBox 加密核心：Argon2id 密钥派生 + AES-256-GCM 文件加密。
//!
//! 安全模型（与 README 一致）：
//! - 密码不落盘；密钥 = Argon2id(密码, 盐)，只在解锁期间驻内存，drop 时 zeroize
//! - 每个保险箱独立随机盐（16 字节）与验证块（AES-GCM 加密的固定明文）
//! - 每文件、每分块独立随机 nonce（12 字节），GCM tag 校验完整性
//! - 防护边界：防他人拷贝/翻看；不防内存取证、键盘记录器等主动攻击
//!
//! 文件密文布局（真流式，逐块处理，内存占用恒定）：
//! ```text
//! [u32 本块密文长(LE)][nonce 12B][GCM 密文(明文块+16B tag)] * N
//! ```

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 盐长度（字节）
pub const SALT_LEN: usize = 16;
/// GCM nonce 长度
pub const NONCE_LEN: usize = 12;
/// 密钥长度（AES-256）
pub const KEY_LEN: usize = 32;
/// 流式分块大小（明文 512 KiB/块）
pub const SEALED_CHUNK: usize = 512 * 1024;
/// Argon2id 参数：64 MiB 内存、3 轮（个人工具在 ~0.2s 派生延迟与防爆破之间的平衡）
const ARGON2_M_KIB: u32 = 65536;
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 1;
const GCM_TAG_LEN: usize = 16;

/// 内存中的主密钥。ZeroizeOnDrop 保证释放前清零。
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultKey([u8; KEY_LEN]);

impl VaultKey {
    pub fn derive(password: &str, salt: &[u8]) -> Result<Self, String> {
        if salt.len() != SALT_LEN {
            return Err(format!("盐长度非法（{}）", salt.len()));
        }
        let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(KEY_LEN))
            .map_err(|e| format!("Argon2 参数错误: {e}"))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; KEY_LEN];
        argon
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| format!("密钥派生失败: {e}"))?;
        Ok(VaultKey(key))
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.0))
    }

    /// 验证块明文（固定内容，仅用于校验密码正确性）
    const CHECK_PLAINTEXT: &[u8] = b"VAULTBOX-CHECK-V1";
    /// 验证块 nonce 固定全零（验证块是唯一 nonce 固定的用途）
    const CHECK_NONCE: [u8; NONCE_LEN] = [0u8; NONCE_LEN];

    /// 生成验证块密文（创建保险箱时）
    pub fn make_check_block(&self) -> Vec<u8> {
        self.cipher()
            .encrypt(Nonce::from_slice(&Self::CHECK_NONCE), Self::CHECK_PLAINTEXT)
            .expect("加密验证块不可能失败")
    }

    /// 校验密码（解锁时）。Err 表示密码错误或验证块被篡改。
    pub fn verify_check_block(&self, block: &[u8]) -> Result<(), String> {
        self.cipher()
            .decrypt(Nonce::from_slice(&Self::CHECK_NONCE), block)
            .ok()
            .filter(|plain| *plain == Self::CHECK_PLAINTEXT)
            .map(|_| ())
            .ok_or_else(|| "密码错误或数据已损坏".to_string())
    }

    /// 加密内存数据 → [nonce ++ 密文]
    pub fn seal_bytes(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let body = self
            .cipher()
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|e| format!("加密失败: {e}"))?;
        let mut out = Vec::with_capacity(NONCE_LEN + body.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// 解密 seal_bytes 的输出
    pub fn open_bytes(&self, sealed: &[u8]) -> Result<Vec<u8>, String> {
        if sealed.len() < NONCE_LEN + GCM_TAG_LEN {
            return Err("密文数据不完整".to_string());
        }
        let (nonce_bytes, body) = sealed.split_at(NONCE_LEN);
        self.cipher()
            .decrypt(Nonce::from_slice(nonce_bytes), body)
            .map_err(|_| "解密失败：数据损坏或密钥不匹配".to_string())
    }

    /// 流式加密文件：逐块读明文 → [len][nonce][GCM] 写出。返回密文字节数。
    pub fn seal_file(&self, plain: &Path, sealed_out: &Path) -> Result<u64, String> {
        let reader = File::open(plain).map_err(|e| format!("打开 {} 失败: {e}", plain.display()))?;
        let mut reader = BufReader::new(reader);
        let writer = File::create(sealed_out)
            .map_err(|e| format!("创建 {} 失败: {e}", sealed_out.display()))?;
        let mut writer = BufWriter::new(writer);
        let cipher = self.cipher();
        let mut buf = vec![0u8; SEALED_CHUNK];
        let mut total: u64 = 0;
        loop {
            let n = read_full(&mut reader, &mut buf)?;
            if n == 0 {
                break;
            }
            let mut nonce_bytes = [0u8; NONCE_LEN];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let body = cipher
                .encrypt(Nonce::from_slice(&nonce_bytes), &buf[..n])
                .map_err(|e| format!("加密 {} 失败: {e}", plain.display()))?;
            let sealed_len = (NONCE_LEN + body.len()) as u32;
            writer
                .write_all(&sealed_len.to_le_bytes())
                .and_then(|_| writer.write_all(&nonce_bytes))
                .and_then(|_| writer.write_all(&body))
                .map_err(|e| format!("写入 {} 失败: {e}", sealed_out.display()))?;
            total += 4 + sealed_len as u64;
        }
        writer.flush().map_err(|e| format!("落盘失败: {e}"))?;
        Ok(total)
    }

    /// 流式解密 seal_file 的输出。返回明文字节数。
    pub fn open_file(&self, sealed: &Path, plain_out: &Path) -> Result<u64, String> {
        let reader = File::open(sealed).map_err(|e| format!("打开 {} 失败: {e}", sealed.display()))?;
        let mut reader = BufReader::new(reader);
        let writer = File::create(plain_out)
            .map_err(|e| format!("创建 {} 失败: {e}", plain_out.display()))?;
        let mut writer = BufWriter::new(writer);
        let cipher = self.cipher();
        let mut total: u64 = 0;
        loop {
            // 块长度前缀
            let mut len_buf = [0u8; 4];
            match read_full(&mut reader, &mut len_buf)? {
                0 => break, // 干净 EOF
                4 => {}
                _ => return Err("密文块边界损坏".to_string()),
            }
            let sealed_len = u32::from_le_bytes(len_buf) as usize;
            if sealed_len < NONCE_LEN + GCM_TAG_LEN || sealed_len > SEALED_CHUNK + NONCE_LEN + GCM_TAG_LEN {
                return Err("密文块长度非法（数据损坏）".to_string());
            }
            let mut block = vec![0u8; sealed_len];
            if read_full(&mut reader, &mut block)? != sealed_len {
                return Err("密文块不完整".to_string());
            }
            let (nonce_bytes, body) = block.split_at(NONCE_LEN);
            let plain = cipher
                .decrypt(Nonce::from_slice(nonce_bytes), body)
                .map_err(|_| "解密失败：数据损坏或密钥不匹配".to_string())?;
            writer
                .write_all(&plain)
                .map_err(|e| format!("写入 {} 失败: {e}", plain_out.display()))?;
            total += plain.len() as u64;
        }
        writer.flush().map_err(|e| format!("落盘失败: {e}"))?;
        Ok(total)
    }

    /// 生成随机盐
    pub fn random_salt() -> [u8; SALT_LEN] {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        salt
    }

    /// 生成随机 blob 文件名（16 字节 hex，与用户输入完全无关，杜绝路径注入）
    pub fn random_blob_name() -> String {
        let mut id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut id);
        hex::encode(id) + ".bin"
    }
}

/// 读满缓冲区；EOF 返回 0，读到部分返回实读数
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, String> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let n = reader
            .read(&mut buf[filled..])
            .map_err(|e| format!("读取失败: {e}"))?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// 保险箱明文元数据（meta.json，不含任何密钥信息）
#[derive(Serialize, Deserialize, Clone)]
pub struct VaultMeta {
    pub version: u32,
    pub salt_hex: String,
    pub argon2: Argon2Params,
    pub check_block_hex: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct Argon2Params {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self { m_kib: ARGON2_M_KIB, t: ARGON2_T, p: ARGON2_P }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> VaultKey {
        VaultKey::derive("pw", &[seed; SALT_LEN]).unwrap()
    }

    #[test]
    fn derive_deterministic_and_salt_sensitive() {
        let a = key(7);
        let blk = a.make_check_block();
        assert!(key(7).verify_check_block(&blk).is_ok());
        assert!(key(8).verify_check_block(&blk).is_err());
    }

    #[test]
    fn wrong_password_rejected() {
        let blk = VaultKey::derive("abc", &[1u8; SALT_LEN]).unwrap().make_check_block();
        let bad = VaultKey::derive("abd", &[1u8; SALT_LEN]).unwrap();
        assert!(bad.verify_check_block(&blk).is_err());
    }

    #[test]
    fn seal_open_roundtrip() {
        let k = key(2);
        let data = "你好，VaultBox！hello".as_bytes().repeat(1000);
        let sealed = k.seal_bytes(&data).unwrap();
        assert_ne!(&sealed[..], &data[..]);
        assert_eq!(k.open_bytes(&sealed).unwrap(), data);
    }

    #[test]
    fn tamper_detected() {
        let k = key(3);
        let mut sealed = k.seal_bytes(b"secret payload").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(k.open_bytes(&sealed).is_err());
    }

    #[test]
    fn file_roundtrip_various_sizes() {
        let dir = tempfile::tempdir().unwrap();
        let k = key(4);
        for size in [0usize, 1, 100, SEALED_CHUNK, SEALED_CHUNK + 1, SEALED_CHUNK * 2 + 123] {
            let plain = dir.path().join(format!("p{size}"));
            let sealed = dir.path().join(format!("s{size}"));
            let restored = dir.path().join(format!("r{size}"));
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            fs::write(&plain, &data).unwrap();
            k.seal_file(&plain, &sealed).unwrap();
            if size > 0 {
                assert_ne!(fs::read(&sealed).unwrap(), data, "size={size} 密文不应等于明文");
            }
            k.open_file(&sealed, &restored).unwrap();
            assert_eq!(fs::read(&restored).unwrap(), data, "size={size} 往返不一致");
        }
    }

    #[test]
    fn file_tamper_detected() {
        let dir = tempfile::tempdir().unwrap();
        let k = key(5);
        let plain = dir.path().join("p");
        let sealed = dir.path().join("s");
        fs::write(&plain, "重要内容 ABC".as_bytes()).unwrap();
        k.seal_file(&plain, &sealed).unwrap();
        let mut data = fs::read(&sealed).unwrap();
        let last = data.len() - 1;
        data[last] ^= 0xff;
        fs::write(&sealed, data).unwrap();
        let restored = dir.path().join("r");
        assert!(k.open_file(&sealed, &restored).is_err());
    }
}
