//! 快速隐藏：切换 Windows 文件/文件夹的 HIDDEN 属性。
//!
//! 诚实边界（界面同步说明）：这只是“防误看”——资源管理器开启
//! “显示隐藏的项目”后依然可见，不提供任何加密。

use std::fs;
use std::path::Path;
use walkdir::WalkDir;
use windows_sys::Win32::Storage::FileSystem::{
    GetFileAttributesW, SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN,
};

const HIDDEN: u32 = FILE_ATTRIBUTE_HIDDEN;

fn to_wide(path: &Path) -> Vec<u16> {
    path.as_os_str().to_string_lossy().encode_utf16().chain([0]).collect()
}

fn get_attrs(path: &Path) -> Result<u32, String> {
    let wide = to_wide(path);
    // INVALID_FILE_ATTRIBUTES == u32::MAX
    let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
    if attrs == u32::MAX {
        return Err(format!("读取属性失败：{}", path.display()));
    }
    Ok(attrs)
}

fn set_attrs(path: &Path, attrs: u32) -> Result<(), String> {
    let wide = to_wide(path);
    if unsafe { SetFileAttributesW(wide.as_ptr(), attrs) } == 0 {
        return Err(format!("设置属性失败：{}", path.display()));
    }
    Ok(())
}

#[derive(serde::Serialize)]
pub struct HideResult {
    pub path: String,
    pub hidden: bool,
    /// 递归处理的项目数
    pub count: u32,
}

/// 查询是否隐藏（不递归）
pub fn is_hidden(path: &Path) -> Result<bool, String> {
    Ok(get_attrs(path)? & HIDDEN != 0)
}

/// 切换隐藏状态：目标本身 + （若是文件夹）其内部所有条目递归。
/// 返回切换后的状态（true=已隐藏）。
pub fn toggle(path: &Path) -> Result<HideResult, String> {
    if !path.exists() {
        return Err(format!("路径不存在：{}", path.display()));
    }
    let now_hidden = get_attrs(path)? & HIDDEN == 0; // 当前可见 → 切换为隐藏
    let mut count: u32 = 0;
    apply_recursive(path, now_hidden, &mut count)?;
    Ok(HideResult {
        path: path.to_string_lossy().to_string(),
        hidden: now_hidden,
        count,
    })
}

fn apply_recursive(path: &Path, hide: bool, count: &mut u32) -> Result<(), String> {
    let attrs = get_attrs(path)?;
    let new_attrs = if hide { attrs | HIDDEN } else { attrs & !HIDDEN };
    set_attrs(path, new_attrs)?;
    *count += 1;
    if path.is_dir() && !path.is_symlink() {
        for entry in WalkDir::new(path)
            .max_depth(1)
            .into_iter()
            .skip(1) // 自身已在上面处理
            .filter_map(|e| e.ok())
        {
            apply_recursive(entry.path(), hide, count)?;
        }
    }
    Ok(())
}

/// 列出某目录下（不递归）条目的隐藏状态，供前端展示
pub fn list_dir_state(path: &Path) -> Result<Vec<HideResult>, String> {
    let mut out = Vec::new();
    for entry in fs::read_dir(path).map_err(|e| format!("读取目录失败: {e}"))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let hidden = get_attrs(&entry.path()).map(|a| a & HIDDEN != 0).unwrap_or(false);
        out.push(HideResult {
            path: entry.path().to_string_lossy().to_string(),
            hidden,
            count: 0,
        });
    }
    out.sort_by_key(|r| r.path.clone());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggle_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("测试.txt");
        fs::write(&f, b"x").unwrap();
        assert!(!is_hidden(&f).unwrap());
        let r = toggle(&f).unwrap();
        assert!(r.hidden);
        assert!(is_hidden(&f).unwrap());
        let r2 = toggle(&f).unwrap();
        assert!(!r2.hidden);
        assert!(!is_hidden(&f).unwrap());
    }

    #[test]
    fn toggle_folder_recursive() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("文件夹");
        fs::create_dir_all(sub.join("内层")).unwrap();
        fs::write(sub.join("a.txt"), b"a").unwrap();
        fs::write(sub.join("内层/b.txt"), b"b").unwrap();
        let r = toggle(&sub).unwrap();
        assert!(r.hidden);
        assert!(r.count >= 4, "应递归处理 文件夹+内层+两个文件，got {}", r.count);
        assert!(is_hidden(&sub.join("内层/b.txt")).unwrap());
        toggle(&sub).unwrap();
        assert!(!is_hidden(&sub.join("内层/b.txt")).unwrap());
    }

    #[test]
    fn missing_path_rejected() {
        assert!(toggle(Path::new("Z:/不存在/绝不")).is_err());
    }
}
