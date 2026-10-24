/* VaultBox 前端：保险箱（状态机 UI）+ 快速隐藏 */
"use strict";

const invoke = (cmd, args) => window.__TAURI__.core.invoke(cmd, args);
const dialog = () => window.__TAURI__.dialog;
const $ = (id) => document.getElementById(id);

const state = {
  path: "",
  status: null,      // vault_status 结果
  autoSecs: 600,
};

/* ---------------- 基础 UI ---------------- */
let toastTimer;
function toast(text, ms) {
  const t = $("toast");
  t.textContent = text;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, ms || 2600);
}

function confirmModal(opts) {
  const o = opts || {};
  return new Promise((resolve) => {
    const box = $("modal");
    box.innerHTML = "";
    const card = document.createElement("div");
    card.className = "modal-card";
    const h = document.createElement("h3");
    h.textContent = o.title || "确认";
    const p = document.createElement("div");
    p.className = "muted";
    p.style.margin = "6px 0 0";
    p.textContent = o.label || "";
    const actions = document.createElement("div");
    actions.className = "modal-actions";
    const no = document.createElement("button");
    no.className = "btn";
    no.textContent = "取消";
    const yes = document.createElement("button");
    yes.className = "btn " + (o.danger ? "danger" : "primary");
    yes.textContent = o.okText || "确定";
    actions.appendChild(no);
    actions.appendChild(yes);
    card.appendChild(h);
    card.appendChild(p);
    card.appendChild(actions);
    box.appendChild(card);
    box.hidden = false;
    const close = (v) => { box.hidden = true; box.innerHTML = ""; resolve(v); };
    no.onclick = () => close(false);
    yes.onclick = () => close(true);
    box.onclick = (e) => { if (e.target === box) close(false); };
  });
}

function fmtSize(n) {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + " MB";
  return (n / 1024 / 1024 / 1024).toFixed(2) + " GB";
}
function fmtTime(ms) {
  if (!ms) return "";
  return new Date(ms).toLocaleString("zh-CN", { hour12: false });
}
function passwordModal(title) {
  return new Promise((resolve) => {
    const box = $("modal");
    box.innerHTML = "";
    const card = document.createElement("div");
    card.className = "modal-card";
    const h = document.createElement("h3");
    h.textContent = title || "输入密码";
    const field = document.createElement("div");
    field.className = "field";
    const input = document.createElement("input");
    input.type = "password";
    field.appendChild(input);
    const actions = document.createElement("div");
    actions.className = "modal-actions";
    const no = document.createElement("button");
    no.className = "btn";
    no.textContent = "取消";
    const yes = document.createElement("button");
    yes.className = "btn primary";
    yes.textContent = "确定";
    actions.append(no, yes);
    card.append(h, field, actions);
    box.append(card);
    box.hidden = false;
    input.focus();
    const close = (v) => { box.hidden = true; box.innerHTML = ""; resolve(v); };
    no.onclick = () => close(null);
    yes.onclick = () => {
      if (!input.value) { toast("请输入密码"); return; }
      close(input.value);
    };
    input.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") close(input.value);
      if (ev.key === "Escape") close(null);
    });
    box.onclick = (ev) => { if (ev.target === box) close(null); };
  });
}

function showLockResult(r) {
  // r = { handled, resealedBytes, busy }
  const bytes = r.resealedBytes || r.resealed_bytes || 0;
  const busyN = r.busy || 0;
  if (busyN > 0) {
    toast("部分上锁：" + (r.handled - busyN >= 0 ? r.handled : r.handled) + " 个已加密；"
      + busyN + " 个文件被占用暂保持明文，关闭占用程序（如游戏）后再点一次上锁即可补齐", 6000);
  } else {
    toast("已上锁：" + r.handled + " 个文件" + (bytes ? "，本次重新加密 " + fmtSize(bytes) : ""));
  }
}

function escapeHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

async function busy(btn, fn) {
  const old = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span>处理中…';
  try { return await fn(); }
  finally { btn.disabled = false; btn.innerHTML = old; }
}

/* ---------------- 保险箱页 ---------------- */
async function refreshStatus(keepPath) {
  if (!keepPath) state.path = $("vault-path").value.trim();
  else state.path = $("vault-path").value.trim() || state.path;
  if (!state.path) { $("vault-body").innerHTML = ""; return; }
  try {
    state.status = await invoke("vault_status", { path: state.path });
    renderVault();
  } catch (e) {
    $("vault-body").innerHTML = banner("err", e);
  }
}

function banner(kind, text, extraHtml) {
  return '<div class="banner ' + kind + '"><span>' + text + '</span><span class="spacer"></span>' + (extraHtml || "") + '</div>';
}

function renderVault() {
  const s = state.status;
  const el = $("vault-body");
  el.innerHTML = "";
  if (!s) return;

  if (s.meta_error) {
    el.innerHTML = banner("err", "元数据异常：" + s.meta_error)
      + mkCard("保险箱损坏", "meta.json 解析失败，请检查目录是否完整。");
    return;
  }
  if (!s.is_vault) {
    el.innerHTML = renderCreate();
    bindCreate();
    return;
  }
  if (s.has_journal) {
    el.innerHTML += banner("warn", "检测到上次操作未完成（可能异常退出）。下次解锁时将自动恢复到一致状态。");
  }
  if (s.unlocked) {
    el.innerHTML += renderUnlocked(s);
    bindUnlocked();
  } else {
    el.innerHTML += renderLocked(s);
    bindLocked();
  }
}

function mkCard(title, bodyHtml) {
  return '<div class="card"><h3>' + title + '</h3>' + bodyHtml + '</div>';
}

/* ---- 未初始化 ---- */
function renderCreate() {
  return mkCard("设为加密保险箱", `
    <div class="muted" style="margin-bottom:6px">
      上锁后：文件夹内所有文件与文件名全部加密（AES-256-GCM），只剩 .vaultbox/data 下的乱码数据；<br />
      解锁后：文件恢复原名，可直接用资源管理器 / Excel / WPS 操作。<b>密码丢失无法找回。</b>
    </div>
    <div class="field"><label>设置密码（至少 6 位）</label><input id="pw1" type="password" /></div>
    <div class="field"><label>确认密码</label><input id="pw2" type="password" /></div>
    <div style="margin-top:10px"><button id="btn-create" class="btn primary">初始化保险箱</button></div>
  `);
}
function bindCreate() {
  $("btn-create").onclick = async (e) => {
    const pw1 = $("pw1").value;
    const pw2 = $("pw2").value;
    if (pw1 !== pw2) { toast("两次密码不一致"); return; }
    await busy(e.target, async () => {
      try {
        await invoke("vault_create", { path: state.path, password: pw1, force: false });
        toast("保险箱已创建并解锁，可导入文件");
        refreshStatus(true);
      } catch (err) {
        if (String(err).indexOf("非空") >= 0) {
          const ok = await confirmModal({
            title: "文件夹非空",
            label: "继续会把现有内容一并纳入加密管理（下次上锁时全部加密）。确定继续？",
            okText: "继续创建",
            danger: true,
          });
          if (!ok) return;
          try {
            await invoke("vault_create", { path: state.path, password: pw1, force: true });
            toast("保险箱已创建并解锁");
            refreshStatus(true);
          } catch (e2) { toast("创建失败：" + e2); }
        } else {
          toast("创建失败：" + err);
        }
      }
    });
  };
}

/* ---- 已上锁 ---- */
function renderLocked(s) {
  const stats = '<div class="stat-grid">'
    + '<div class="stat"><div class="num">' + (s.file_count || "—") + '</div><div class="lbl">加密文件数</div></div>'
    + '<div class="stat"><div class="num">' + (s.total_size ? fmtSize(s.total_size) : "—") + '</div><div class="lbl">加密总量</div></div>'
    + '<div class="stat"><div class="num">🔒</div><div class="lbl">状态</div></div>'
    + '</div>';
  return stats + mkCard("解锁保险箱", `
    <div class="field"><label>密码</label><input id="pw" type="password" placeholder="输入密码解锁" /></div>
    <div style="margin-top:10px"><button id="btn-unlock" class="btn primary">解锁</button></div>
    <div class="muted" style="margin-top:8px">连续输错 5 次将锁定 30 秒。上锁中的文件名与内容均不可见。</div>
  `);
}
function bindLocked() {
  const doUnlock = async (btn) => {
    const pw = $("pw").value;
    if (!pw) { toast("请输入密码"); return; }
    await busy(btn, async () => {
      try {
        const r = await invoke("vault_unlock", { path: state.path, password: pw });
        state.autoSecs = r[1];
        toast("已解锁，共 " + r[0] + " 个文件");
        refreshStatus(true);
      } catch (e) { toast("解锁失败：" + e); }
    });
  };
  $("btn-unlock").onclick = (e) => doUnlock(e.target);
  $("pw").addEventListener("keydown", (e) => {
    if (e.key === "Enter") doUnlock($("btn-unlock"));
  });
}

/* ---- 已解锁 ---- */
function renderUnlocked(s) {
  return banner("ok", "🔓 已解锁 —— 文件当前以明文形式存在于文件夹中，可直接使用。",
      '<span id="auto-count" class="muted"></span><button id="btn-lock" class="btn primary">立即上锁</button>')
    + '<div class="path-bar" style="margin-bottom:8px">'
    + '<button id="btn-import-files" class="btn">导入文件…</button>'
    + '<button id="btn-import-dir" class="btn">导入文件夹…</button>'
    + '<span style="flex:1"></span>'
    + '<label class="muted" for="auto-select" style="display:inline-flex;align-items:center;gap:6px">自动上锁'
    + '<select id="auto-select" class="btn" style="padding:4px 8px">'
    + '<option value="0">关闭（退出程序时上锁）</option>'
    + '<option value="5">5 分钟</option>'
    + '<option value="10">10 分钟</option>'
    + '<option value="30">30 分钟</option>'
    + '</select></label>'
    + '<button id="btn-dissolve" class="btn danger" title="移除加密结构（要求箱内已清空）">移除保险箱…</button>'
    + '</div>'
    + '<div class="muted" style="margin:0 0 8px;font-size:12px">箱里放游戏等常驻程序时建议选「关闭」；退出 VaultBox 前请先关掉正在使用文件的程序，否则无法完成上锁。</div>'
    + '<table class="files"><thead><tr><th style="width:55%">路径</th><th>大小</th><th>修改时间</th></tr></thead>'
    + '<tbody id="file-rows"><tr><td colspan="3" class="muted">加载中…</td></tr></tbody></table>';
}

async function loadFiles() {
  try {
    const rows = await invoke("vault_list", { path: state.path });
    const tb = $("file-rows");
    if (!tb) return;
    if (!rows.length) {
      tb.innerHTML = '<tr><td colspan="3" class="muted">（空）用上方按钮导入，或直接把文件放进文件夹</td></tr>';
      return;
    }
    tb.innerHTML = rows.map((r) =>
      '<tr class="' + (r.is_dir ? "dir" : "") + '">'
      + '<td class="path">' + (r.is_dir ? "📁 " : "📄 ") + escapeHtml(r.path) + '</td>'
      + '<td>' + (r.is_dir ? "—" : fmtSize(r.size)) + '</td>'
      + '<td class="muted">' + (r.is_dir ? "" : fmtTime(r.mtime_ms)) + '</td>'
      + '</tr>').join("");
  } catch (e) {
    const tb = $("file-rows");
    if (tb) tb.innerHTML = '<tr><td colspan="3" class="muted">读取失败：' + escapeHtml(String(e)) + '</td></tr>';
  }
}

function bindUnlocked() {
  loadFiles();
  $("btn-lock").onclick = async (e) => {
    await busy(e.target, async () => {
      let r = null;
      try {
        r = await invoke("vault_lock", { path: state.path });
      } catch (err) {
        // 无会话（程序重启后/刚创建即其他原因）：弹密码框凭密码上锁
        const pw = await passwordModal("上锁失败：" + err + "\n\n输入密码直接上锁（取消则放弃）");
        if (!pw) return;
        try {
          r = await invoke("vault_lock", { path: state.path, password: pw });
        } catch (e2) { toast("上锁失败：" + e2); return; }
      }
      showLockResult(r);
      refreshStatus(true);
    });
  };
  $("btn-import-files").onclick = async (e) => {
    const picked = await dialog().open({ multiple: true, title: "选择要导入的文件" });
    if (!picked) return;
    const sources = Array.isArray(picked) ? picked : [picked];
    await busy(e.target, async () => {
      try {
        const n = await invoke("vault_import", { path: state.path, sources });
        toast("已导入 " + n + " 个文件");
        loadFiles();
      } catch (err) { toast("导入失败：" + err); }
    });
  };
  $("btn-import-dir").onclick = async (e) => {
    const picked = await dialog().open({ directory: true, title: "选择要导入的文件夹" });
    if (!picked) return;
    await busy(e.target, async () => {
      try {
        const n = await invoke("vault_import", { path: state.path, sources: [picked] });
        toast("已导入 " + n + " 个文件");
        loadFiles();
      } catch (err) { toast("导入失败：" + err); }
    });
  };
  const sel = $("auto-select");
  if (sel) {
    sel.value = String(state.autoSecs);
    sel.onchange = async () => {
      const v = Number(sel.value);
      try {
        await invoke("set_auto_lock", { seconds: v });
        state.autoSecs = v;
        try { localStorage.setItem("vaultbox:autoLock", String(v)); } catch (_) {}
        toast(v === 0 ? "已关闭空闲自动上锁：退出程序时统一上锁" : "自动上锁已设为 " + v + " 分钟");
      } catch (e) { toast("设置失败：" + e); }
    };
  }
  $("btn-dissolve").onclick = async () => {
    const ok = await confirmModal({
      title: "移除保险箱",
      label: "仅当箱内已无加密数据时可用（先取出全部文件并上锁）。确认移除加密结构？",
      okText: "移除",
      danger: true,
    });
    if (!ok) return;
    try {
      await invoke("vault_dissolve", { path: state.path });
      toast("已移除保险箱结构");
      refreshStatus(true);
    } catch (e) { toast("移除失败：" + e); }
  };
}

/* 自动上锁倒计时（每 5 秒） */
setInterval(async () => {
  try {
    const idle = await invoke("idle_seconds");
    const auto = await invoke("get_auto_lock");
    state.autoSecs = auto;
    const el = document.getElementById("auto-count");
    const conf = document.getElementById("auto-conf");
    if (auto === 0) {
      if (el) el.textContent = "退出程序时自动上锁";
      if (conf) conf.textContent = "";
      const sel = document.getElementById("auto-select");
      if (sel) sel.value = "0";
      return;
    }
    const remain = Math.max(0, auto - idle);
    const txt = "无操作 " + Math.max(1, Math.ceil(remain / 60)) + " 分钟后自动上锁";
    if (el) el.textContent = txt;
    if (conf) conf.textContent = "自动上锁：" + Math.max(1, Math.ceil(remain / 60)) + " 分钟";
  } catch (_) { /* 会话不存在等，忽略 */ }
}, 5000);

/* 拖拽导入：Tauri 拖放事件提供文件/文件夹的真实绝对路径 */
window.__TAURI__.event.listen("tauri://drag-over", () => {
  document.body.classList.add("dragging");
});
window.__TAURI__.event.listen("tauri://drag-leave", () => {
  document.body.classList.remove("dragging");
});
window.__TAURI__.event.listen("tauri://drag-drop", async (ev) => {
  document.body.classList.remove("dragging");
  const paths = (ev.payload && ev.payload.paths) || [];
  if (!paths.length) return;
  // 快速隐藏页不处理拖拽
  if ($("page-vault").hidden) { toast("切到「保险箱」页再拖入"); return; }
  if (!state.status || !state.status.is_vault) {
    toast("请先把目标文件夹设为保险箱，解锁后再拖入");
    return;
  }
  if (!state.status.unlocked) {
    toast("请先解锁保险箱，再拖入文件");
    return;
  }
  try {
    const n = await invoke("vault_import", { path: state.path, sources: paths });
    toast("已导入 " + n + " 个文件（立即加密）");
    loadFiles();
  } catch (e) { toast("导入失败：" + e); }
});

/* 用户在应用内任意点击 → 刷新会话活动（自动上锁的“空闲”以应用内操作为准） */
document.addEventListener("click", () => {
  invoke("vault_activity").catch(() => {});
}, true);

/* 退出时上锁失败（罕见）：程序已阻止退出，告知用户 */
window.__TAURI__.event.listen("vault-exit-lock-failed", (ev) => {
  const roots = (ev.payload && ev.payload.roots) || [];
  const again = window.confirm
    ? null
    : null;
  // confirm() 在 WebView 可用；简单可靠
  const ok = window.confirm("以下保险箱上锁失败：\n" + roots.join("\n")
    + "\n\n请关闭正在使用这些文件的程序（如游戏），然后再次点击窗口关闭按钮重试。\n"
    + "点「确定」强制退出（这些箱将保持解锁状态）");
  if (ok) {
    invoke("force_exit").catch(() => {});
  }
});

/* 自动上锁事件 → 刷新界面 */
window.__TAURI__.event.listen("vault-auto-locked", (ev) => {
  toast("已自动上锁：" + ev.payload.root);
  refreshStatus(true);
});

/* ---------------- 快速隐藏页 ---------------- */
async function refreshHide() {
  const p = $("hide-path").value.trim();
  const st = $("hide-state");
  if (!p) { st.textContent = "尚未选择路径"; $("hide-children").innerHTML = ""; return; }
  try {
    const hidden = await invoke("hide_is_hidden", { path: p });
    st.innerHTML = (hidden ? '<span class="badge hidden">已隐藏</span>' : '<span class="badge visible">可见</span>')
      + ' <span class="muted">' + escapeHtml(p) + '</span>';
    let kids = [];
    try { kids = await invoke("hide_list_dir", { path: p }); } catch (_) { /* 非目录则无子项 */ }
    let html = "";
    if (kids.length) {
      html = '<div class="muted" style="margin-bottom:6px">该目录下的条目：</div>';
      for (const k of kids) {
        const name = k.path.replace(/^.*[\\/]/, "");
        html += '<div class="hide-row"><span class="p" title="' + escapeHtml(k.path) + '">' + escapeHtml(name) + '</span>'
          + '<span class="badge ' + (k.hidden ? "hidden" : "visible") + '">' + (k.hidden ? "隐藏" : "可见") + '</span>'
          + '<button class="btn" style="padding:2px 10px;font-size:11px" data-hide-path="' + escapeHtml(k.path) + '">切换</button></div>';
      }
    }
    $("hide-children").innerHTML = html;
    $("hide-children").querySelectorAll("[data-hide-path]").forEach((b) => {
      b.onclick = async () => {
        try {
          const r = await invoke("hide_toggle", { path: b.dataset.hidePath });
          toast(r.hidden ? "已隐藏：" + r.path : "已显示：" + r.path);
          refreshHide();
        } catch (e) { toast("操作失败：" + e); }
      };
    });
  } catch (e) {
    st.textContent = "状态读取失败：" + e;
  }
}

/* ---------------- 全局绑定与启动 ---------------- */
$("btn-pick-dir").onclick = async () => {
  const p = await dialog().open({ directory: true, title: "选择保险箱文件夹" });
  if (p) { $("vault-path").value = p; refreshStatus(true); }
};
$("btn-refresh").onclick = () => refreshStatus(true);
$("vault-path").addEventListener("change", () => refreshStatus(true));
$("vault-path").addEventListener("keydown", (e) => { if (e.key === "Enter") refreshStatus(true); });

$("btn-hide-pick").onclick = async () => {
  const p = await dialog().open({ title: "选择文件或文件夹" });
  if (p) { $("hide-path").value = p; refreshHide(); }
};
$("btn-hide-toggle").onclick = async (e) => {
  const p = $("hide-path").value.trim();
  if (!p) { toast("请先选择路径"); return; }
  await busy(e.target, async () => {
    try {
      const r = await invoke("hide_toggle", { path: p });
      toast(r.hidden ? "已隐藏（含 " + r.count + " 项）" : "已显示（含 " + r.count + " 项）");
      refreshHide();
    } catch (err) { toast("操作失败：" + err); }
  });
};
$("hide-path").addEventListener("change", refreshHide);

$("nav-vault").onclick = () => switchPage("vault");
$("nav-hide").onclick = () => switchPage("hide");
function switchPage(which) {
  $("nav-vault").classList.toggle("on", which === "vault");
  $("nav-hide").classList.toggle("on", which === "hide");
  $("page-vault").hidden = which !== "vault";
  $("page-hide").hidden = which !== "hide";
  if (which === "hide") refreshHide();
}

(async function boot() {
  try { $("ver").textContent = "v" + (await invoke("version")); } catch (_) {}
  // 恢复上次的自动上锁设置（默认 10 分钟）
  let saved = 10;
  try { saved = Number(localStorage.getItem("vaultbox:autoLock")); if (isNaN(saved)) saved = 10; } catch (_) {}
  state.autoSecs = saved;
  try { await invoke("set_auto_lock", { seconds: saved }); } catch (_) {}
  const roots = await invoke("session_roots").catch(() => []);
  if (roots && roots.length) {
    $("vault-path").value = roots[roots.length - 1];
    refreshStatus(true);
    if (roots.length > 1) {
      toast("当前有 " + roots.length + " 个保险箱处于解锁状态（程序退出时会全部上锁）", 4200);
    }
  }
})();
