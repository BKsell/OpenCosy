'use strict';

// shortcutconflictresolver.js —— 快捷键冲突解决。
//
// 用户自己加了 Ctrl+Shift+N 当"新建标签"，而外壳已经把它留给"隐私窗口"。
// 这里把"建议换哪个键"收敛成纯函数：固定候选顺序，跳过已占用的。

// pickFallbackAccelerator 入参：
//   desired         用户想要的 accelerator，如 'Ctrl+Shift+N'
//   existing        已占用 accelerator 列表
//   preferredFallback  候选 fallback 列表（按优先级）
// 返回 { chosen, collisionsWithExisting }
function pickFallbackAccelerator(opts) {
  const o = opts || {};
  const desired = String(o.desired || '');
  const existing = new Set((o.existing || []).map((x) => String(x).toLowerCase()));
  const fallbacks = Array.isArray(o.preferredFallback) ? o.preferredFallback : [];
  if (desired && !existing.has(desired.toLowerCase())) {
    return { chosen: desired, collisionsWithExisting: false };
  }
  for (const fb of fallbacks) {
    if (!existing.has(String(fb).toLowerCase())) {
      return { chosen: fb, collisionsWithExisting: true };
    }
  }
  // 全部冲突：返回 null，让 UI 提示用户手动选。
  return { chosen: null, collisionsWithExisting: true };
}

// isAcceleratorSyntaxOk 粗判 accelerator 字符串格式。
function isAcceleratorSyntaxOk(acc) {
  const s = String(acc || '').trim();
  if (!s) return false;
  const parts = s.split('+').map((x) => x.trim()).filter(Boolean);
  if (parts.length < 2) return false;
  const mod = new Set(['CommandOrControl', 'Control', 'CmdOrCtrl', 'Cmd', 'Alt', 'Option', 'Shift', 'Super', 'Meta']);
  const last = parts[parts.length - 1];
  if (!mod.has(last)) return true;
  return false;
}

module.exports = {
  pickFallbackAccelerator,
  isAcceleratorSyntaxOk,
};
