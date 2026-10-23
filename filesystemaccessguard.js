'use strict';

// filesystemaccessguard.js —— File System Access API（showSaveFilePicker /
// showOpenFilePicker / showDirectoryPicker + 句柄读写）安全裁决内核。
//
// 威胁模型：
//   1. 保存/打开选择器被无手势、无页面焦点时程序化触发，做点击劫持诱导覆盖系统文件；
//   2. 用户授予的目录句柄被持久化后，后台反复读写，越权扩大到整个目录树；
//   3. 建议文件名（suggestedName）携带路径分隔、盘符、设备名、点号穿越、控制字符，
//      诱导写入危险位置或可执行文件；
//   4. 写 .exe/.scr/.bat/.lnk 等可执行/脚本文件，落地即可被执行；
//   5. 接受类型（accept）用伪装 MIME/扩展名放行可执行内容；
//   6. 单文件写入字节无上限，句柄长时间不释放，配额耗尽；
//   7. 目录写入未限制深度/条目数，被用于文件夹炸弹。
//
// 纯逻辑，复用本仓库 nameguard 等价规则（在本文件内自带，避免跨文件依赖）。

const FA_DENY = 'deny';
const FA_PROMPT = 'prompt';

const FA_REASON = Object.freeze({
  INSECURE_CONTEXT: 'fa-insecure-context',
  BAD_ORIGIN: 'fa-bad-origin',
  BLOCKED_ORIGIN: 'fa-blocked-origin',
  NO_GESTURE: 'fa-requires-gesture',
  NOT_FOCUSED: 'fa-not-focused',
  BACKGROUND: 'fa-background',
  PICKER_THROTTLED: 'fa-picker-throttled',
  BAD_SUGGESTED_NAME: 'fa-bad-suggested-name',
  PATH_TRAVERSAL: 'fa-path-traversal',
  RESERVED_DEVICE_NAME: 'fa-reserved-device-name',
  CONTROL_CHAR: 'fa-control-char',
  EXECUTABLE_EXTENSION: 'fa-executable-extension',
  MIME_EXTENSION_MISMATCH: 'fa-mime-extension-mismatch',
  WRITE_TOO_LARGE: 'fa-write-too-large',
  TOO_MANY_HANDLES: 'fa-too-many-handles',
  DIRECTORY_TOO_DEEP: 'fa-directory-too-deep',
  TOO_MANY_ENTRIES: 'fa-too-many-entries',
  HANDLE_REVOKED: 'fa-handle-revoked',
});

const EXECUTABLE_EXT = Object.freeze(new Set([
  'exe', 'scr', 'bat', 'cmd', 'com', 'pif', 'lnk', 'msi', 'msp', 'mst',
  'ps1', 'psm1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'jar', 'app',
  'dll', 'sys', 'cpl', 'reg', 'hta', 'iso', 'sh', 'deb', 'rpm',
]));

function defaultFsPolicy() {
  return {
    requireSecureContext: true,
    requireGesture: true,
    requireFocus: true,
    denyBackground: true,
    pickerMinIntervalMs: 1500,
    maxOpenHandles: 8,
    maxWriteBytes: 200 * 1024 * 1024,
    maxNameBytes: 255,
    maxDirDepth: 8,
    maxDirEntries: 5000,
    blockExecutableExt: true,
  };
}

function originKey(origin) {
  if (typeof origin !== 'string') return '';
  const idx = origin.indexOf('://');
  if (idx <= 0) return '';
  const scheme = origin.slice(0, idx).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') return '';
  const rest = origin.slice(idx + 3);
  if (rest === '' || rest.indexOf('/') >= 0 || rest.indexOf('?') >= 0) return '';
  return scheme + '://' + rest.toLowerCase();
}

function containsControlChar(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 32 || c === 127) return true;
  }
  return false;
}

function extOfName(name) {
  const dot = name.lastIndexOf('.');
  if (dot <= 0 || dot === name.length - 1) return '';
  return name.slice(dot + 1).toLowerCase();
}

function stemOfName(name) {
  const dot = name.lastIndexOf('.');
  return dot > 0 ? name.slice(0, dot) : name;
}

// beforeWhitespace 返回第一个空格/制表之前的子串，纯字符实现。
function beforeWhitespace(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 32 || c === 9) return s.slice(0, i);
  }
  return s;
}

function isSingleDigit(s) {
  return s.length === 1 && s.charCodeAt(0) >= 48 && s.charCodeAt(0) <= 57;
}

// isReservedDeviceName 识别 Windows 保留设备名（CON/PRN/AUX/NUL/COMx/LPTx）。
function isReservedDeviceName(name) {
  const base = beforeWhitespace(stemOfName(name).toUpperCase());
  if (base === 'CON' || base === 'PRN' || base === 'AUX' || base === 'NUL') return true;
  if (base.length === 4) {
    const p = base.slice(0, 3);
    const n = base.slice(3);
    if ((p === 'COM' || p === 'LPT') && isSingleDigit(n)) return true;
  }
  return false;
}

// validateName 校验建议文件名/句柄文件名，返回原因码（空串表示通过）。
function validateName(rawName, policy) {
  const name = typeof rawName === 'string' ? rawName : '';
  if (name === '' || name === '.' || name === '..') return FA_REASON.BAD_SUGGESTED_NAME;
  if (name.length > policy.maxNameBytes) return FA_REASON.BAD_SUGGESTED_NAME;
  if (containsControlChar(name)) return FA_REASON.CONTROL_CHAR;
  if (name.indexOf('/') >= 0 || name.indexOf('\\') >= 0 || name.indexOf('::') >= 0) {
    return FA_REASON.PATH_TRAVERSAL;
  }
  if (name.indexOf(':') >= 0) return FA_REASON.PATH_TRAVERSAL;
  if (name.indexOf('..') >= 0) return FA_REASON.PATH_TRAVERSAL;
  if (name.charCodeAt(name.length - 1) === 46 || name.charCodeAt(name.length - 1) === 32) {
    return FA_REASON.BAD_SUGGESTED_NAME;
  }
  if (isReservedDeviceName(name)) return FA_REASON.RESERVED_DEVICE_NAME;
  const ext = extOfName(name);
  if (policy.blockExecutableExt && EXECUTABLE_EXT.has(ext)) return FA_REASON.EXECUTABLE_EXTENSION;
  return '';
}

// checkAcceptMime 校验 accept 里 MIME 与扩展名不伪装（如 image/png 配 .exe）。
function acceptMismatch(accept) {
  if (!accept || typeof accept !== 'object') return false;
  for (const mime of Object.keys(accept)) {
    const exts = accept[mime] || [];
    for (const e of exts) {
      let ext = String(e).toLowerCase();
      if (ext.charAt(0) === '.') ext = ext.slice(1);
      if (EXECUTABLE_EXT.has(ext)) return true;
    }
  }
  return false;
}

class FileSystemAccessGuard {
  constructor(policy) {
    this.policy = policy || defaultFsPolicy();
    this.lastPicker = new Map();
    this.handles = new Map(); // origin -> Set(handleId)
  }

  _common(ctx) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { ok: false, reason: FA_REASON.BAD_ORIGIN };
    if (pol.requireSecureContext && ctx.isSecureContext !== true) {
      return { ok: false, reason: FA_REASON.INSECURE_CONTEXT };
    }
    const key = originKey(ctx.origin);
    if (!key) return { ok: false, reason: FA_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { ok: false, reason: FA_REASON.BLOCKED_ORIGIN };
    if (pol.denyBackground && ctx.isBackground === true) return { ok: false, reason: FA_REASON.BACKGROUND };
    if (pol.requireGesture && ctx.hasUserGesture !== true) return { ok: false, reason: FA_REASON.NO_GESTURE };
    if (pol.requireFocus && ctx.hasFocus !== true) return { ok: false, reason: FA_REASON.NOT_FOCUSED };
    const now = ctx.now || 0;
    if (this.lastPicker.has(key) && now - this.lastPicker.get(key) < pol.pickerMinIntervalMs) {
      return { ok: false, reason: FA_REASON.PICKER_THROTTLED };
    }
    return { ok: true, key, now };
  }

  // decideSavePicker 裁决 showSaveFilePicker。
  decideSavePicker(ctx, suggestedName, accept) {
    const g = this._common(ctx);
    if (!g.ok) return { decision: FA_DENY, reason: g.reason };
    const nameReason = validateName(suggestedName, this.policy);
    if (nameReason) return { decision: FA_DENY, reason: nameReason };
    if (acceptMismatch(accept)) return { decision: FA_DENY, reason: FA_REASON.MIME_EXTENSION_MISMATCH };
    this.lastPicker.set(g.key, g.now);
    return { decision: FA_PROMPT, reason: '', safeName: suggestedName };
  }

  decideOpenPicker(ctx, accept, multiple) {
    const g = this._common(ctx);
    if (!g.ok) return { decision: FA_DENY, reason: g.reason };
    if (acceptMismatch(accept)) return { decision: FA_DENY, reason: FA_REASON.MIME_EXTENSION_MISMATCH };
    this.lastPicker.set(g.key, g.now);
    return { decision: FA_PROMPT, reason: '', multiple: multiple === true };
  }

  registerHandle(origin, handleId) {
    const key = originKey(origin);
    let set = this.handles.get(key);
    if (!set) { set = new Set(); this.handles.set(key, set); }
    if (set.size >= this.policy.maxOpenHandles && !set.has(handleId)) {
      return { ok: false, reason: FA_REASON.TOO_MANY_HANDLES };
    }
    set.add(handleId);
    return { ok: true };
  }

  revokeHandle(origin, handleId) {
    const set = this.handles.get(originKey(origin));
    if (set) set.delete(handleId);
  }

  // decideWrite 裁决经某句柄写入字节。
  decideWrite(origin, handleId, fileName, byteLength, depth) {
    const pol = this.policy;
    const set = this.handles.get(originKey(origin));
    if (!set || !set.has(handleId)) return { allowed: false, reason: FA_REASON.HANDLE_REVOKED };
    const nameReason = validateName(fileName, pol);
    if (nameReason) return { allowed: false, reason: nameReason };
    if (typeof byteLength === 'number' && byteLength > pol.maxWriteBytes) {
      return { allowed: false, reason: FA_REASON.WRITE_TOO_LARGE };
    }
    if (typeof depth === 'number' && depth > pol.maxDirDepth) {
      return { allowed: false, reason: FA_REASON.DIRECTORY_TOO_DEEP };
    }
    return { allowed: true, reason: '' };
  }

  // decideDirectoryEntry 裁决目录写入条目数。
  decideDirectoryEntry(origin, entryCount) {
    if ((entryCount || 0) > this.policy.maxDirEntries) {
      return { allowed: false, reason: FA_REASON.TOO_MANY_ENTRIES };
    }
    return { allowed: true, reason: '' };
  }
}

module.exports = {
  FA_DENY, FA_PROMPT, FA_REASON, EXECUTABLE_EXT,
  defaultFsPolicy, originKey, validateName, extOfName, stemOfName,
  isReservedDeviceName, acceptMismatch, FileSystemAccessGuard,
};
