'use strict';

// dragdropguard.js —— 窗口/页面拖放内容的安全裁决内核（纯函数，可单测，不触 DOM 网络）。
//
// 威胁模型：
//   Electron 的 BrowserWindow / WebContents 会接收系统级 HTML5 拖放。恶意页面
//   或同台机器上的另一个程序，可以把以下内容拖进浏览器窗口：
//     1. 可执行文件（.exe/.scr/.bat/.msi/.lnk …）：Chromium 可能弹出“下载/打开”，
//        一旦用户惯性确认即落地执行；
//     2. file:// / file:/// URL：诱导 webview 导航到本地文件，读取本机资源或
//        触发本地 HTML 的 file:// 同源能力（信息泄露 / UXSS）；
//     3. \\server\share 的 UNC 路径：Windows 资源管理器/Chromium 解析时会向
//        攻击者主机发起 SMB 协商，自动携带当前用户 NTLM 凭据（凭据中继/窃取）；
//     4. text/uri-list 里塞 javascript: / data: / vbscript:，借“链接”名义
//        把脚本协议喂给后续导航逻辑；
//     5. 成百上千个条目制造拖放处理卡顿（UI DoS），或同名重复项制造混乱。
//
//   本内核只做静态裁决，不访问文件系统、不发起解析：调用方（main/preload 的
//   will-navigate / webContents 拖放拦截点）把 DataTransfer 条目归一后传入，
//   依据策略返回 allow / reason。默认策略面向“普通网页上下文”，从严。

// 默认一次拖放允许的最大条目数：超出直接整批拒绝，不逐个处理（防 UI DoS）。
const DEFAULT_MAX_ITEMS = 32;
// 单条 URI / 文件名长度上限（字符），防止超长字符串打爆下游拼接。
const DEFAULT_MAX_URI_LEN = 4096;
const DEFAULT_MAX_NAME_LEN = 512;

// 可执行 / 可脚本化 / 可挂载的危险扩展名（小写、含点）。命中即拒绝拖入导航。
const DANGEROUS_EXTS = Object.freeze(new Set([
  '.exe', '.scr', '.com', '.bat', '.cmd', '.ps1', '.psm1', '.vbs', '.vbe',
  '.js', '.jse', '.ws', '.wsf', '.wsh', '.msi', '.msp', '.mst', '.lnk',
  '.url', '.reg', '.inf', '.dll', '.sys', '.drv', '.ocx', '.cpl', '.jar',
  '.app', '.appref-ms', '.gadget', '.hta', '.csh', '.sh', '.bash', '.desktop',
  '.iso', '.img', '.vhd', '.vhdx', '.wim',
]));

// 即便走“允许文件”策略，也只放行这些明确的只读文档/媒体类型（白名单）。
const SAFE_FILE_EXTS = Object.freeze(new Set([
  '.txt', '.md', '.csv', '.log', '.json', '.xml', '.yaml', '.yml', '.ini',
  '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.svg', '.ico',
  '.mp3', '.wav', '.flac', '.ogg', '.mp4', '.mkv', '.webm', '.mov',
  '.zip', '.gz', '.tar', '.7z',
]));

// 允许作为“链接”拖入的传输协议白名单；其它协议（file/javascript/data/…）拒绝。
const ALLOWED_URI_SCHEMES = Object.freeze(new Set(['http:', 'https:']));

// 默认策略：普通网页上下文。
const DEFAULT_POLICY = Object.freeze({
  allowFiles: false,     // 是否允许本地文件条目（false 时文件一律拒绝）
  allowFileUri: false,   // 是否允许 file:// 链接（默认拒绝导航本地资源）
  safeExtsOnly: true,    // allowFiles=true 时仅放行 SAFE_FILE_EXTS
  maxItems: DEFAULT_MAX_ITEMS,
  maxUriLen: DEFAULT_MAX_URI_LEN,
  maxNameLen: DEFAULT_MAX_NAME_LEN,
});

function hasControlChar(s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 32) return true;
  }
  return false;
}

// 提取小写扩展名（含点）；无扩展名返回空串。
function extOf(name) {
  const dot = name.lastIndexOf('.');
  if (dot <= 0) return '';
  return name.slice(dot).toLowerCase();
}

// 识别 Windows UNC（\\host\share 或 //host/share）。
function isUncPath(p) {
  return p.startsWith('\\\\') || p.startsWith('//');
}

// 识别盘符绝对路径（C:\ …）。
function isDrivePath(p) {
  return p.length >= 3 &&
    ((p.charCodeAt(0) >= 65 && p.charCodeAt(0) <= 90) ||
     (p.charCodeAt(0) >= 97 && p.charCodeAt(0) <= 122)) &&
    p.charCodeAt(1) === 58 &&
    (p.charCodeAt(2) === 92 || p.charCodeAt(2) === 47);
}

// 从 file:// URI 中解出裸路径部分（不做解码之外的文件访问）。
// file: 之后剥掉 authority 前导的一对斜杠；空 authority 时路径仍以 / 开头，
// Windows 盘符形态 /C:/x 再去掉那个根斜杠。
function fileUriToPath(uri) {
  let rest = uri.slice('file:'.length);
  if (rest.startsWith('//')) rest = rest.slice(2);
  try {
    rest = decodeURIComponent(rest);
  } catch {
    // 非法百分号编码：保留原样交给后续长度/字符检查拒绝。
  }
  if (rest.length >= 3 && rest[0] === '/' && rest[2] === ':') {
    const c = rest.charCodeAt(1);
    if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122)) {
      rest = rest.slice(1);
    }
  }
  return rest;
}

// 归一化单个拖放条目。item 形态：
//   { kind: 'uri'|'file'|'text', uri?, name?, type?, path? }
// 返回 { ok, reason, entry }；ok=false 时 reason 为拒绝原因。
function classifyDroppedItem(item, policy) {
  if (!item || typeof item !== 'object') {
    return { ok: false, reason: 'not-an-object' };
  }
  const kind = String(item.kind || '').toLowerCase();
  if (kind !== 'uri' && kind !== 'file' && kind !== 'text') {
    return { ok: false, reason: 'unknown-kind' };
  }

  // 纯文本片段不触发导航，直接放行（长度仍受限）。
  if (kind === 'text') {
    const text = String(item.uri || item.name || '');
    if (text.length > policy.maxUriLen) return { ok: false, reason: 'uri-too-long' };
    if (hasControlChar(text)) return { ok: false, reason: 'control-char' };
    return { ok: true, entry: { kind: 'text', value: text } };
  }

  const uri = String(item.uri || item.path || '').trim();
  const name = String(item.name || '').trim();

  if (kind === 'file') {
    if (name.length > policy.maxNameLen) return { ok: false, reason: 'name-too-long' };
    if (hasControlChar(name)) return { ok: false, reason: 'control-char' };
    const path = uri || name;
    if (!path) return { ok: false, reason: 'empty-file' };
    if (path.length > policy.maxUriLen) return { ok: false, reason: 'uri-too-long' };
    if (isUncPath(path)) return { ok: false, reason: 'unc-path' };
    if (!policy.allowFiles) return { ok: false, reason: 'file-not-allowed' };
    const ext = extOf(name || path);
    if (DANGEROUS_EXTS.has(ext)) return { ok: false, reason: 'dangerous-ext' };
    if (policy.safeExtsOnly && ext && !SAFE_FILE_EXTS.has(ext)) {
      return { ok: false, reason: 'ext-not-whitelisted' };
    }
    if (isDrivePath(path)) {
      return { ok: true, entry: { kind: 'file', path, name: name || '' } };
    }
    return { ok: true, entry: { kind: 'file', path, name: name || '' } };
  }

  // kind === 'uri'
  if (!uri) return { ok: false, reason: 'empty-uri' };
  if (uri.length > policy.maxUriLen) return { ok: false, reason: 'uri-too-long' };
  if (hasControlChar(uri)) return { ok: false, reason: 'control-char' };

  const lower = uri.toLowerCase();
  if (lower.startsWith('file:')) {
    if (!policy.allowFileUri) return { ok: false, reason: 'file-uri-not-allowed' };
    // 按前导斜杠数区分形态（不依赖正则）：
    //   file:///X   恰好 3 个斜杠 = 本机绝对路径；
    //   file://X    恰好 2 个斜杠 = 远程主机（authority），按 UNC 拒绝；
    //   file:////X  4 个及以上 = UNC（\\host\share 的常见编码），拒绝。
    let rest = uri.slice('file:'.length);
    let slashes = 0;
    while (rest[slashes] === '/') slashes++;
    if (slashes === 2 || slashes >= 4) return { ok: false, reason: 'unc-path' };
    let p;
    try {
      p = decodeURIComponent(rest.slice(slashes));
    } catch {
      return { ok: false, reason: 'bad-percent-encoding' };
    }
    if (isUncPath(p)) return { ok: false, reason: 'unc-path' };
    const ext = extOf(p);
    if (DANGEROUS_EXTS.has(ext)) return { ok: false, reason: 'dangerous-ext' };
    if (policy.safeExtsOnly && ext && !SAFE_FILE_EXTS.has(ext)) {
      return { ok: false, reason: 'ext-not-whitelisted' };
    }
    return { ok: true, entry: { kind: 'uri', scheme: 'file:', uri } };
  }

  let scheme = '';
  const colon = uri.indexOf(':');
  if (colon > 0) scheme = uri.slice(0, colon + 1).toLowerCase();
  if (scheme && !ALLOWED_URI_SCHEMES.has(scheme)) {
    return { ok: false, reason: 'scheme-not-allowed' };
  }
  // 无 scheme 的“裸字符串”不应当作链接导航，拒绝以免被拼出意外协议。
  if (!scheme) return { ok: false, reason: 'scheme-missing' };

  return { ok: true, entry: { kind: 'uri', scheme, uri } };
}

// 审计整批拖放条目。重复条目（同 kind+uri/name 归一键）去重计数；
// 超出 maxItems 整批拒绝；任一危险条目即整批拒绝（拖放是原子手势，不做
// “放一半”，避免用户误以为其余文件也已处理）。
function auditDroppedItems(items, override) {
  const policy = Object.assign({}, DEFAULT_POLICY, override || {});
  const list = Array.isArray(items) ? items : [];
  if (list.length === 0) {
    return { allow: false, reason: 'empty-drop', allowed: [], rejected: [], duplicates: 0 };
  }
  if (list.length > policy.maxItems) {
    return { allow: false, reason: 'too-many-items', allowed: [], rejected: list.slice(), duplicates: 0 };
  }

  const allowed = [];
  const rejected = [];
  const seen = new Set();
  let duplicates = 0;

  for (const raw of list) {
    const verdict = classifyDroppedItem(raw, policy);
    if (!verdict.ok) {
      rejected.push({ item: raw, reason: verdict.reason });
      continue;
    }
    const e = verdict.entry;
    const key = e.kind + '|' + (e.uri || e.path || e.value || '');
    if (seen.has(key)) {
      duplicates++;
      continue;
    }
    seen.add(key);
    allowed.push(e);
  }

  if (rejected.length > 0) {
    return { allow: false, reason: rejected[0].reason, allowed, rejected, duplicates };
  }
  return { allow: true, reason: '', allowed, rejected: [], duplicates };
}

// 供调用方在明确用户手势（如“始终允许拖放图片到本页”）时使用的宽松策略，
// 仍然拒绝危险扩展名 / UNC / 非 http(s) 脚本协议。
function permissivePolicy(override) {
  return Object.assign({}, DEFAULT_POLICY, {
    allowFiles: true,
    allowFileUri: true,
    safeExtsOnly: true,
  }, override || {});
}

module.exports = {
  DEFAULT_MAX_ITEMS,
  DEFAULT_MAX_URI_LEN,
  DANGEROUS_EXTS,
  SAFE_FILE_EXTS,
  ALLOWED_URI_SCHEMES,
  DEFAULT_POLICY,
  hasControlChar,
  extOf,
  isUncPath,
  isDrivePath,
  fileUriToPath,
  classifyDroppedItem,
  auditDroppedItems,
  permissivePolicy,
};
