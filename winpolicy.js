'use strict';

// winpolicy.js —— BrowserWindow / WebContentsView 的 webPreferences 安全基线。
//
// 现状两个窗口创建点（主窗口、每个标签的 WebContentsView）都手写了一遍安全配置。
// 手写的问题是：未来新增窗口 / 第三方改动漏掉任意一项（nodeIntegration、
// contextIsolation、sandbox、webSecurity……）就是提权缺口。这里集中成一个纯策略：
//   1) 强制所有“必须为安全值”的选项，调用方传错也会被覆盖；
//   2) 删除会授予额外能力的开关（Blink 特性、实验特性、插件、webview 标签等）；
//   3) 校验 preload 脚本路径必须位于应用目录内，拒绝路径穿越 / 外部 preload；
//   4) 返回审计 findings，供主进程启动时记录，防止以后回退。
//
// 纯函数 + Node path，不直接依赖 electron，便于单测。

const path = require('path');

// 必须固定为安全值的选项。
const FORCED_SAFE = {
  nodeIntegration: false,
  nodeIntegrationInSubFrames: false,
  contextIsolation: true,
  sandbox: true,
  webSecurity: true,
  allowRunningInsecureContent: false,
  enableRemoteModule: false,
  webviewTag: false,
  plugins: false,
  experimentalFeatures: false,
};

// 这些选项若被赋予非空 / 非安全值，直接清空（属于额外能力授予）。
const STRIPPED_KEYS = ['enableBlinkFeatures'];

// 默认允许透传的“无害”选项；不在此表、也不是强制安全项的未知选项给 warn，
// 避免新版 Electron 出现默认不安全的能力时被静默带入。
const PASSTHROUGH_KEYS = new Set([
  'spellcheck',
  'preload',
  'partition',
  'zoomFactor',
  'defaultFontFamily',
  'defaultFontSize',
  'defaultMonospaceFontSize',
  'minimumFontSize',
  'defaultEncoding',
  'backgroundThrottling',
  'offscreen',
  'autoplayPolicy',
  'disableHtmlFullscreenWindowResize',
  'accessibleTitle',
  'safeDialogs',
  'safeDialogsMessage',
  'navigateOnDragDrop',
  'devTools',
  'webgl',
]);

function finding(severity, key, detail) {
  return { severity, key, detail };
}

// isInsideRoot 判断 target 是否位于 root 目录之内（含 root 本身），
// 基于 resolve/relative 做词面判定，挡住 ../ 穿越与跨盘符。
function isInsideRoot(target, root) {
  if (typeof target !== 'string' || typeof root !== 'string') return false;
  if (target.trim() === '' || root.trim() === '') return false;
  const resolvedTarget = path.resolve(target);
  const resolvedRoot = path.resolve(root);
  const rel = path.relative(resolvedRoot, resolvedTarget);
  if (rel === '') return true;
  // 任何以 '..' 开头的相对结果都表示跑到 root 外；跨盘符时 rel 是绝对路径同样被挡。
  return !rel.startsWith('..' + path.sep) && !path.isAbsolute(rel);
}

// reviewPreload 校验 preload 必须位于允许的根目录集合内。
function reviewPreload(preloadPath, allowedRoots) {
  if (preloadPath === undefined || preloadPath === null) {
    return { ok: true, value: undefined };
  }
  if (typeof preloadPath !== 'string' || preloadPath.trim() === '') {
    return { ok: false, value: undefined, detail: 'preload 路径非法' };
  }
  const roots = Array.isArray(allowedRoots) ? allowedRoots : [allowedRoots];
  const contained = roots.some((root) => isInsideRoot(preloadPath, root));
  if (!contained) {
    return { ok: false, value: undefined, detail: 'preload 不在应用目录内' };
  }
  return { ok: true, value: path.resolve(preloadPath) };
}

// harden 以输入配置为基础产出安全配置与审计结果。
// options:
//   preloadRoots  string|string[]  允许的 preload 根目录（一般传 __dirname）
//   requirePreload bool            是否必须提供 preload（标签视图 / 主窗口都要）
function harden(input, options) {
  const opts = options || {};
  const findings = [];
  const inPrefs = input && typeof input === 'object' ? input : {};
  const out = {};

  for (const key of Object.keys(inPrefs)) {
    if (Object.prototype.hasOwnProperty.call(FORCED_SAFE, key)) continue; // 稍后强制
    if (STRIPPED_KEYS.includes(key)) continue; // 直接丢弃
    if (key === 'preload') continue;           // 单独校验
    if (PASSTHROUGH_KEYS.has(key)) {
      out[key] = inPrefs[key];
    } else {
      findings.push(finding('warn', key, '未登记的 webPreferences 选项，默认不透传'));
    }
  }

  // 强制安全基线；若调用方给错值，记录一条 critical 便于定位回退点。
  for (const [key, safeValue] of Object.entries(FORCED_SAFE)) {
    if (Object.prototype.hasOwnProperty.call(inPrefs, key) &&
      inPrefs[key] !== safeValue) {
      findings.push(finding('critical', key, `不安全的 ${key} 配置已被强制覆盖`));
    }
    out[key] = safeValue;
  }

  for (const key of STRIPPED_KEYS) {
    if (inPrefs[key] !== undefined && inPrefs[key] !== '' && inPrefs[key] !== false) {
      findings.push(finding('warn', key, `${key} 已被清空`));
    }
  }

  const roots = opts.preloadRoots === undefined
    ? []
    : Array.isArray(opts.preloadRoots) ? opts.preloadRoots : [opts.preloadRoots];
  const preloadReview = reviewPreload(inPrefs.preload, roots);
  if (!preloadReview.ok) {
    findings.push(finding('critical', 'preload', preloadReview.detail));
  } else if (preloadReview.value) {
    out.preload = preloadReview.value;
  }
  if (opts.requirePreload && !out.preload) {
    findings.push(finding('critical', 'preload', '缺少受信 preload 脚本'));
  }

  return { prefs: out, findings };
}

// hasCritical 判断审计里是否存在必须阻断启动的关键问题（preload 越界等）。
function hasCritical(findings) {
  return Array.isArray(findings) && findings.some((f) => f && f.severity === 'critical');
}

module.exports = {
  harden,
  reviewPreload,
  isInsideRoot,
  hasCritical,
  FORCED_SAFE,
  PASSTHROUGH_KEYS,
};
