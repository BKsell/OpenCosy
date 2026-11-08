'use strict';

// devtoolsguard.js —— 开发者工具内“在浏览器打开链接”（devtools-open-url）的收口内核。
//
// 威胁模型：
//   在 DevTools 的 Console / Network / Sources 面板里点击链接时，Electron 触发
//   webContents 的 'devtools-open-url' 事件；若不拦截，默认会把该 URL 交给系统外壳
//   （openExternal 语义）处理。问题在于：
//     - DevTools 里展示的 URL 完全由被调试页面/脚本控制，攻击者可以在控制台或网络
//       面板里诱导出 file:、javascript:、data: 或已注册的外部应用协议（mailto:、
//       自定义 scheme）链接，借一次点击直接唤起本地程序或执行外部协议处理器；
//     - 直接交给系统外壳绕过了浏览器既有的导航来源矩阵、外部协议确认与危险协议黑名单。
//
//   策略（浏览器最小权限）：
//     - 仅允许 http / https（以及本浏览器内部 cosy:）这三类“可安全转入标签页”的链接；
//       命中时不走系统外壳，而是由 main.js 用受控的 createNewTab 在应用内打开；
//     - 其余 scheme（file:、data:、javascript:、vbscript:、blob:、以及任意外部应用
//       协议）一律 preventDefault 并留痕，杜绝借 DevTools 唤起本地程序。
//
// 纯判定模块，main.js 负责 preventDefault、createNewTab 与 recordSecurityEvent。

const ACTION_OPEN_TAB = 'open-tab';
const ACTION_BLOCK = 'block';

const REASON_ALLOW_HTTP = 'allow-http';
const REASON_ALLOW_COSY = 'allow-cosy';
const REASON_MALFORMED = 'malformed-url';
const REASON_EMPTY = 'empty-url';
const REASON_DANGEROUS_SCHEME = 'dangerous-scheme';
const REASON_UNSUPPORTED_SCHEME = 'unsupported-scheme';

// 明确危险、绝不允许从 DevTools 直接转跳的 scheme（即便是应用内打开也不行）。
const DANGEROUS_SCHEMES = new Set([
  'file:', 'javascript:', 'vbscript:', 'data:', 'blob:', 'filesystem:', 'about:',
]);

// 允许转入受控标签页的标准 Web scheme。
const SAFE_WEB_SCHEMES = new Set(['http:', 'https:']);
const INTERNAL_SCHEME = 'cosy:';

function originFromUrl(rawUrl) {
  try {
    return new URL(rawUrl || '').origin;
  } catch {
    return '';
  }
}

// decideDevToolsUrl 判定一个 DevTools 请求打开的 URL。
// 返回 { action, url, scheme, origin, reason }。
//   ACTION_OPEN_TAB：main.js 应 preventDefault 后 createNewTab(url)（在应用内打开）；
//   ACTION_BLOCK：main.js 应 preventDefault 并留痕，不做任何转跳。
function decideDevToolsUrl(rawUrl) {
  const url = typeof rawUrl === 'string' ? rawUrl.trim() : '';
  if (url === '') {
    return { action: ACTION_BLOCK, url: '', scheme: '', origin: '', reason: REASON_EMPTY };
  }
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { action: ACTION_BLOCK, url, scheme: '', origin: '', reason: REASON_MALFORMED };
  }
  const scheme = (parsed.protocol || '').toLowerCase();

  if (DANGEROUS_SCHEMES.has(scheme)) {
    return { action: ACTION_BLOCK, url, scheme, origin: '', reason: REASON_DANGEROUS_SCHEME };
  }
  if (SAFE_WEB_SCHEMES.has(scheme)) {
    return { action: ACTION_OPEN_TAB, url: parsed.href, scheme, origin: parsed.origin, reason: REASON_ALLOW_HTTP };
  }
  if (scheme === INTERNAL_SCHEME) {
    return { action: ACTION_OPEN_TAB, url: parsed.href, scheme, origin: parsed.origin, reason: REASON_ALLOW_COSY };
  }
  // 其余一切外部应用协议（mailto:、tel:、自定义 scheme 等）默认拒绝：
  // DevTools 打开外部程序没有正当的浏览场景，风险远大于便利。
  return { action: ACTION_BLOCK, url, scheme, origin: '', reason: REASON_UNSUPPORTED_SCHEME };
}

function describeDevToolsReason(reason) {
  switch (reason) {
    case REASON_ALLOW_HTTP:
      return 'DevTools 链接已在应用内新标签页打开';
    case REASON_ALLOW_COSY:
      return 'DevTools 内部页面链接已在应用内打开';
    case REASON_EMPTY:
      return 'DevTools 请求打开的链接为空，已忽略';
    case REASON_MALFORMED:
      return 'DevTools 请求打开的 URL 非法，已拦截';
    case REASON_DANGEROUS_SCHEME:
      return 'DevTools 试图打开 file/data/javascript 等危险协议链接，已拦截';
    case REASON_UNSUPPORTED_SCHEME:
      return 'DevTools 试图唤起外部应用协议，已拦截（仅允许 http/https 在应用内打开）';
    default:
      return 'DevTools 链接请求';
  }
}

module.exports = {
  ACTION_OPEN_TAB,
  ACTION_BLOCK,
  REASON_ALLOW_HTTP,
  REASON_ALLOW_COSY,
  REASON_MALFORMED,
  REASON_EMPTY,
  REASON_DANGEROUS_SCHEME,
  REASON_UNSUPPORTED_SCHEME,
  DANGEROUS_SCHEMES,
  SAFE_WEB_SCHEMES,
  originFromUrl,
  decideDevToolsUrl,
  describeDevToolsReason,
};
