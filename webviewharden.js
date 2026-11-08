'use strict';

// webviewharden.js —— <webview> 挂载（will-attach-webview）的完整安全策略。
//
// 本应用用 WebContentsView 承载页面，从不使用 <webview>，默认 webviewTag=false。
// will-attach-webview 是最后一道兜底：一旦未来某处打开了 webviewTag，或第三方
// 内容被嵌进 webview，挂载时携带的 webPreferences / params 完全由嵌入方控制，
// 可借此打开 nodeIntegration、关闭 webSecurity、指定任意 preload、甚至把 guest
// 挂到主会话分区（persist:default）窃取浏览器 Cookie。Electron 官方安全教程明确
// 要求在此事件里强制安全配置并校验 src。
//
// 本模块是纯函数：给定（webPreferences, params）产出阻断判定与一份“必须赋回”的
// 安全配置，不触碰 Electron 对象，方便单测。

const MAX_ADDITIONAL_ARGS = 16;
const MAX_ARG_LENGTH = 128;
// guest 分区不能与主浏览器会话重合，否则 guest 页面直接复用用户的登录态 / Cookie。
const FORBIDDEN_PARTITIONS = new Set(['', 'default', 'persist:default']);

function safeParse(raw) {
  if (typeof raw !== 'string' || raw === '') return null;
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

// reviewGuestSrc 只允许远程 http(s) 页面作为 webview guest。
// file:/data:/blob:/cosy:/javascript: 等一律拒绝：
//   - file:       guest 直接读本地文件；
//   - data:/blob: 内容由嵌入方即时生成，可携带任意脚本且来源不透明；
//   - cosy:       guest 进入浏览器特权内部页；
//   - 外部协议     唤起本机程序。
function reviewGuestSrc(src) {
  if (typeof src !== 'string' || src.trim() === '') {
    return { ok: false, reason: 'guest-src-empty' };
  }
  const u = safeParse(src.trim());
  if (!u) {
    return { ok: false, reason: 'guest-src-unparseable' };
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') {
    return { ok: false, reason: 'guest-src-scheme' };
  }
  if (u.username || u.password) {
    return { ok: false, reason: 'guest-src-userinfo' };
  }
  return { ok: true, url: u };
}

// sanitizeAdditionalArgs 过滤传给 guest preload 的附加参数。默认不允许任何参数：
// 它们虽不是 Chromium 开关，但会进入 guest preload 的 process.argv，嵌入方可借此
// 注入伪造配置；只有显式列入 allowlist 的参数才保留。数量 / 长度均有界。
function sanitizeAdditionalArgs(args, allowlist) {
  const allowed = allowlist instanceof Set
    ? allowlist
    : Array.isArray(allowlist) ? new Set(allowlist) : new Set();
  const kept = [];
  const dropped = [];
  if (!Array.isArray(args)) {
    return { kept, dropped, replaced: args !== undefined };
  }
  for (const arg of args) {
    if (typeof arg !== 'string') {
      dropped.push(String(arg).slice(0, MAX_ARG_LENGTH));
      continue;
    }
    if (kept.length >= MAX_ADDITIONAL_ARGS || arg.length > MAX_ARG_LENGTH) {
      dropped.push(arg.slice(0, MAX_ARG_LENGTH));
      continue;
    }
    if (allowed.has(arg)) {
      kept.push(arg);
    } else {
      dropped.push(arg);
    }
  }
  return { kept, dropped, replaced: dropped.length > 0 };
}

// buildSafePrefs 返回必须强制写回 guest webPreferences 的安全基线。
function buildSafePrefs() {
  return {
    nodeIntegration: false,
    nodeIntegrationInSubFrames: false,
    contextIsolation: true,
    sandbox: true,
    webSecurity: true,
    allowRunningInsecureContent: false,
    enableRemoteModule: false,
    webviewTag: false, // 禁止 guest 再嵌套 webview
    plugins: false,
    experimentalFeatures: false,
    enableBlinkFeatures: '', // 不授予任何非默认 Blink 特性
    allowPopups: false,
    preload: undefined, // guest 不允许携带 preload
    additionalArguments: [],
    additionalPreferencesBlob: undefined,
  };
}

// review 评估一次 webview 挂载。
// 入参：
//   webPreferences  事件给出的 guest 配置（会被读取，不在原对象上修改）
//   params          挂载参数（至少含 src / partition）
//   options.allowedArgs  允许透传的 additionalArguments 白名单，默认全拒绝
// 返回：
//   {
//     blocked: bool,          // true 时调用方必须 preventDefault
//     reasons: string[],      // 命中的问题（稳定枚举，便于审计）
//     prefs: object,          // 未阻断时应赋回 webPreferences 的安全配置
//   }
function review(webPreferences, params, options) {
  const reasons = [];
  const prefsIn = webPreferences && typeof webPreferences === 'object' ? webPreferences : {};
  const paramsIn = params && typeof params === 'object' ? params : {};

  const srcReview = reviewGuestSrc(paramsIn.src);
  if (!srcReview.ok) {
    reasons.push(srcReview.reason);
  }

  // 危险能力一旦出现即记录（即便最终配置会被覆盖，也要留痕定位是谁试图提权）。
  if (prefsIn.nodeIntegration === true) reasons.push('node-integration');
  if (prefsIn.nodeIntegrationInSubFrames === true) reasons.push('node-integration-subframes');
  if (prefsIn.contextIsolation === false) reasons.push('context-isolation-off');
  if (prefsIn.sandbox === false) reasons.push('sandbox-off');
  if (prefsIn.webSecurity === false) reasons.push('web-security-off');
  if (prefsIn.allowRunningInsecureContent === true) reasons.push('insecure-content');
  if (prefsIn.enableRemoteModule === true) reasons.push('remote-module');
  if (prefsIn.webviewTag === true) reasons.push('nested-webview-tag');
  if (prefsIn.plugins === true) reasons.push('plugins-enabled');
  if (prefsIn.experimentalFeatures === true) reasons.push('experimental-features');
  if (typeof prefsIn.enableBlinkFeatures === 'string' && prefsIn.enableBlinkFeatures.trim() !== '') {
    reasons.push('blink-features');
  }
  if (prefsIn.allowPopups === true) reasons.push('allow-popups');
  if (prefsIn.preload) reasons.push('guest-preload');
  if (prefsIn.additionalPreferencesBlob) reasons.push('preferences-blob');

  if (typeof prefsIn.partition === 'string' && FORBIDDEN_PARTITIONS.has(prefsIn.partition)) {
    reasons.push('shared-default-partition');
  }

  const safePrefs = buildSafePrefs();
  // 合法的自定义分区保留（guest 用独立分区是正常用法），只挡与主会话重合的分区。
  if (typeof prefsIn.partition === 'string' && !FORBIDDEN_PARTITIONS.has(prefsIn.partition)) {
    safePrefs.partition = prefsIn.partition;
  }
  const argReview = sanitizeAdditionalArgs(prefsIn.additionalArguments, options && options.allowedArgs);
  if (argReview.replaced) reasons.push('additional-args-stripped');
  safePrefs.additionalArguments = argReview.kept;

  return {
    blocked: !srcReview.ok,
    reasons,
    prefs: safePrefs,
  };
}

// describeReason 把审计枚举转成稳定中文说明。
function describeReason(reason) {
  const map = {
    'guest-src-empty': 'webview 缺少 src',
    'guest-src-unparseable': 'webview src 无法解析',
    'guest-src-scheme': 'webview src 不是 http/https，已拒绝',
    'guest-src-userinfo': 'webview src 携带账号密码',
    'node-integration': 'webview 试图开启 Node 集成',
    'node-integration-subframes': 'webview 试图在子框架开启 Node 集成',
    'context-isolation-off': 'webview 试图关闭上下文隔离',
    'sandbox-off': 'webview 试图关闭沙箱',
    'web-security-off': 'webview 试图关闭同源 / 安全策略',
    'insecure-content': 'webview 试图允许不安全内容',
    'remote-module': 'webview 试图启用 remote 模块',
    'nested-webview-tag': 'webview 试图再嵌套 webview',
    'plugins-enabled': 'webview 试图启用插件',
    'experimental-features': 'webview 试图启用实验特性',
    'blink-features': 'webview 试图授予额外 Blink 特性',
    'allow-popups': 'webview 试图允许弹窗',
    'guest-preload': 'webview 试图自带 preload 脚本',
    'preferences-blob': 'webview 携带额外偏好 Blob',
    'shared-default-partition': 'webview 试图挂载主会话分区',
    'additional-args-stripped': 'webview 附加参数已被过滤',
  };
  return Object.prototype.hasOwnProperty.call(map, reason) ? map[reason] : 'webview 不安全配置';
}

module.exports = {
  review,
  reviewGuestSrc,
  sanitizeAdditionalArgs,
  buildSafePrefs,
  describeReason,
  FORBIDDEN_PARTITIONS,
  MAX_ADDITIONAL_ARGS,
};
