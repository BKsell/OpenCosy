'use strict';

// mixedguard.js —— 混合内容（Mixed Content）判定纯逻辑内核（不依赖 Electron）。
//
// 场景：用户通过 HTTPS 打开的页面，却去加载 HTTP 的子资源。HTTP 子资源在传输
// 途中可被中间人改写，等于把整页 HTTPS 的保护拆掉。现代 Chrome 的策略是：
//   - 主动混合内容（脚本 / XHR / WebSocket / 子框架 / 样式 / 插件对象）
//     一律阻止——它们能直接执行或篡改页面；
//   - 被动混合内容（图片 / 音视频 / 字体 / ping）先自动升级成 HTTPS，
//     升级失败才放弃，不直接断网，尽量不破坏显示。
// Electron 的默认行为随版本而变，这里把策略显式实现并可在 onBeforeRequest
// 里统一执行，判定逻辑全部集中此处便于单测。

const ACTIVE_TYPES = new Set([
  'subFrame',
  'stylesheet',
  'script',
  'object',
  'xhr',
  'webSocket',
]);

const PASSIVE_TYPES = new Set([
  'image',
  'imageset',
  'media',
  'font',
  'ping',
  'cspReport',
]);

// 顶层导航本身不是“子资源”：用户主动打开 http:// 页面属于明文访问，由
// HTTPS-only 模式那条独立链路处理，这里绝不拦，否则会把整页导航掐断。
const TOPLEVEL_TYPES = new Set(['mainFrame']);

function lowerScheme(url) {
  try {
    return new URL(url).protocol.toLowerCase();
  } catch {
    return '';
  }
}

// isInsecureSubresourceScheme 报告子资源是不是明文协议（http / ws）。
function isInsecureSubresourceScheme(url) {
  const s = lowerScheme(url);
  return s === 'http:' || s === 'ws:';
}

// pageIsSecure 报告承载该子资源的页面是不是安全上下文（https / wss / file）。
// file:// 本地页面在规范上属于 potentially trustworthy，Chrome 同样会拦它
// 加载的明文主动混合内容，因此这里一并视为需要保护。
function pageIsSecure(pageUrl) {
  const s = lowerScheme(pageUrl);
  return s === 'https:' || s === 'wss:' || s === 'file:';
}

// upgradedURL 把 http 被动资源升级成 https。返回空串表示无法安全升级
// （例如 ws://，它不能靠一次 HTTP 重定向升级）。
function upgradedURL(url) {
  try {
    const u = new URL(url);
    if (u.protocol === 'http:') {
      u.protocol = 'https:';
      return u.toString();
    }
    return '';
  } catch {
    return '';
  }
}

// isLoopbackInsecure 允许开发者本地联调的明文回环资源豁免（http://localhost、
// 127.x / ::1 作为子资源主机时），公网明文一律不豁免。判定保守，只认字面量。
function isLoopbackInsecure(url) {
  try {
    const u = new URL(url);
    // WHATWG URL 里 IPv6 字面量的 hostname 带一对方括号，先剥掉再比对。
    const h = u.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
    if (h === 'localhost' || h.endsWith('.localhost')) return true;
    if (h === '::1') return true;
    if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
    return false;
  } catch {
    return false;
  }
}

// classifyMixedContent 判定一个子资源请求应被阻止、升级还是放行。
// 入参：
//   url          子资源 URL
//   pageUrl      发起它的顶层页面 URL（取 webContents.getURL()）
//   resourceType Electron webRequest 的 resourceType
// 返回 { action, reason, resourceType, url, upgrade? }，action 取值：
//   'block'   主动混合内容，必须阻止
//   'upgrade' 被动混合内容，重定向到 https
//   'allow'   非混合内容或不属于本策略管辖
function classifyMixedContent(url, pageUrl, resourceType) {
  const rt = String(resourceType || 'other');
  const base = { action: 'allow', reason: '', resourceType: rt, url: String(url || '') };

  if (!url || typeof url !== 'string') return base;
  if (TOPLEVEL_TYPES.has(rt)) return { ...base, reason: 'toplevel-navigation' };
  if (!pageIsSecure(pageUrl)) return { ...base, reason: 'insecure-page' };
  if (!isInsecureSubresourceScheme(url)) return { ...base, reason: 'secure-resource' };
  if (isLoopbackInsecure(url)) return { ...base, reason: 'loopback-exempt' };

  if (ACTIVE_TYPES.has(rt)) {
    return {
      action: 'block',
      reason: rt === 'webSocket' ? 'active-websocket' : 'active-mixed-content',
      resourceType: rt,
      url,
    };
  }

  if (PASSIVE_TYPES.has(rt)) {
    const upgrade = upgradedURL(url);
    if (upgrade) {
      return { action: 'upgrade', reason: 'passive-mixed-content', resourceType: rt, url, upgrade };
    }
    // 无法安全升级（如 ws 被错误标成被动类型）时，fail-closed 阻止。
    return { action: 'block', reason: 'unupgradable-passive', resourceType: rt, url };
  }

  // other 等不明类型不武断阻断，交给 Chromium 自身策略，避免误伤扩展/内部请求。
  return { ...base, reason: 'unclassified-type' };
}

module.exports = {
  ACTIVE_TYPES,
  PASSIVE_TYPES,
  TOPLEVEL_TYPES,
  isInsecureSubresourceScheme,
  pageIsSecure,
  upgradedURL,
  isLoopbackInsecure,
  classifyMixedContent,
};
