'use strict';

const { isObj } = require('./modutil');

// fpguard.js —— 出站指纹与跨站追踪收敛（纯内核，无 Electron 依赖，可单测）。
//
// 现代浏览器默认会向站点暴露大量“高熵”信号：
//   1. 高熵 Client Hints：完整 Chrome 版本、操作系统小版本、CPU 架构、位数、
//      设备型号等，经 Sec-CH-UA-* 请求头逐站发送，比传统 User-Agent 更易指纹；
//   2. 广告归因 / Topics 信号：Sec-Browsing-Topics、Attribution-Reporting-*
//      等请求头，把兴趣主题与归因链暴露给广告商；
//   3. <a ping> / sendBeacon 之外的 hyperlink auditing：resourceType=ping，
//      页面可在用户点击时静默向第三方打点；
//   4. 站点用 Accept-CH / Critical-CH 响应头“订阅”高熵提示，Critical-CH 还会
//      触发带新头的重试，是放大指纹面与制造额外请求的通道；
//   5. WebRTC：ICE 候选可能泄漏本机内网 IP 与真实公网 IP（穿透 VPN）。
//
// 本模块只负责纯判定与台账聚合，不触碰 session / fs，便于在主进程接线与 node 单测。

// 需要剥离的高熵 Client Hints（低熵的 sec-ch-uaplatform 保留，兼容性好）。
const HIGH_ENTROPY_CLIENT_HINTS = Object.freeze([
  'sec-ch-ua-full-version',
  'sec-ch-ua-full-version-list',
  'sec-ch-ua-platform-version',
  'sec-ch-ua-arch',
  'sec-ch-ua-bitness',
  'sec-ch-ua-model',
  'sec-ch-ua-wow64',
  'sec-ch-ua-form-factors',
]);

// 广告 / 归因 / 兴趣主题追踪请求头。
const AD_SIGNAL_HEADERS = Object.freeze([
  'sec-browsing-topics',
  'attribution-reporting-eligible',
  'attribution-reporting-support',
  'x-attribution-reporting',
  'sec-ad-availability',
]);

// 站点用来“订阅”高熵 Client Hints 的响应头（请求方向），以及会触发重试的
// Critical-CH。移除后浏览器不再缓存/补采这些高熵值。
const ACCEPT_CH_RESPONSE_HEADERS = Object.freeze([
  'accept-ch',
  'critical-ch',
]);

// WebRTC IP 处理策略白名单（对应 Electron / Chromium 的 setWebRTCIPHandlingPolicy）。
const WEBRTC_POLICIES = Object.freeze({
  strict: 'default_public_interface_only',   // 仅默认公网接口，不暴露内网 IP
  balanced: 'default_public_and_private_interfaces', // 允许 mDNS 混淆的内网候选
  legacy: 'default',                         // 不干预（兼容旧 P2P）
});

const DEFAULT_WEBRTC_POLICY = 'strict';

const DEFAULT_OPTIONS = Object.freeze({
  reduceClientHints: true,
  blockAdSignals: true,
  blockHyperlinkPing: true,
  stripAcceptCh: true,
  webrtcMode: DEFAULT_WEBRTC_POLICY,
});

// 头部名大小写不敏感地从对象中删除；返回被删的原始头部名（用于台账）。
function deleteHeaderCaseInsensitive(headers, lowerName) {
  if (!isObj(headers)) return null;
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lowerName) {
      delete headers[key];
      return key;
    }
  }
  return null;
}

// 从请求头中剥离一组目标头，返回实际被剥离的小写名列表（去重）。
function stripHeaderGroup(headers, names) {
  const removed = [];
  for (const name of names) {
    const original = deleteHeaderCaseInsensitive(headers, name);
    if (original !== null && !removed.includes(name)) removed.push(name);
  }
  return removed;
}

// sanitizeOutboundHeaders 在 onBeforeSendHeaders 里就地精简请求头。
// details 仅用于读取 resourceType（区分 ping）；headers 会被原地修改。
// 返回本次剥离明细，供主进程聚合台账：
//   { clientHints: [..], adSignals: [..] }
function sanitizeOutboundHeaders(details, headers, options) {
  const opts = Object.assign({}, DEFAULT_OPTIONS, options || {});
  const result = { clientHints: [], adSignals: [] };
  if (!isObj(headers)) return result;

  if (opts.reduceClientHints) {
    result.clientHints = stripHeaderGroup(headers, HIGH_ENTROPY_CLIENT_HINTS);
  }
  if (opts.blockAdSignals) {
    result.adSignals = stripHeaderGroup(headers, AD_SIGNAL_HEADERS);
  }
  return result;
}

// stripAcceptClientHints 在 onHeadersReceived 里移除站点订阅高熵提示的响应头。
// 就地修改响应头对象，返回被移除的小写名列表。
function stripAcceptClientHints(responseHeaders, options) {
  const opts = Object.assign({}, DEFAULT_OPTIONS, options || {});
  if (!opts.stripAcceptCh || !isObj(responseHeaders)) return [];
  return stripHeaderGroup(responseHeaders, ACCEPT_CH_RESPONSE_HEADERS);
}

// isHyperlinkPing 判定一个请求是否为超链接审计打点（Electron 用 resourceType
// 'ping' 表示 <a ping>；sendBeacon 在 Chromium 里也归入 ping）。
// 主进程可据此决定是否取消——顶层导航不受影响。
function isHyperlinkPing(details, options) {
  const opts = Object.assign({}, DEFAULT_OPTIONS, options || {});
  if (!opts.blockHyperlinkPing) return false;
  if (!isObj(details)) return false;
  if (details.resourceType === 'ping') return true;
  // 兜底：部分版本以 xhr 发送但带 Ping-To/Ping-From 头。
  const reqHeaders = details.requestHeaders || {};
  return !!(reqHeaders['Ping-To'] || reqHeaders['ping-to'] ||
    reqHeaders['Ping-From'] || reqHeaders['ping-from']);
}

// normalizeWebRtcMode 把设置值归一到合法策略键；非法值回退 strict。
function normalizeWebRtcMode(mode) {
  return Object.prototype.hasOwnProperty.call(WEBRTC_POLICIES, mode) ? mode : DEFAULT_WEBRTC_POLICY;
}

// resolveWebRtcPolicy 返回可直接喂给 session.setWebRTCIPHandlingPolicy 的字符串。
function resolveWebRtcPolicy(mode) {
  return WEBRTC_POLICIES[normalizeWebRtcMode(mode)];
}

// hostOf 从 URL 中安全取主机（失败返回空串）。
function hostOf(u) {
  try { return new URL(u).hostname || ''; } catch { return ''; }
}

module.exports = {
  ACCEPT_CH_RESPONSE_HEADERS,
  AD_SIGNAL_HEADERS,
  DEFAULT_OPTIONS,
  DEFAULT_WEBRTC_POLICY,
  HIGH_ENTROPY_CLIENT_HINTS,
  WEBRTC_POLICIES,
  deleteHeaderCaseInsensitive,
  hostOf,
  isHyperlinkPing,
  normalizeWebRtcMode,
  resolveWebRtcPolicy,
  sanitizeOutboundHeaders,
  stripAcceptClientHints,
  stripHeaderGroup
};
