'use strict';

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

function isObj(v) {
  return v !== null && typeof v === 'object';
}

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

// createFingerprintLedger 建一个按“主机 + 类别”聚合的有界台账。
// category ∈ client-hints / ad-signals / ping / accept-ch。
function createFingerprintLedger(limit) {
  const max = Number.isInteger(limit) && limit > 0 ? limit : 500;
  const rows = new Map(); // key -> row

  function keyFor(host, category) {
    return host + '\u0000' + category;
  }

  function record(host, category, signals) {
    const h = String(host || '').slice(0, 255);
    const cat = String(category || 'unknown').slice(0, 32);
    if (!h) return null;
    const key = keyFor(h, cat);
    const row = rows.get(key) || { host: h, category: cat, hits: 0, signals: new Set(), lastTime: 0 };
    row.hits += 1;
    row.lastTime = Date.now();
    if (Array.isArray(signals)) {
      for (const s of signals) {
        const v = String(s || '').slice(0, 64);
        if (v) row.signals.add(v);
      }
    }
    rows.set(key, row);
    if (rows.size > max) {
      // 淘汰最久未命中的一条，给高活跃主机让位。
      let oldestKey = null;
      let oldestTime = Infinity;
      for (const [k, r] of rows) {
        if (r.lastTime < oldestTime) { oldestTime = r.lastTime; oldestKey = k; }
      }
      if (oldestKey !== null) rows.delete(oldestKey);
    }
    return row;
  }

  function toJSON() {
    return {
      version: 1,
      rows: [...rows.values()].map((r) => ({
        host: r.host,
        category: r.category,
        hits: r.hits,
        lastTime: r.lastTime,
        signals: [...r.signals].sort(),
      })),
    };
  }

  function load(data) {
    rows.clear();
    if (!isObj(data) || !Array.isArray(data.rows)) return;
    for (const r of data.rows) {
      if (!isObj(r) || typeof r.host !== 'string') continue;
      const row = {
        host: r.host.slice(0, 255),
        category: String(r.category || 'unknown').slice(0, 32),
        hits: Number(r.hits) || 1,
        lastTime: Number(r.lastTime) || Date.now(),
        signals: new Set(),
      };
      if (Array.isArray(r.signals)) {
        for (const s of r.signals) row.signals.add(String(s).slice(0, 64));
      }
      rows.set(keyFor(row.host, row.category), row);
    }
  }

  function stats() {
    let hits = 0;
    const byCategory = { 'client-hints': 0, 'ad-signals': 0, ping: 0, 'accept-ch': 0 };
    for (const r of rows.values()) {
      hits += r.hits;
      byCategory[r.category] = (byCategory[r.category] || 0) + r.hits;
    }
    return { hosts: rows.size, hits, byCategory };
  }

  function entries() {
    return [...rows.values()]
      .map((r) => ({
        host: r.host,
        category: r.category,
        hits: r.hits,
        lastTime: r.lastTime,
        signals: [...r.signals].sort(),
      }))
      .sort((a, b) => b.lastTime - a.lastTime);
  }

  function clear() { rows.clear(); }
  function size() { return rows.size; }

  return { record, toJSON, load, stats, entries, clear, size, hostOf };
}

module.exports = {
  HIGH_ENTROPY_CLIENT_HINTS,
  AD_SIGNAL_HEADERS,
  ACCEPT_CH_RESPONSE_HEADERS,
  WEBRTC_POLICIES,
  DEFAULT_WEBRTC_POLICY,
  DEFAULT_OPTIONS,
  deleteHeaderCaseInsensitive,
  stripHeaderGroup,
  sanitizeOutboundHeaders,
  stripAcceptClientHints,
  isHyperlinkPing,
  normalizeWebRtcMode,
  resolveWebRtcPolicy,
  hostOf,
  createFingerprintLedger,
};
