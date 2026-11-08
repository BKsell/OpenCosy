'use strict';

// dntpolicy.js —— Do Not Track (DNT) 与 Global Privacy Control (GPC) 透传决策内核。
//
// 现代浏览器把“别追踪我”做成两个 HTTP 信号：
//   - DNT: 1            （老式，Data-Clean-Works 时代沿用至今）
//   - Sec-GPC: 1        （Global Privacy Control，WD 2023 起主流浏览器默认带）
//
// 问题：Electron 不会自动帮你加这两个头；如果不主动透传，站点收到的就是“无偏好”，
// 等于用户在系统级开了 DNT 也不被任何网站知晓。本模块只做“这次请求到底带不带、
// 带哪个头”的纯决策，不改网络栈，便于单测。
//
// 保守策略：
//   - 用户关闭了偏好 -> 两个头都不加（不替用户撒谎说我不想被追踪）；
//   - 只对 http(s) 出站子资源请求加；内部页面 / chrome-extension: / data: 不加；
//   - GPC 与 DNT 同时开启时两个头都发（站点各自识别自己支持的那个）；
//   - 顶层文档导航也带（DNT/GPC 本就是给站点看的，导航首跳更要带）；
//   - 出的头值固定为 "1"，不发 "0"（发 0 是冗余噪声，且老实现会被当成显式允许追踪）。

// 资源类型里，这些属于“浏览器内部/扩展”，不对外发追踪偏好信号。
const NON_WEB_TYPES = new Set([
  'mainFrame', // 见下方 decideRequest：顶层导航单独放行，不在这里排
]);

function isWebTarget(url) {
  return /^https?:\/\//i.test(String(url || ''));
}

// decideRequest 对一次 onBeforeSendHeaders 决策：返回要追加的请求头对象。
// prefs: { dnt: bool, gpc: bool }；details: { url, resourceType }。
// 返回 { headers: {DNT?, 'Sec-GPC'?}, active: bool }。active=false 表示本次不加任何头。
function decideRequest(prefs, details) {
  const p = prefs || {};
  const out = {};
  if (!p.dnt && !p.gpc) {
    return { headers: out, active: false };
  }
  const url = String((details && details.url) || '');
  if (!isWebTarget(url)) {
    return { headers: out, active: false };
  }
  // 扩展内部/非网页 origin 不发。
  if (/^(chrome-extension|file|data|blob):/i.test(url)) {
    return { headers: out, active: false };
  }
  if (p.dnt) out['DNT'] = '1';
  if (p.gpc) out['Sec-GPC'] = '1';
  return { headers: out, active: Object.keys(out).length > 0 };
}

// headerSummary 把决策压成一行可读标签，写进请求台账/调试面板。
function headerSummary(prefs, details) {
  const r = decideRequest(prefs, details);
  if (!r.active) return 'no-dnt-signal';
  const keys = Object.keys(r.headers);
  return 'dnt-signal:' + keys.join('+');
}

// describeSignal 给 UI 用的人类可读状态。
function describeSignal(prefs) {
  const p = prefs || {};
  if (p.dnt && p.gpc) return 'DNT + GPC 均已开启';
  if (p.dnt) return 'DNT 已开启';
  if (p.gpc) return 'GPC 已开启';
  return 'DNT/GPC 均关闭';
}

module.exports = {
  NON_WEB_TYPES,
  isWebTarget,
  decideRequest,
  headerSummary,
  describeSignal,
};
