'use strict';

// requestpipeline.js —— 统一的 onBeforeRequest 决策内核（不依赖 Electron）。
//
// 背景：Electron 的 webRequest 处理器按 session 注册、不会从 defaultSession 继承。
// 默认会话与 fromPartition 的隔离 / 访客会话必须走完全一致的请求过滤，否则
// tracker / ping / 私网访问 / 混合内容 / 追踪参数 / HTTPS-only 在“本该更安全”的
// 分区里会全部失效。历史上这套逻辑内联在 main.js 默认会话中，分区会话漏挂。
//
// 本模块把“一条请求该 cancel / redirect / allow”以及对应的留痕副作用，收敛成
// 一个纯函数 decideRequest，所有外部能力（各守卫判定、台账、安全事件、向渲染
// 进程发横幅）通过 deps 注入，main.js 只负责把返回的决策映射成 Electron 回调。
// 这样默认会话与分区会话共用同一份、可用 node:test 直接验证决策顺序的内核。
//
// 决策顺序必须与历史默认会话严格一致（短路返回）：
//   1. 超链接打点 ping        -> cancel
//   2. 第三方 tracker         -> cancel
//   3. 私网访问 PNA           -> cancel
//   4. 混合内容主动块/被动升级 -> cancel / redirect
//   5. 顶层导航追踪参数剥离    -> redirect（只重定向一次）
//   6. 顶层导航钓鱼/同形字横幅  -> 仅副作用
//   7. HTTPS-only 升级        -> redirect
//   8. 其余                   -> allow
// 注意：redirect 不记请求量（带新 URL 会再进本管道），只有最终 cancel/allow 计数。

const DECISION_CANCEL = 'cancel';
const DECISION_REDIRECT = 'redirect';
const DECISION_ALLOW = 'allow';

// HTTPS-Only 的升级 / 例外判定复用纯内核 httpsonly.js（无正则、无 Electron 依赖），
// 避免在管道里手写 'https://' + slice(7) 把显式 :80/:8080 端口一起带崩。
const httpsOnly = require('./httpsonly');

function isHttpUrl(url) {
  return typeof url === 'string'
    && (url.startsWith('http://') || url.startsWith('https://'));
}

function noop() {}

// decideRequest 返回 { type, url?, reason? }：
//   { type:'cancel' }
//   { type:'redirect', url }
//   { type:'allow' }
// deps 字段（除判定开关外，缺省均为安全的空实现 / 空值）：
//   flags.blockHyperlinkPing / blockLocalNetworkAccess / httpsOnlyEnabled
//   guards.isHyperlinkPing(details,{blockHyperlinkPing}) -> bool
//   guards.hostOf(url) -> string
//   guards.isTrackerRequest(details) -> bool
//   guards.evaluatePnaRequest(details,{enabled}) -> {block,targetSpace,targetHost}
//   guards.classifyMixedContent(url,page,resourceType) -> {action,upgrade,resourceType}
//   guards.stripTrackingFromUrl(url) -> string
//   guards.analyzeHostForSpoof(host) -> truthy
//   guards.analyzeBrand(host) -> truthy
//   guards.analyzePhish(url) -> {level,signals,...} | null
//   guards.isPrivateNetworkHost(url) -> bool
//   record / notify 系列留痕与横幅回调。
function decideRequest(deps, details) {
  const d = deps || {};
  const flags = d.flags || {};
  const guards = d.guards || {};
  const rec = d.record || {};
  const notify = d.notify || {};

  const hostOf = guards.hostOf || (() => '');
  const recordFpHit = rec.fpHit || noop;
  const recordSecurityEvent = rec.securityEvent || noop;
  const recordBlockedTracker = rec.blockedTracker || noop;
  const recordPnaBlock = rec.pnaBlock || noop;
  const recordBrandSpoof = rec.brandSpoof || noop;
  const sendToRenderer = notify.sendToRenderer || noop;

  const url = (details && details.url) || '';
  const http = isHttpUrl(url);

  // 1) 超链接审计打点：静默取消，顶层导航不受影响。
  if (http) {
    try {
      if (guards.isHyperlinkPing
        && guards.isHyperlinkPing(details, { blockHyperlinkPing: !!flags.blockHyperlinkPing })) {
        const host = hostOf(url);
        recordFpHit(host, 'ping', ['hyperlink-ping']);
        recordSecurityEvent('fingerprint-blocked', 'info',
          `已阻止超链接打点请求（ping）：${url}`, host);
        return { type: DECISION_CANCEL, reason: 'ping' };
      }
    } catch { /* 判定异常不干预浏览 */ }
  }

  // 2) 第三方追踪 / 广告子资源：直接取消（不动顶层导航）。
  if (http && guards.isTrackerRequest && guards.isTrackerRequest(details)) {
    recordBlockedTracker(url);
    return { type: DECISION_CANCEL, reason: 'tracker' };
  }

  // 3) 私有网络访问：公网页面不得借浏览器打本机 / 内网 / 云元数据。
  if (http && guards.evaluatePnaRequest) {
    try {
      const verdict = guards.evaluatePnaRequest(details, {
        enabled: !!flags.blockLocalNetworkAccess,
      });
      if (verdict && verdict.block) {
        recordPnaBlock(details, verdict);
        recordSecurityEvent('pna-blocked', 'warn',
          `已阻止公网页面访问${verdict.targetSpace === 'loopback' ? '本机' :
            verdict.targetSpace === 'link-local' ? '链路本地/元数据' : '内网'}地址：${url}`,
          verdict.targetHost || '');
        return { type: DECISION_CANCEL, reason: 'pna' };
      }
    } catch { /* 判定异常不干预浏览 */ }
  }

  // 4) 混合内容：主动内容阻断，被动内容升级（升级请求带新 URL 再入，不成环）。
  if (guards.classifyMixedContent) {
    try {
      const page = (details && (details.documentURL || details.originURL)) || '';
      const mixed = guards.classifyMixedContent(url, page, details && details.resourceType);
      if (mixed && mixed.action === 'block') {
        recordSecurityEvent('mixed-content-blocked', 'warn',
          `已阻止混合内容（${mixed.resourceType}）：${url}（页面 ${page}）`,
          String(page).slice(0, 2048));
        return { type: DECISION_CANCEL, reason: 'mixed-block' };
      }
      if (mixed && mixed.action === 'upgrade' && mixed.upgrade) {
        return { type: DECISION_REDIRECT, url: mixed.upgrade, reason: 'mixed-upgrade' };
      }
    } catch { /* 退回 Chromium 默认策略 */ }
  }

  // 5/6) 顶层导航：剥追踪参数；随后发同形字 / 品牌 / 结构钓鱼横幅（只提示）。
  if (http && details && details.resourceType === 'mainFrame') {
    const stripped = guards.stripTrackingFromUrl ? guards.stripTrackingFromUrl(url) : '';
    if (stripped && stripped !== url) {
      return { type: DECISION_REDIRECT, url: stripped, reason: 'tracking-strip' };
    }
    try {
      const navHost = new URL(url).hostname;
      if (guards.analyzeHostForSpoof) {
        const spoof = guards.analyzeHostForSpoof(navHost);
        if (spoof) sendToRenderer('spoof-warning', spoof);
      }
      if (guards.analyzeBrand) {
        const brandHit = guards.analyzeBrand(navHost);
        if (brandHit) {
          recordBrandSpoof(brandHit);
          sendToRenderer('brand-spoof-warning', brandHit);
        }
      }
      if (guards.analyzePhish) {
        const phishHit = guards.analyzePhish(url);
        if (phishHit && phishHit.level === 'high') {
          const topSignal = Array.isArray(phishHit.signals) && phishHit.signals.length
            ? phishHit.signals[0] : null;
          recordBrandSpoof({
            hostname: phishHit.hostname,
            brand: phishHit.brand,
            reason: 'url-structural',
            hint: topSignal ? topSignal.detail : 'URL 结构高度可疑',
          });
          sendToRenderer('phish-url-warning', {
            hostname: phishHit.hostname,
            url: phishHit.url,
            score: phishHit.score,
            brand: phishHit.brand,
            signals: phishHit.signals,
          });
        }
      }
    } catch { /* 无效主机名忽略 */ }
  }

  // 7) HTTPS-only：可关闭；私网 / 回环主机、以及用户明确登记的 HTTP 例外站点保留
  //    http://。升级目标由 httpsonly 内核计算：默认端口（无端口/:80）收敛到 https
  //    默认 443；非标准端口不盲目改 scheme（对端在该端口说的是明文 HTTP，强行 TLS
  //    握手必失败），此时直接放行 http 并留痕，由后续“升级失败可回退”链路兜底。
  if (flags.httpsOnlyEnabled && url.startsWith('http://')) {
    let privateHost = false;
    try {
      privateHost = !!(guards.isPrivateNetworkHost && guards.isPrivateNetworkHost(url));
    } catch { privateHost = false; }
    let exceptionHost = false;
    try {
      exceptionHost = !!(guards.isHttpException && guards.isHttpException(url));
    } catch { exceptionHost = false; }
    if (!privateHost && !exceptionHost) {
      let upgrade;
      try {
        upgrade = httpsOnly.upgradeHttpUrl(url);
      } catch { upgrade = null; }
      if (upgrade && upgrade.ok) {
        return { type: DECISION_REDIRECT, url: upgrade.url, reason: 'https-only' };
      }
      if (upgrade && upgrade.reason === httpsOnly.REASON_NONSTANDARD_PORT) {
        recordSecurityEvent('https-only', 'info',
          `非标准端口不自动升级，保留 HTTP：${url}`, upgrade.host || '');
      }
      // private-host / 畸形 URL：落到下面的 allow，不干预浏览。
    }
  }

  // 8) 放行。
  return { type: DECISION_ALLOW };
}

// applyPipeline 把决策内核挂到某个 session 的 onBeforeRequest 上。
// noteAttempt 仅在最终 cancel/allow 时调用（redirect 不计数，避免重复）。
function applyPipeline(webRequest, deps, noteAttempt) {
  const count = typeof noteAttempt === 'function' ? noteAttempt : noop;
  webRequest.onBeforeRequest((details, callback) => {
    let decision;
    try {
      decision = decideRequest(deps, details);
    } catch {
      decision = { type: DECISION_ALLOW };
    }
    if (decision.type === DECISION_CANCEL) {
      count(details, true);
      return callback({ cancel: true });
    }
    if (decision.type === DECISION_REDIRECT && decision.url) {
      return callback({ redirectURL: decision.url });
    }
    count(details, false);
    callback({});
  });
}

module.exports = {
  DECISION_CANCEL,
  DECISION_REDIRECT,
  DECISION_ALLOW,
  isHttpUrl,
  decideRequest,
  applyPipeline,
};
