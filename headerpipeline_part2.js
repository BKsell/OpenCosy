'use strict';

let d = {};

function applyOutboundHeaderHardening(targetSession, options) {
  const recordFp = !!(options && options.recordFp);
  targetSession.webRequest.onBeforeSendHeaders((details, callback) => {
    const headers = details.requestHeaders || {};
    headers['DNT'] = '1';
    headers['Sec-GPC'] = '1';
    headers['Upgrade-Insecure-Requests'] = '1';
    // UA 覆盖：非 default 策略时把请求头里的 User-Agent 换成策略取值。
    // 顶层导航的 UA 由 session.setUserAgent（applyUaPolicyToSession）兜底，
    // 这里覆盖 fetch/XHR/子资源等所有子请求，统计只计实际改写次数。
    if (d.uaPolicyState.mode !== d.uaPolicyCore.MODES.DEFAULT) {
      headers['User-Agent'] = d.resolveEffectiveUa();
      d.uaOverrideCount = d.uaPolicyCore.countUaOverrides(d.uaOverrideCount);
      d.uaLastOverrideAt = Date.now();
    }
    try { trimReferrerHeader(details, headers); } catch {}
    try {
      const removed = d.fpGuard.sanitizeOutboundHeaders(details, headers, {
        reduceClientHints: d.reduceClientHints,
        blockAdSignals: d.blockAdSignals,
        blockHyperlinkPing: d.blockHyperlinkPing,
        stripAcceptCh: d.stripAcceptCh,
        webrtcMode: d.webrtcMode,
      });
      if (recordFp) {
        const host = d.fpGuard.hostOf(details.url);
        if (host && removed.clientHints.length) {
          d.recordFpHit(host, 'client-hints', removed.clientHints);
        }
        if (host && removed.adSignals.length) {
          d.recordFpHit(host, 'ad-signals', removed.adSignals);
        }
      }
    } catch {}
    callback({ requestHeaders: headers });
  });
}

function applySecureDns() {
  d.loadDohLedger();
  const resolved = d.dohGuard.resolveControls({
    mode: d.dohMode,
    provider: d.dohProvider,
    customUrl: d.dohCustomUrl,
  });
  const sess = d.session.defaultSession;
  if (typeof sess.setHostResolverControls !== 'function') {
    d.dohActive = false;
    d.dohLedger.add({ mode: d.dohMode, event: 'unsupported', detail: 'no setHostResolverControls' });
    d.persistDohLedger();
    return;
  }
  try {
    sess.setHostResolverControls(resolved.controls);
    d.dohActive = resolved.mode !== d.dohGuard.SECURE_DNS_MODES.OFF;
    if (resolved.warning) {
      d.dohLedger.add({ mode: resolved.mode, event: 'fallback', detail: resolved.warning });
      d.recordSecurityEvent('fingerprint-blocked', 'warn',
        `安全 DNS 自定义服务器非法（${resolved.warning}），已回退到自动模式`, '');
    } else {
      d.dohLedger.add({
        mode: resolved.mode,
        event: 'applied',
        detail: resolved.template || resolved.mode,
      });
    }
    d.persistDohLedger();
  } catch (e) {
    d.dohActive = false;
    d.dohLedger.add({ mode: d.dohMode, event: 'error', detail: String(e && e.message || e).slice(0, 200) });
    d.persistDohLedger();
  }
}

function applyCookieHardening(headers, details) {
  try {
    const setCookieKey = Object.prototype.hasOwnProperty.call(headers, 'set-cookie')
      ? 'set-cookie'
      : (Object.prototype.hasOwnProperty.call(headers, 'Set-Cookie') ? 'Set-Cookie' : '');
    if (!setCookieKey) return [];
    const original = d.cookieGuard.extractSetCookieHeaders(headers);
    if (!original.length) return [];

    const result = d.cookieGuard.hardenSetCookieHeader(original, details, {
      blockThirdParty: d.blockThirdPartyCookies,
      hardenSameSite: d.hardenCookies,
    });
    headers[setCookieKey] = result.lines;
    if (!result.actions.length) return [];

    d.loadCookieLedger();
    d.cookieLedger.addMany(result.actions);
    d.persistCookieLedger();
    for (const a of result.actions) {
      // SameSite 补全是静默改写，只进台账不刷安全事件；剥离类才登记事件。
      if (a.action === 'samesite-default-lax') continue;
      d.recordSecurityEvent('cookie-blocked', 'warn',
        `已剥离不安全的 Cookie「${a.name}」（${a.reason}）`, a.host);
    }
    d.sendToRenderer('cookie-hardening-updated', d.cookieLedger.stats());
    return result.actions;
  } catch {
    return [];
  }
}

function buildRequestPipelineDeps() {
  return {
    flags: {
      get blockHyperlinkPing() { return d.blockHyperlinkPing; },
      get blockLocalNetworkAccess() { return d.blockLocalNetworkAccess; },
      get httpsOnlyEnabled() { return d.httpsOnlyEnabled; },
    },
    guards: {
      isHyperlinkPing: d.fpGuard.isHyperlinkPing.bind(d.fpGuard),
      hostOf: d.fpGuard.hostOf.bind(d.fpGuard),
      isTrackerRequest: d.isTrackerRequest,
      evaluatePnaRequest: d.pnaGuard.evaluatePnaRequest.bind(d.pnaGuard),
      evaluateRequestMethod: d.requestMethodGuard.evaluateRequestMethod.bind(d.requestMethodGuard),
      evaluatePluginResource: d.pluginResourceGuard.evaluatePluginResource.bind(d.pluginResourceGuard),
      classifyMixedContent: d.mixedGuard.classifyMixedContent.bind(d.mixedGuard),
      stripTrackingFromUrl: d.stripTrackingFromUrl,
      analyzeHostForSpoof: d.analyzeHostForSpoof,
      analyzeBrand: d.brandGuard.analyzeBrand.bind(d.brandGuard),
      analyzePhish: d.phishUrl.analyze.bind(d.phishUrl),
      isPrivateNetworkHost: d.isPrivateNetworkHost,
      isHttpException: d.isHttpExceptionHost,
    },
    record: {
      fpHit: d.recordFpHit,
      securityEvent: d.recordSecurityEvent,
      blockedTracker: d.recordBlockedTracker,
      pnaBlock: d.recordPnaBlock,
      brandSpoof: d.recordBrandSpoof,
    },
    notify: { sendToRenderer: d.sendToRenderer },
  };
}

function setupSecurityHeaders() {
  d.session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    const headers = d.hardenResponseHeaders(details.responseHeaders, details, { grade: true });
    callback({ responseHeaders: headers });
  });
  // 默认会话聚合指纹命中与请求量统计；三套过滤与隔离会话共用同一内核，避免行为分叉。
  applyOutboundHeaderHardening(d.session.defaultSession, { recordFp: true });
  d.applyWebRequestFiltering(d.session.defaultSession, { logRequests: true });
}

function trimReferrerHeader(details, headers) {
  const referrer = headers['Referer'] || headers['referer'];
  if (!referrer) return;
  const fromOrigin = d.originOf(referrer);
  const toOrigin = d.originOf(details.url);
  if (!fromOrigin || !toOrigin) return;
  if (fromOrigin === toOrigin) return; // 同源不裁剪
  const fromHttps = referrer.startsWith('https://');
  const toHttp = details.url.startsWith('http://');
  if (fromHttps && toHttp) {
    delete headers['Referer'];
    delete headers['referer'];
    return;
  }
  // 跨源：只暴露源，不暴露路径与查询串。
  const trimmed = fromOrigin === 'null' ? '' : fromOrigin + '/';
  headers['Referer'] = trimmed;
  delete headers['referer'];
}

function bindDeps(x) { d = x; }

module.exports = { applyOutboundHeaderHardening, applySecureDns, applyCookieHardening, buildRequestPipelineDeps, setupSecurityHeaders, trimReferrerHeader, bindDeps };
