'use strict';

// attributionguard.js —— Attribution Reporting API（register-source/trigger、聚合报告）裁决内核。
//
// 威胁模型：
//   1. attribution-reporting 让广告网络在无三方 Cookie 下仍做跨站归因：register-source 与
//      register-trigger 分别由发布者/转化方页面触发，可重建用户跨站转化路径；
//   2. 报告端点（Attribution-Reporting-Redirect / register-source header）被设到明文 http 或
//      与注册方不同源的第三方主机，形成数据汇聚；
//   3. debug 报告（debug-reporting）携带未加噪明文，泄露可识别的点击/转化；
//   4. 事件级报告窗口/数量被放大，聚合报告的 epsilon=0 或极大 budget 等于去匿名；
//   5. 三方上下文调用注册接口属于隐式跨站埋点。
//
// 纯逻辑，对注册调用与报告配置做判定。

const AR_ALLOW = 'allow';
const AR_DENY = 'deny';

const AR_REASON = Object.freeze({
  BAD_CONTEXT: 'ar-bad-context',
  INSECURE_ORIGIN: 'ar-insecure-origin',
  API_DISABLED: 'ar-api-disabled',
  THIRD_PARTY_CONTEXT: 'ar-third-party-context',
  INSECURE_REPORT_ENDPOINT: 'ar-insecure-report-endpoint',
  ENDPOINT_CROSS_SITE: 'ar-endpoint-cross-site',
  BAD_ENDPOINT: 'ar-bad-endpoint',
  DEBUG_REPORTING: 'ar-debug-reporting',
  EVENT_REPORT_TOO_MANY: 'ar-event-report-too-many',
  PRIVACY_BUDGET_INVALID: 'ar-privacy-budget-invalid',
  EPSILON_TOO_LARGE: 'ar-epsilon-too-large',
  WINDOW_TOO_LARGE: 'ar-window-too-large',
});

function defaultAttributionPolicy() {
  return {
    requireHttps: true,
    apiEnabled: true,
    allowInThirdPartyContext: false,
    allowedReporterSites: [],
    requireSameSiteEndpoint: true,
    blockDebugReporting: true,
    maxEventReportsPerSource: 1,
    maxAggregatableReportsPerSource: 20,
    maxEventWindowSeconds: 30 * 24 * 3600, // 30 天
    maxEpsilon: 14, // Chrome 聚合噪声上限为 14（较小 epsilon 噪声更大更隐私）
    minEpsilon: 0,
  };
}

function siteOf(urlOrOrigin) {
  if (typeof urlOrOrigin !== 'string') return '';
  const i = urlOrOrigin.indexOf('://');
  if (i <= 0) return '';
  let rest = urlOrOrigin.slice(i + 3);
  for (const ch of ['/', '?', '#', ':']) {
    const p = rest.indexOf(ch);
    if (p >= 0) rest = rest.slice(0, p);
  }
  const labels = rest.toLowerCase().split('.');
  return labels.length >= 2 ? labels.slice(-2).join('.') : rest.toLowerCase();
}

function schemeOf(url) {
  if (typeof url !== 'string') return '';
  const c = url.indexOf(':');
  return c > 0 ? url.slice(0, c).toLowerCase() : '';
}

class AttributionGuard {
  constructor(policy) {
    this.policy = policy || defaultAttributionPolicy();
  }

  _gate(ctx) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return AR_REASON.BAD_CONTEXT;
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return AR_REASON.INSECURE_ORIGIN;
    if (!pol.apiEnabled) return AR_REASON.API_DISABLED;
    if (!pol.allowInThirdPartyContext && ctx.isTopFrame === false) {
      const site = siteOf(ctx.origin);
      const ok = pol.allowedReporterSites.some((s) => site === s || site.endsWith('.' + s));
      if (!ok) return AR_REASON.THIRD_PARTY_CONTEXT;
    }
    return '';
  }

  // decideRegister 裁决注册调用。
  // kind: 'source' | 'trigger'；registration: {endpoints:[urls], debugReporting, eventReports,
  //   aggregatableReports, eventWindowSeconds, epsilon}
  decideRegister(ctx, kind, registration) {
    const bad = this._gate(ctx);
    if (bad) return { decision: AR_DENY, reason: bad };
    if (kind !== 'source' && kind !== 'trigger') return { decision: AR_DENY, reason: AR_REASON.BAD_CONTEXT };
    const pol = this.policy;
    const reg = registration && typeof registration === 'object' ? registration : {};

    const endpoints = Array.isArray(reg.endpoints) ? reg.endpoints : [];
    if (endpoints.length === 0) return { decision: AR_DENY, reason: AR_REASON.BAD_ENDPOINT };
    const callerSite = siteOf(ctx.origin);
    for (const ep of endpoints) {
      const sch = schemeOf(ep);
      if (sch !== 'https' && sch !== 'http') return { decision: AR_DENY, reason: AR_REASON.BAD_ENDPOINT, endpoint: ep };
      if (sch !== 'https') return { decision: AR_DENY, reason: AR_REASON.INSECURE_REPORT_ENDPOINT, endpoint: ep };
      if (pol.requireSameSiteEndpoint) {
        const epSite = siteOf(ep);
        const ok = pol.allowedReporterSites.some((s) => epSite === s || epSite.endsWith('.' + s));
        if (epSite !== callerSite && !ok) {
          return { decision: AR_DENY, reason: AR_REASON.ENDPOINT_CROSS_SITE, endpoint: ep, site: epSite };
        }
      }
    }

    if (pol.blockDebugReporting && reg.debugReporting === true) {
      return { decision: AR_DENY, reason: AR_REASON.DEBUG_REPORTING };
    }

    if (kind === 'source') {
      const ev = typeof reg.eventReports === 'number' ? reg.eventReports : 0;
      const agg = typeof reg.aggregatableReports === 'number' ? reg.aggregatableReports : 0;
      if (ev > pol.maxEventReportsPerSource) {
        return { decision: AR_DENY, reason: AR_REASON.EVENT_REPORT_TOO_MANY, count: ev };
      }
      if (agg > pol.maxAggregatableReportsPerSource) {
        return { decision: AR_DENY, reason: AR_REASON.EVENT_REPORT_TOO_MANY, count: agg, kind: 'aggregatable' };
      }
      if (reg.eventWindowSeconds !== undefined) {
        const w = reg.eventWindowSeconds;
        if (typeof w !== 'number' || !Number.isFinite(w) || w <= 0) {
          return { decision: AR_DENY, reason: AR_REASON.WINDOW_TOO_LARGE };
        }
        if (w > pol.maxEventWindowSeconds) return { decision: AR_DENY, reason: AR_REASON.WINDOW_TOO_LARGE, seconds: w };
      }
      if (reg.epsilon !== undefined) {
        const e = reg.epsilon;
        if (typeof e !== 'number' || !Number.isFinite(e) || e < pol.minEpsilon) {
          return { decision: AR_DENY, reason: AR_REASON.PRIVACY_BUDGET_INVALID };
        }
        if (e > pol.maxEpsilon) return { decision: AR_DENY, reason: AR_REASON.EPSILON_TOO_LARGE, epsilon: e };
      }
    }
    return { decision: AR_ALLOW, reason: '' };
  }
}

module.exports = {
  AR_ALLOW, AR_DENY, AR_REASON,
  defaultAttributionPolicy, siteOf, schemeOf, AttributionGuard,
};
