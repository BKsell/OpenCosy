'use strict';

const REASON = {
  OK: 'ok',
  PREFETCH_CROSS_SITE: 'cross-site-prefetch',
  PRECONNECT_CREDENTIALS: 'preconnect-with-credentials',
  DNS_OVER_HTTP: 'dns-over-plain-http',
  CNAME_CLOAKING: 'cname-cloaking',
  TRACKER_HOST: 'tracker-host',
};

const TRACKERS = ['doubleclick.net', 'google-analytics.com', 'googletagmanager.com', 'facebook.net', 'hotjar.com', 'segment.io', 'mixpanel.com', 'amplitude.com'];

function hostOf(value) {
  try {
    return new URL(value).hostname.toLowerCase();
  } catch (err) {
    return '';
  }
}

function siteKey(host) {
  const parts = String(host || '').split('.');
  if (parts.length < 2) return parts.join('.');
  return parts.slice(-2).join('.');
}

function isTracker(host) {
  return TRACKERS.some((t) => host === t || host.endsWith('.' + t));
}

function evaluate(request) {
  const req = request && typeof request === 'object' ? request : {};
  const target = String(req.url || '');
  const host = hostOf(target);
  if (!host) return { allowed: false, reason: REASON.TRACKER_HOST };
  if (isTracker(host)) return { allowed: false, reason: REASON.TRACKER_HOST, host };
  if (req.pageUrl && siteKey(hostOf(req.pageUrl)) !== siteKey(host)) {
    if (req.rel === 'dns-prefetch' || req.rel === 'preconnect' || req.rel === 'prefetch' || req.rel === 'prerender') {
      return { allowed: false, reason: REASON.PREFETCH_CROSS_SITE, host };
    }
  }
  if (req.protocol === 'http' || /^http:\/\//.test(target)) {
    return { allowed: false, reason: REASON.DNS_OVER_HTTP, host };
  }
  if (req.cnameTarget && siteKey(hostOf(req.cnameTarget)) !== siteKey(host)) {
    return { allowed: false, reason: REASON.CNAME_CLOAKING, host };
  }
  return { allowed: true, reason: REASON.OK, host };
}

function applyDnsLeakGuard(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = evaluate(req);
  return {
    allowed: result.allowed,
    reason: result.reason,
    host: result.host || '',
    action: result.allowed ? 'allow' : 'strip',
  };
}

function auditDnsBatch(hints, options) {
  const list = Array.isArray(hints) ? hints : [];
  const findings = [];
  let stripped = 0;
  for (const item of list) {
    const result = evaluate(item);
    if (!result.allowed) stripped += 1;
    if (result.reason !== REASON.OK) findings.push({ url: item && item.url, reason: result.reason });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { stripped, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no dns prefetch risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyDnsLeakGuard,
  auditDnsBatch,
  describeFindings,
  isTracker,
};
