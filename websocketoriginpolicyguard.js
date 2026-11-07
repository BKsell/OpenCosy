'use strict';

const REASON = {
  OK: 'ok',
  INVALID: 'invalid-url',
  INSECURE_WS: 'insecure-webSocket',
  ORIGIN_MISSING: 'origin-missing',
  ORIGIN_MISMATCH: 'origin-mismatch',
  CREDENTIALS: 'url-credentials',
  PORT_BLOCKED: 'port-blocked',
  HOST_BLOCKED: 'host-blocked',
};

const BLOCKED_PORTS = new Set(['1', '7', '9', '11', '13', '15', '17', '19', '25', '53', '110', '135', '137', '138', '139', '143', '389', '445', '465', '587', '636', '993', '995', '1433', '1521', '3306', '3389', '5432', '5900', '6379', '11211', '27017']);

function parse(value) {
  if (typeof value !== 'string' || !value) return null;
  try {
    return new URL(value);
  } catch (err) {
    return null;
  }
}

function normalizeOrigin(value) {
  const url = parse(value);
  if (!url) return '';
  return url.protocol + '//' + url.host;
}

function isSameSite(originA, originB) {
  const a = parse(originA);
  const b = parse(originB);
  if (!a || !b) return false;
  if (a.host === b.host && a.protocol === b.protocol) return true;
  const keyOf = (u) => u.hostname.toLowerCase().split('.').slice(-2).join('.');
  return keyOf(a) === keyOf(b);
}

function evaluate(request) {
  const req = request && typeof request === 'object' ? request : {};
  const url = parse(req.url);
  if (!url) return { allowed: false, reason: REASON.INVALID, url: '' };
  if (url.protocol !== 'wss:' && url.protocol !== 'ws:') {
    return { allowed: false, reason: REASON.INVALID, url: url.href };
  }
  if (url.username || url.password) {
    return { allowed: false, reason: REASON.CREDENTIALS, url: url.href };
  }
  if (url.protocol === 'ws:' && !req.allowInsecure) {
    const secure = new URL(url.href);
    secure.protocol = 'wss:';
    return { allowed: false, reason: REASON.INSECURE_WS, url: secure.href, rewrite: secure.href };
  }
  const port = url.port || (url.protocol === 'wss:' ? '443' : '80');
  if (BLOCKED_PORTS.has(port) && !req.allowBlockedPort) {
    return { allowed: false, reason: REASON.PORT_BLOCKED, url: url.href, port };
  }
  if (Array.isArray(req.blockedHosts)) {
    const lower = url.hostname.toLowerCase();
    if (req.blockedHosts.some((h) => String(h).toLowerCase() === lower)) {
      return { allowed: false, reason: REASON.HOST_BLOCKED, url: url.href };
    }
  }
  const origin = normalizeOrigin(req.origin);
  if (!origin) return { allowed: false, reason: REASON.ORIGIN_MISSING, url: url.href };
  if (Array.isArray(req.allowedOrigins) && req.allowedOrigins.length > 0) {
    const allowed = req.allowedOrigins.map(normalizeOrigin);
    if (!allowed.includes(origin)) {
      return { allowed: false, reason: REASON.ORIGIN_MISMATCH, url: url.href, origin };
    }
  } else if (!isSameSite(origin, url.href) && !req.allowCrossOrigin) {
    return { allowed: false, reason: REASON.ORIGIN_MISMATCH, url: url.href, origin };
  }
  return { allowed: true, reason: REASON.OK, url: url.href };
}

function applyWebSocketOriginPolicyGuard(request) {
  const result = evaluate(request);
  const headers = {};
  if (result.allowed) headers.Origin = normalizeOrigin(request && request.origin);
  return {
    allowed: result.allowed,
    reason: result.reason,
    url: result.url,
    rewrite: result.rewrite || '',
    headers,
  };
}

function auditWebSocketBatch(requests, options) {
  const list = Array.isArray(requests) ? requests : [];
  const findings = [];
  let denied = 0;
  for (const item of list) {
    const result = evaluate(item);
    if (!result.allowed) denied += 1;
    if (result.reason !== REASON.OK) findings.push({ url: item && item.url, reason: result.reason });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { denied, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no websocket origin risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyWebSocketOriginPolicyGuard,
  auditWebSocketBatch,
  describeFindings,
  isSameSite,
};
