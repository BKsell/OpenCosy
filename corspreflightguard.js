'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'preflight-empty',
  ORIGIN_WILDCARD_WITH_CREDENTIALS: 'preflight-wildcard-credentials',
  ORIGIN_WILDCARD: 'preflight-wildcard-origin',
  CREDENTIALS_NOT_BOOLEAN: 'preflight-credentials-value',
  MISSING_MAX_AGE: 'preflight-max-age',
  BAD_METHOD: 'preflight-method',
  MISSING_HEADERS: 'preflight-headers',
};

const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];

function headerValue(headers, name) {
  const list = Array.isArray(headers) ? headers : [];
  for (const entry of list) {
    if (!Array.isArray(entry)) continue;
    if (String(entry[0] || '').toLowerCase() === name) return String(entry[1] || '');
  }
  return null;
}

function evaluatePreflight(headers, options) {
  const opts = options || {};
  const list = Array.isArray(headers) ? headers : [];
  if (list.length === 0) return { ok: false, blocked: true, reason: REASON.EMPTY, findings: [] };
  const allowOrigin = headerValue(list, 'access-control-allow-origin');
  const allowCreds = headerValue(list, 'access-control-allow-credentials');
  const allowMethods = headerValue(list, 'access-control-allow-methods');
  const maxAge = headerValue(list, 'access-control-max-age');
  const allowHeaders = headerValue(list, 'access-control-allow-headers');
  const findings = [];
  if (allowOrigin === '*') {
    if (String(allowCreds || '').toLowerCase() === 'true') {
      findings.push({ reason: REASON.ORIGIN_WILDCARD_WITH_CREDENTIALS });
    } else {
      findings.push({ reason: REASON.ORIGIN_WILDCARD });
    }
  }
  if (allowCreds !== null && allowCreds.toLowerCase() !== 'true' && allowCreds.toLowerCase() !== 'false') {
    findings.push({ reason: REASON.CREDENTIALS_NOT_BOOLEAN, value: allowCreds.slice(0, 16) });
  }
  if (maxAge === null) findings.push({ reason: REASON.MISSING_MAX_AGE });
  else if (!/^[0-9]+$/.test(maxAge.trim())) findings.push({ reason: REASON.MISSING_MAX_AGE, value: maxAge.slice(0, 16) });
  if (allowMethods !== null) {
    for (const method of allowMethods.split(',')) {
      const token = method.trim().toUpperCase();
      if (token === '') continue;
      if (!METHODS.includes(token) || token === 'CONNECT' || token === 'TRACE') {
        findings.push({ reason: REASON.BAD_METHOD, method: token.slice(0, 16) });
      }
    }
  } else if (opts.requireMethods !== false) {
    findings.push({ reason: REASON.MISSING_HEADERS, header: 'access-control-allow-methods' });
  }
  if (allowHeaders === '*') findings.push({ reason: REASON.BAD_METHOD, method: '*' });
  if (findings.length > 0) {
    const blocked = findings.some((f) => f.reason === REASON.ORIGIN_WILDCARD_WITH_CREDENTIALS);
    return { ok: false, blocked, reason: findings[0].reason, findings };
  }
  return { ok: true, blocked: false, reason: REASON.OK, findings: [] };
}

module.exports = {
  REASON,
  METHODS,
  headerValue,
  evaluatePreflight,
};
