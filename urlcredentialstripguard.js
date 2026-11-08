'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'url-empty',
  INVALID: 'url-invalid',
  CREDENTIALS: 'url-has-credentials',
  CREDENTIAL_REDIRECT: 'url-credential-redirect',
  LOG_LEAK: 'url-log-leak',
};

function splitUrl(value) {
  try {
    return new URL(String(value || '').trim());
  } catch (err) {
    return null;
  }
}

function stripCredentials(value) {
  const url = splitUrl(value);
  if (!url) return { ok: false, blocked: true, reason: REASON.INVALID, url: String(value || '').slice(0, 64) };
  const hadCredentials = Boolean(url.username || url.password);
  if (hadCredentials) {
    url.username = '';
    url.password = '';
  }
  return {
    ok: !hadCredentials,
    blocked: hadCredentials,
    reason: hadCredentials ? REASON.CREDENTIALS : REASON.OK,
    url: url.href,
    sanitized: url.href,
  };
}

function evaluateUrl(value, options) {
  const opts = options || {};
  if (typeof value !== 'string' || value.trim() === '') {
    return { ok: false, blocked: true, reason: REASON.EMPTY, url: '' };
  }
  const url = splitUrl(value);
  if (!url) return { ok: false, blocked: true, reason: REASON.INVALID, url: value.slice(0, 64) };
  if (url.username || url.password) {
    return { ok: false, blocked: true, reason: REASON.CREDENTIALS, url: url.origin + url.pathname, sanitized: url.origin + url.pathname };
  }
  if (opts.viaRedirect === true && opts.redirectTargetHasUserinfo === true) {
    return { ok: false, blocked: true, reason: REASON.CREDENTIAL_REDIRECT, url: url.origin + url.pathname };
  }
  if (opts.forLog === true && url.search && /(token|key|secret|password|session)=/i.test(url.search)) {
    return { ok: false, blocked: true, reason: REASON.LOG_LEAK, url: url.origin + url.pathname };
  }
  return { ok: true, blocked: false, reason: REASON.OK, url: url.href, sanitized: url.href };
}

function auditUrlBatch(list, options) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateUrl(item, options);
    if (result.blocked) {
      blocked += 1;
      findings.push({ url: result.url, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no url credential risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.url || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  stripCredentials,
  evaluateUrl,
  auditUrlBatch,
  describeFindings,
};
