'use strict';

const REASON = {
  OK: 'ok',
  TAG_DISABLED: 'webview-tag-disabled',
  MISSING_SRC: 'webview-missing-src',
  INVALID_SRC: 'webview-invalid-src',
  HOST_NOT_ALLOWED: 'webview-host-not-allowed',
  INSECURE_SRC: 'webview-insecure-src',
  CREDENTIALS: 'webview-credentials',
  NODE_EXPOSED: 'webview-node-exposed',
};

const MAX_SRC = 8192;

function parseSrc(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_SRC) return null;
  try {
    return new URL(value);
  } catch (err) {
    return null;
  }
}

function hostAllowed(host, allowlist) {
  const name = String(host || '').toLowerCase();
  return allowlist.some((pattern) => {
    const item = String(pattern || '').toLowerCase();
    if (item.startsWith('*.')) {
      const suffix = item.slice(1);
      return name.endsWith(suffix) && name.length > suffix.length;
    }
    return name === item;
  });
}

function evaluateWebview(input, options) {
  const opts = options || {};
  const item = input || {};
  const allowlist = Array.isArray(opts.allowHosts) ? opts.allowHosts : [];
  if (item.webviewTagEnabled !== true) {
    return { ok: false, blocked: true, reason: REASON.TAG_DISABLED, src: item.src || null };
  }
  const url = parseSrc(item.src);
  if (!url) return { ok: false, blocked: true, reason: item.src ? REASON.INVALID_SRC : REASON.MISSING_SRC, src: item.src || null };
  if (url.username || url.password) {
    return { ok: false, blocked: true, reason: REASON.CREDENTIALS, src: url.href };
  }
  if (url.protocol !== 'https:' && url.protocol !== 'file:') {
    return { ok: false, blocked: true, reason: REASON.INSECURE_SRC, src: url.href };
    }
  if (url.protocol === 'https:' && !hostAllowed(url.hostname, allowlist)) {
    return { ok: false, blocked: true, reason: REASON.HOST_NOT_ALLOWED, src: url.href };
  }
  if (item.allowpopups === true && opts.allowPopups !== true) {
    return { ok: false, blocked: true, reason: REASON.INSECURE_SRC, src: url.href };
  }
  if (item.nodeIntegration === true) {
    return { ok: false, blocked: true, reason: REASON.NODE_EXPOSED, src: url.href };
  }
  return { ok: true, blocked: false, reason: REASON.OK, src: url.href };
}

function auditWebviewBatch(list, options) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateWebview(item, options);
    if (result.blocked) {
      blocked += 1;
      findings.push({ src: result.src, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no webview risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.src || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateWebview,
  auditWebviewBatch,
  describeFindings,
  hostAllowed,
};
