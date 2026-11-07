'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'update-feed-empty',
  PLAINTEXT: 'update-feed-plaintext',
  HOST_NOT_ALLOWED: 'update-feed-host-not-allowed',
  CREDENTIALS: 'update-feed-credentials',
  REDIRECT_TO_HTTP: 'update-feed-redirect-downgrade',
  LOCAL_PATH: 'update-feed-local-path',
  CHANNEL_MISMATCH: 'update-feed-channel-mismatch',
};

const MAX_URL = 8192;
const ALLOWED_PROTOCOLS = new Set(['https:']);
const CHANNELS = new Set(['stable', 'beta', 'nightly']);

function hostAllowed(host, allowlist) {
  const name = String(host || '').toLowerCase();
  return allowlist.some((pattern) => {
    const item = String(pattern || '').toLowerCase();
    if (item.startsWith('*.')) return name.endsWith(item.slice(1)) && name.length > item.length - 2;
    return name === item;
  });
}

function evaluateUpdateFeed(config) {
  const cfg = config || {};
  const allowHosts = Array.isArray(cfg.allowHosts) ? cfg.allowHosts : [];
  if (!cfg.url) return { ok: false, blocked: true, reason: REASON.EMPTY, url: null };
  if (typeof cfg.url !== 'string' || cfg.url.length > MAX_URL) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, url: null };
  }
  if (/^(file|app|data|javascript):/i.test(cfg.url)) {
    return { ok: false, blocked: true, reason: REASON.LOCAL_PATH, url: cfg.url };
  }
  let url;
  try {
    url = new URL(cfg.url);
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, url: cfg.url };
  }
  if (!ALLOWED_PROTOCOLS.has(url.protocol)) {
    return { ok: false, blocked: true, reason: REASON.PLAINTEXT, url: url.href };
  }
  if (url.username || url.password) {
    return { ok: false, blocked: true, reason: REASON.CREDENTIALS, url: url.href };
  }
  if (!hostAllowed(url.hostname, allowHosts) && allowHosts.length > 0) {
    return { ok: false, blocked: true, reason: REASON.HOST_NOT_ALLOWED, url: url.href };
  }
  if (cfg.channel && !CHANNELS.has(String(cfg.channel).toLowerCase())) {
    return { ok: false, blocked: true, reason: REASON.CHANNEL_MISMATCH, channel: cfg.channel };
  }
  if (Array.isArray(cfg.redirects)) {
    for (const hop of cfg.redirects) {
      let next;
      try {
        next = new URL(String(hop));
      } catch (err) {
        return { ok: false, blocked: true, reason: REASON.REDIRECT_TO_HTTP, url: String(hop) };
      }
      if (next.protocol === 'http:' && !optsAllowHttp(cfg)) {
        return { ok: false, blocked: true, reason: REASON.REDIRECT_TO_HTTP, url: next.href };
      }
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, url: url.href, channel: String(cfg.channel || 'stable').toLowerCase() };
}

function optsAllowHttp(cfg) {
  return cfg && cfg.allowPlaintextRedirects === true;
}

function auditUpdateBatch(list) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateUpdateFeed(item);
    if (result.blocked) {
      blocked += 1;
      findings.push({ url: result.url, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no update feed risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.url || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateUpdateFeed,
  auditUpdateBatch,
  describeFindings,
  hostAllowed,
};
