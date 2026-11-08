'use strict';

const REASON = {
  OK: 'ok',
  UNTRUSTED_ORIGIN: 'untrusted-origin',
  INSECURE_ORIGIN: 'insecure-origin',
  LOOKALIKE: 'lookalike-domain',
  REDIRECT_CHAIN: 'cross-origin-redirect',
  MIME_MISMATCH: 'mime-mismatch',
  SHA_MISSING: 'hash-missing',
};

const BRANDS = ['github.com', 'gitlab.com', 'microsoft.com', 'mozilla.org', 'openjdk.net', 'adoptium.net', 'modrinth.com', 'curseforge.com', 'papermc.io', 'spigotmc.org', 'fabricmc.net', 'forge.net'];

function domainOf(value) {
  try {
    return new URL(value).hostname.toLowerCase();
  } catch (err) {
    return '';
  }
}

function editDistance(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = new Array(n + 1);
  for (let j = 0; j <= n; j += 1) dp[j] = j;
  for (let i = 1; i <= m; i += 1) {
    let prev = dp[0];
    dp[0] = i;
    for (let j = 1; j <= n; j += 1) {
      const tmp = dp[j];
      dp[j] = Math.min(dp[j] + 1, dp[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = tmp;
    }
  }
  return dp[n];
}

function isLookalike(host) {
  for (const brand of BRANDS) {
    if (host === brand) return false;
    if (host.endsWith('.' + brand)) return false;
    if (editDistance(host, brand) <= 1) return true;
    if (host.replace(/[^a-z]/g, '') === brand.replace(/[^a-z]/g, '') && host !== brand) return true;
  }
  return false;
}

function evaluate(request) {
  const req = request && typeof request === 'object' ? request : {};
  const host = domainOf(req.url);
  if (!host) return { allowed: false, reason: REASON.UNTRUSTED_ORIGIN };
  const url = new URL(req.url);
  if (url.protocol !== 'https:') return { allowed: false, reason: REASON.INSECURE_ORIGIN };
  if (isLookalike(host)) return { allowed: false, reason: REASON.LOOKALIKE, host };
  if (Array.isArray(req.trustedHosts) && req.trustedHosts.length > 0) {
    const trusted = req.trustedHosts.map((h) => String(h).toLowerCase());
    const match = trusted.some((t) => host === t || host.endsWith('.' + t));
    if (!match) return { allowed: false, reason: REASON.UNTRUSTED_ORIGIN, host };
  }
  if (Array.isArray(req.redirectChain)) {
    const first = domainOf(req.redirectChain[0]);
    if (first && first !== host) return { allowed: false, reason: REASON.REDIRECT_CHAIN, host: first };
  }
  if (req.expectedMime && req.actualMime && String(req.actualMime).toLowerCase() !== String(req.expectedMime).toLowerCase()) {
    return { allowed: false, reason: REASON.MIME_MISMATCH };
  }
  if (req.requireHash && !req.hash) return { allowed: false, reason: REASON.SHA_MISSING };
  return { allowed: true, reason: REASON.OK, host };
}

function applyDownloadSourceTrustGuard(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = evaluate(req);
  return {
    allowed: result.allowed,
    reason: result.reason,
    host: result.host || '',
    requireConfirm: result.allowed && !req.trustedConfirmed,
  };
}

function auditDownloadBatch(requests, options) {
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
  if (list.length === 0) return 'no download source risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyDownloadSourceTrustGuard,
  auditDownloadBatch,
  describeFindings,
  isLookalike,
};
