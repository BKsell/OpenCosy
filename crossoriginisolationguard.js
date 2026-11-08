'use strict';

const REASON = {
  OK: 'ok',
  INVALID: 'invalid-input',
  ISOLATION_DOWNGRADE: 'isolation-downgrade',
  COEP_MISSING: 'coep-missing',
  CORP_TOO_OPEN: 'corp-too-open',
  COOP_UNSAFE: 'coop-unsafe',
  CROSS_ORIGIN_EMBED: 'cross-origin-embed',
};

const SAFE_COOP = new Set(['same-origin', 'same-origin-allow-popups']);
const SAFE_CORP = new Set(['same-origin', 'same-site']);

function normalizeToken(value) {
  return String(value || '').trim().toLowerCase();
}

function parseUrl(value) {
  if (typeof value !== 'string' || !value) return null;
  try {
    return new URL(value);
  } catch (err) {
    return null;
  }
}

function sameHost(a, b) {
  return String(a || '').toLowerCase() === String(b || '').toLowerCase();
}

function buildIsolationPolicy(request) {
  const req = request && typeof request === 'object' ? request : {};
  const url = parseUrl(req.url);
  if (!url) {
    return { headers: {}, findings: [{ reason: REASON.INVALID, detail: 'url' }], isolated: false };
  }
  const findings = [];
  const headers = {};
  const requiresIsolation = Boolean(req.requiresIsolation);
  const embeds = Array.isArray(req.embeds) ? req.embeds : [];
  const crossOriginEmbeds = embeds.filter((item) => {
    const embed = parseUrl(item);
    return embed && !sameHost(embed.hostname, url.hostname);
  });
  if (requiresIsolation && crossOriginEmbeds.length > 0) {
    findings.push({ reason: REASON.CROSS_ORIGIN_EMBED, detail: crossOriginEmbeds[0] });
  }
  if (requiresIsolation && !req.coep) {
    findings.push({ reason: REASON.COEP_MISSING, detail: 'Cross-Origin-Embedder-Policy' });
  }
  const coop = normalizeToken(req.coop) || 'same-origin';
  if (!SAFE_COOP.has(coop)) {
    findings.push({ reason: REASON.COOP_UNSAFE, detail: coop });
    headers['Cross-Origin-Opener-Policy'] = 'same-origin';
  } else {
    headers['Cross-Origin-Opener-Policy'] = coop;
  }
  const corp = normalizeToken(req.corp) || 'same-origin';
  if (!SAFE_CORP.has(corp)) {
    findings.push({ reason: REASON.CORP_TOO_OPEN, detail: corp });
    headers['Cross-Origin-Resource-Policy'] = 'same-origin';
  } else {
    headers['Cross-Origin-Resource-Policy'] = corp;
  }
  if (requiresIsolation) {
    headers['Cross-Origin-Embedder-Policy'] = 'require-corp';
    headers['Cross-Origin-Opener-Policy'] = 'same-origin';
  }
  if (req.previousIsolated && !requiresIsolation) {
    findings.push({ reason: REASON.ISOLATION_DOWNGRADE, detail: 'page lost crossOriginIsolated' });
  }
  const isolated = headers['Cross-Origin-Embedder-Policy'] === 'require-corp' && headers['Cross-Origin-Opener-Policy'] === 'same-origin';
  return { headers, findings, isolated };
}

function applyCrossOriginIsolationGuard(response) {
  const res = response && typeof response === 'object' ? response : {};
  const policy = buildIsolationPolicy(res);
  const headers = Object.assign({}, res.headers || {});
  let changed = false;
  for (const key of Object.keys(policy.headers)) {
    if (headers[key] !== policy.headers[key]) {
      headers[key] = policy.headers[key];
      changed = true;
    }
  }
  return {
    changed,
    headers,
    isolated: policy.isolated,
    reason: policy.findings.length > 0 ? policy.findings[0].reason : REASON.OK,
    findings: policy.findings,
  };
}

function auditIsolationBatch(pages, options) {
  const list = Array.isArray(pages) ? pages : [];
  const findings = [];
  let isolated = 0;
  for (const page of list) {
    const result = buildIsolationPolicy(page);
    if (result.isolated) isolated += 1;
    for (const f of result.findings) findings.push({ url: page && page.url, reason: f.reason });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { isolated, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no isolation risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyCrossOriginIsolationGuard,
  auditIsolationBatch,
  buildIsolationPolicy,
  describeFindings,
};
