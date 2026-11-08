'use strict';

const REASON = {
  OK: 'ok',
  ACTIVE_BLOCKED: 'active-mixed-content',
  PASSIVE_UPGRADED: 'passive-upgraded',
  PASSIVE_LOOPBACK: 'loopback-allowed',
  INVALID: 'invalid-url',
};

const ACTIVE_TAGS = new Set(['script', 'iframe', 'object', 'embed', 'stylesheet', 'style', 'font', 'xhr', 'fetch', 'websocket', 'worker', 'manifest']);
const PASSIVE_TAGS = new Set(['img', 'image', 'video', 'audio', 'track', 'poster', 'background']);

function parse(value) {
  if (typeof value !== 'string' || !value) return null;
  try {
    return new URL(value);
  } catch (err) {
    return null;
  }
}

function isLoopback(hostname) {
  const h = String(hostname || '').toLowerCase();
  return h === 'localhost' || h === '127.0.0.1' || h === '[::1]' || h === '::1' || h.endsWith('.localhost');
}

function evaluate(request) {
  const req = request && typeof request === 'object' ? request : {};
  const resource = parse(req.resourceUrl);
  if (!resource) return { action: 'block', reason: REASON.INVALID, url: '' };
  if (resource.protocol !== 'http:') {
    return { action: 'allow', reason: REASON.OK, url: resource.href };
  }
  const kind = String(req.kind || '').toLowerCase();
  if (isLoopback(resource.hostname)) {
    return { action: 'allow', reason: REASON.PASSIVE_LOOPBACK, url: resource.href };
  }
  const secure = new URL(resource.href);
  secure.protocol = 'https:';
  if (ACTIVE_TAGS.has(kind)) {
    return { action: 'block', reason: REASON.ACTIVE_BLOCKED, url: resource.href, upgradeTo: secure.href };
  }
  if (PASSIVE_TAGS.has(kind)) {
    return { action: 'rewrite', reason: REASON.PASSIVE_UPGRADED, url: secure.href };
  }
  return { action: 'block', reason: REASON.ACTIVE_BLOCKED, url: resource.href, upgradeTo: secure.href };
}

function applyMixedContentGuard(request) {
  const result = evaluate(request);
  return {
    action: result.action,
    url: result.url,
    reason: result.reason,
    upgradeTo: result.upgradeTo || '',
    blocked: result.action === 'block',
  };
}

function classifyElement(tag, attr) {
  const name = String(tag || '').toLowerCase();
  const attribute = String(attr || '').toLowerCase();
  if (name === 'link' && ['stylesheet', 'manifest', 'preload'].includes(attribute)) return 'stylesheet';
  if (name === 'img' || name === 'picture') return 'img';
  if (name === 'script') return 'script';
  if (name === 'iframe') return 'iframe';
  if (name === 'video' || name === 'audio' || name === 'source') return 'media';
  return 'other';
}

function auditMixedContentBatch(items, options) {
  const list = Array.isArray(items) ? items : [];
  const findings = [];
  let blocked = 0;
  let rewritten = 0;
  for (const item of list) {
    const result = evaluate(item);
    if (result.action === 'block') blocked += 1;
    if (result.action === 'rewrite') rewritten += 1;
    if (result.reason !== REASON.OK) findings.push({ url: item && item.resourceUrl, reason: result.reason, action: result.action });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { blocked, rewritten, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no mixed content risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyMixedContentGuard,
  auditMixedContentBatch,
  classifyElement,
  describeFindings,
};
