'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  TOO_MANY: 'too-many-tokens',
  UNDECODABLE: 'undecodable-token',
  EXPIRED: 'expired-token',
  FOREIGN_ORIGIN: 'foreign-origin-claim',
  SUBDOMAIN_GRANT: 'subdomain-grant',
  HIGH_RISK_FEATURE: 'high-risk-feature',
};

const HEADER = 'origin-trial';
const MAX_VALUE_LENGTH = 4096;
const MAX_TOKENS = 8;
const HIGH_RISK_FEATURES = new Set([
  'fledge',
  'privateaggregation',
  'sharedstorage',
  'attributionreportingcrossappweb',
  'privacysandboxadsapis',
  'topics',
  'interestgroupauction',
]);

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function firstValue(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return '';
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' ? value : '';
}

function deleteHeader(headers, name) {
  const key = headerKey(headers, name);
  if (key) delete headers[key];
}

function decodeToken(token) {
  const trimmed = token.trim();
  if (!trimmed || trimmed.length < 32 || !/^[A-Za-z0-9_\-+/=]+$/.test(trimmed)) return null;
  try {
    const decoded = Buffer.from(trimmed.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const parsed = JSON.parse(decoded);
    if (!parsed || typeof parsed !== 'object') return null;
    return parsed;
  } catch (err) {
    return null;
  }
}

function originOf(value) {
  if (typeof value !== 'string' || !value) return '';
  try {
    return new URL(value).origin;
  } catch (err) {
    return '';
  }
}

function inspectOriginTrial(value, docOrigin, now) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, features: [] };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, features: [] };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, features: [] };

  const tokens = text.split(',').map((token) => token.trim()).filter(Boolean);
  if (tokens.length > MAX_TOKENS) return { reason: REASON.TOO_MANY, features: [] };

  const reference = typeof now === 'number' && Number.isFinite(now) ? now : Date.now();
  const base = originOf(docOrigin) || docOrigin;
  const kept = [];
  let reason = REASON.OK;
  const note = (next) => {
    if (reason === REASON.OK) reason = next;
  };

  for (const token of tokens) {
    const payload = decodeToken(token);
    if (!payload) {
      note(REASON.UNDECODABLE);
      continue;
    }
    const feature = typeof payload.feature === 'string' ? payload.feature.toLowerCase() : '';
    const claimedOrigin = originOf(payload.origin);
    if (feature && HIGH_RISK_FEATURES.has(feature)) {
      note(REASON.HIGH_RISK_FEATURE);
      continue;
    }
    if (!claimedOrigin) {
      note(REASON.MALFORMED);
      continue;
    }
    if (base && claimedOrigin !== base) {
      note(REASON.FOREIGN_ORIGIN);
      continue;
    }
    if (payload.isSubdomain === true) {
      note(REASON.SUBDOMAIN_GRANT);
      continue;
    }
    if (typeof payload.expiry === 'number' && payload.expiry * 1000 <= reference) {
      note(REASON.EXPIRED);
      continue;
    }
    kept.push(feature || 'unknown-feature');
  }

  if (kept.length === 0 && reason !== REASON.OK) return { reason, features: [] };
  return { reason, features: kept };
}

function encodeToken(payload) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  return body.replace(/=+$/, '');
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'origin-trial 取值合规';
    case REASON.MISSING:
      return '响应未声明 origin-trial';
    case REASON.MALFORMED:
      return 'origin-trial 取值非法';
    case REASON.OVERLONG:
      return 'origin-trial 超长';
    case REASON.TOO_MANY:
      return 'origin-trial 令牌数量超出上限，已剥除';
    case REASON.UNDECODABLE:
      return 'origin-trial 令牌无法解码，已剔除';
    case REASON.EXPIRED:
      return 'origin-trial 令牌已过期，已剔除';
    case REASON.FOREIGN_ORIGIN:
      return 'origin-trial 令牌声明的来源与当前站点不符，已剔除';
    case REASON.SUBDOMAIN_GRANT:
      return 'origin-trial 令牌覆盖子域，已剔除';
    case REASON.HIGH_RISK_FEATURE:
      return 'origin-trial 令牌涉及高风险特性，已剔除';
    default:
      return 'origin-trial 未识别状态';
  }
}

function applyOriginTrialGuard(headers, docOrigin, now) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, features: [] };
  const result = inspectOriginTrial(value, docOrigin, now);
  if (result.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, features: result.features };
  }
  deleteHeader(headers, HEADER);
  return { changed: true, reason: result.reason, features: [] };
}

module.exports = {
  REASON,
  HEADER,
  inspectOriginTrial,
  applyOriginTrialGuard,
  encodeToken,
  describeReason,
};
