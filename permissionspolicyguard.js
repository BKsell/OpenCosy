'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  WILDCARD_GRANT: 'wildcard-grant',
  UNKNOWN_FEATURE: 'unknown-feature',
  TOO_MANY: 'too-many',
  TOO_LONG: 'too-long',
};

const SENSITIVE_FEATURES = new Set([
  'camera',
  'microphone',
  'geolocation',
  'usb',
  'serial',
  'hid',
  'bluetooth',
  'clipboard-read',
  'clipboard-write',
  'display-capture',
  'screen-wake-lock',
  'idle-detection',
  'payment',
  'midi',
  'notifications',
  'local-fonts',
]);

const MAX_VALUE_LENGTH = 1024;
const MAX_FEATURES = 24;

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

function splitDirectives(value) {
  const parts = [];
  let depth = 0;
  let quote = '';
  let start = 0;
  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i];
    if (quote) {
      if (ch === quote) quote = '';
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === '(') depth += 1;
    if (ch === ')') depth = Math.max(0, depth - 1);
    if (ch === ',' && depth === 0) {
      parts.push(value.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(value.slice(start));
  return parts.map((part) => part.trim()).filter(Boolean);
}

function allowlistOf(directive) {
  const open = directive.indexOf('(');
  const close = directive.lastIndexOf(')');
  if (open < 0 || close < open) return null;
  const body = directive.slice(open + 1, close).trim();
  if (!body) return [];
  return body.split(/\s+/).map((token) => token.trim()).filter(Boolean);
}

function normalizeOriginToken(token) {
  return token.replace(/^"|"$/g, '').toLowerCase();
}

function directiveIsBroad(directive) {
  const allowlist = allowlistOf(directive);
  if (allowlist === null) {
    const eq = directive.indexOf('=');
    if (eq < 0) return false;
    const tail = directive.slice(eq + 1).trim().toLowerCase();
    return tail === '*';
  }
  return allowlist.some((token) => {
    const normalized = normalizeOriginToken(token);
    return normalized === '*' || normalized === 'https://*' || normalized === 'http://*';
  });
}

function rawFeatureName(directive) {
  const eq = directive.indexOf('=');
  const name = eq < 0 ? directive : directive.slice(0, eq);
  return name.trim();
}

function featureName(directive) {
  return rawFeatureName(directive).toLowerCase();
}

function parsePolicy(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, directives: [] };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, directives: [] };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.TOO_LONG, directives: [] };
  const directives = splitDirectives(text);
  if (!directives.length) return { reason: REASON.MALFORMED, directives: [] };
  if (directives.length > MAX_FEATURES) return { reason: REASON.TOO_MANY, directives };
  for (const directive of directives) {
    const name = rawFeatureName(directive);
    if (!name || !/^[a-z][a-z0-9-]{0,63}$/.test(name)) {
      return { reason: REASON.MALFORMED, directives };
    }
    if (directive.includes('(') !== directive.includes(')')) {
      return { reason: REASON.MALFORMED, directives };
    }
  }
  return { reason: REASON.OK, directives };
}

function inspectPermissionsPolicy(headers) {
  const key = headerKey(headers, 'permissions-policy');
  if (!key) return { changed: false, reason: REASON.MISSING, removed: [], kept: [] };
  const value = firstValue(headers, 'permissions-policy');
  const parsed = parsePolicy(value);
  if (parsed.reason !== REASON.OK) {
    return { changed: true, reason: parsed.reason, removed: [], kept: [] };
  }
  const removed = [];
  const kept = [];
  let broad = false;
  for (const directive of parsed.directives) {
    const name = featureName(directive);
    if (SENSITIVE_FEATURES.has(name) && directiveIsBroad(directive)) {
      removed.push(name);
      broad = true;
      continue;
    }
    if (!SENSITIVE_FEATURES.has(name) && directive.includes('(') && directiveIsBroad(directive)) {
      removed.push(name);
      broad = true;
      continue;
    }
    kept.push(directive);
  }
  if (!removed.length) {
    return { changed: false, reason: REASON.OK, removed, kept };
  }
  return {
    changed: true,
    reason: broad ? REASON.WILDCARD_GRANT : REASON.UNKNOWN_FEATURE,
    removed,
    kept,
  };
}

function applyPermissionsPolicyGuard(headers) {
  const result = inspectPermissionsPolicy(headers);
  if (!result.changed) return result;
  const key = headerKey(headers, 'permissions-policy');
  if (!key) return result;
  if (!result.kept.length) {
    delete headers[key];
    return result;
  }
  headers[key] = [result.kept.join(', ')];
  return result;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.WILDCARD_GRANT:
      return '站点把敏感能力授予任意来源';
    case REASON.MALFORMED:
      return 'Permissions-Policy 语法非法';
    case REASON.UNKNOWN_FEATURE:
      return '策略包含未知或已废弃能力';
    case REASON.TOO_MANY:
      return '策略能力条目超过预算';
    case REASON.TOO_LONG:
      return '策略取值超长';
    case REASON.MISSING:
      return '站点未声明权限策略';
    default:
      return '权限策略有效';
  }
}

module.exports = {
  REASON,
  SENSITIVE_FEATURES,
  MAX_VALUE_LENGTH,
  MAX_FEATURES,
  splitDirectives,
  parsePolicy,
  inspectPermissionsPolicy,
  applyPermissionsPolicyGuard,
  describeReason,
};
