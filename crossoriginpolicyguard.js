'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  INVALID: 'invalid-value',
  PERMISSIVE: 'permissive-value',
  DUPLICATE: 'duplicate-header',
  DOWNGRADED: 'downgraded',
  MALFORMED: 'malformed-header',
};

const CORP_VALUES = new Set(['same-origin', 'same-site', 'cross-origin']);
const COOP_VALUES = new Set(['unsafe-none', 'same-origin-allow-popups', 'same-origin', 'noopener-allow-popups']);
const COEP_VALUES = new Set(['unsafe-none', 'credentialless', 'require-corp']);

const HEADERS = {
  corp: 'cross-origin-resource-policy',
  coop: 'cross-origin-opener-policy',
  coep: 'cross-origin-embedder-policy',
};

const MAX_VALUE_LENGTH = 64;

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function headerList(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return null;
  const raw = headers[key];
  const list = Array.isArray(raw) ? raw : [raw];
  return { key, list };
}

function normalizeToken(value) {
  if (typeof value !== 'string') return '';
  return value.trim().toLowerCase();
}

function accessControlWildcard(headers) {
  const found = headerList(headers, 'access-control-allow-origin');
  if (!found) return false;
  return found.list.some((item) => normalizeToken(item) === '*');
}

function inspectSingle(headers, name, allowed) {
  const found = headerList(headers, name);
  if (!found) return { present: false, reason: REASON.MISSING, token: '', key: '' };
  const tokens = found.list.map(normalizeToken).filter((token) => token.length > 0);
  if (!tokens.length) return { present: true, reason: REASON.MALFORMED, token: '', key: found.key };
  const tooLong = tokens.some((token) => token.length > MAX_VALUE_LENGTH);
  if (tooLong) return { present: true, reason: REASON.INVALID, token: '', key: found.key };
  const valid = tokens.filter((token) => allowed.has(token));
  const invalid = tokens.filter((token) => !allowed.has(token));
  if (!valid.length) {
    return { present: true, reason: REASON.INVALID, token: '', key: found.key };
  }
  const reason = invalid.length ? REASON.INVALID : (tokens.length > 1 ? REASON.DUPLICATE : REASON.OK);
  return { present: true, reason, token: valid[0], key: found.key };
}

function inspectCrossOriginPolicy(headers) {
  const corp = inspectSingle(headers, HEADERS.corp, CORP_VALUES);
  const coop = inspectSingle(headers, HEADERS.coop, COOP_VALUES);
  const coep = inspectSingle(headers, HEADERS.coep, COEP_VALUES);
  const wildcard = accessControlWildcard(headers);
  const findings = [];
  const actions = [];

  if (corp.present) {
    if (corp.reason === REASON.INVALID || corp.reason === REASON.MALFORMED) {
      findings.push({ header: HEADERS.corp, reason: corp.reason, token: '' });
      actions.push({ key: corp.key, value: null });
    } else if (corp.token === 'cross-origin' && wildcard) {
      findings.push({ header: HEADERS.corp, reason: REASON.DOWNGRADED, token: 'same-origin' });
      actions.push({ key: corp.key, value: 'same-origin' });
    } else if (corp.token === 'cross-origin') {
      findings.push({ header: HEADERS.corp, reason: REASON.PERMISSIVE, token: corp.token });
    } else if (corp.reason === REASON.DUPLICATE) {
      findings.push({ header: HEADERS.corp, reason: REASON.DUPLICATE, token: corp.token });
      actions.push({ key: corp.key, value: corp.token });
    }
  }

  if (coop.present) {
    if (coop.reason === REASON.INVALID || coop.reason === REASON.MALFORMED) {
      findings.push({ header: HEADERS.coop, reason: coop.reason, token: '' });
      actions.push({ key: coop.key, value: null });
    } else if (coop.token === 'unsafe-none') {
      findings.push({ header: HEADERS.coop, reason: REASON.PERMISSIVE, token: coop.token });
    } else if (coop.reason === REASON.DUPLICATE) {
      findings.push({ header: HEADERS.coop, reason: REASON.DUPLICATE, token: coop.token });
      actions.push({ key: coop.key, value: coop.token });
    }
  }

  if (coep.present) {
    if (coep.reason === REASON.INVALID || coep.reason === REASON.MALFORMED) {
      findings.push({ header: HEADERS.coep, reason: coep.reason, token: '' });
      actions.push({ key: coep.key, value: null });
    } else if (coep.token === 'unsafe-none') {
      if (coop.token === 'same-origin') {
        findings.push({ header: HEADERS.coep, reason: REASON.DOWNGRADED, token: 'credentialless' });
        actions.push({ key: coep.key, value: 'credentialless' });
      } else {
        findings.push({ header: HEADERS.coep, reason: REASON.PERMISSIVE, token: coep.token });
      }
    } else if (coep.reason === REASON.DUPLICATE) {
      findings.push({ header: HEADERS.coep, reason: REASON.DUPLICATE, token: coep.token });
      actions.push({ key: coep.key, value: coep.token });
    }
  }

  return {
    changed: actions.length > 0,
    actions,
    findings,
    corp,
    coop,
    coep,
    wildcard,
  };
}

function applyCrossOriginPolicyGuard(headers) {
  const result = inspectCrossOriginPolicy(headers);
  for (const action of result.actions || []) {
    if (!action.key) continue;
    if (action.value === null) {
      delete headers[action.key];
    } else {
      headers[action.key] = action.value;
    }
  }
  return result;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.MISSING:
      return '未声明跨源隔离头';
    case REASON.INVALID:
      return '跨源隔离头取值非法，已移除';
    case REASON.PERMISSIVE:
      return '跨源隔离策略过于宽松';
    case REASON.DUPLICATE:
      return '跨源隔离头重复，已合并';
    case REASON.DOWNGRADED:
      return '跨源隔离策略已收紧';
    case REASON.MALFORMED:
      return '跨源隔离头为空，已移除';
    default:
      return '跨源隔离策略通过校验';
  }
}

module.exports = {
  REASON,
  HEADERS,
  CORP_VALUES,
  COOP_VALUES,
  COEP_VALUES,
  MAX_VALUE_LENGTH,
  inspectCrossOriginPolicy,
  applyCrossOriginPolicyGuard,
  describeReason,
};
