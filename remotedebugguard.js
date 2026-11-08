'use strict';

const REASON = {
  OK: 'ok',
  DISABLED: 'remote-debugging-disabled',
  WILDCARD_BIND: 'remote-debugging-wildcard-bind',
  PUBLIC_BIND: 'remote-debugging-public-bind',
  INSECURE_ADDRESS: 'remote-debugging-insecure-address',
  MISSING_ADDRESS: 'remote-debugging-address-required',
};

const MAX_ADDRESS = 256;
const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost', '[::1]']);

function normalizeAddress(value) {
  return String(value || '').trim().toLowerCase();
}

function evaluateRemoteDebug(input, options) {
  const opts = options || {};
  const item = input || {};
  if (item.enabled !== true) {
    return { ok: true, blocked: false, reason: REASON.DISABLED, address: null };
  }
  const address = item.address === undefined || item.address === null ? '' : normalizeAddress(item.address);
  if (address.length > MAX_ADDRESS) {
    return { ok: false, blocked: true, reason: REASON.INSECURE_ADDRESS, address };
  }
  if (address === '' && opts.requireAddress !== false) {
    return { ok: false, blocked: true, reason: REASON.MISSING_ADDRESS, address };
  }
  if (address === '0.0.0.0' || address === '::' || address === '*') {
    return { ok: false, blocked: true, reason: REASON.WILDCARD_BIND, address };
  }
  if (!LOOPBACK.has(address)) {
    return { ok: false, blocked: true, reason: REASON.PUBLIC_BIND, address };
  }
  if (item.allowPublic === true) {
    return { ok: false, blocked: true, reason: REASON.PUBLIC_BIND, address };
  }
  return { ok: true, blocked: false, reason: REASON.OK, address };
}

function evaluateSwitchList(switches) {
  const list = Array.isArray(switches) ? switches : [];
  const findings = [];
  let debug = null;
  for (const raw of list) {
    if (typeof raw !== 'string') continue;
    const text = raw.trim();
    if (!/^--?remote-debugging/i.test(text)) continue;
    const value = text.replace(/^--?remote-debugging(-port|-address)?=?/i, '');
    debug = { value, raw: text };
    break;
  }
  if (!debug) {
    return { ok: true, blocked: false, reason: REASON.DISABLED, findings };
  }
  const isPort = /^\d+$/.test(debug.value);
  const result = evaluateRemoteDebug({ enabled: true, address: isPort ? '127.0.0.1' : debug.value });
  if (result.blocked) findings.push({ reason: result.reason, address: result.address });
  return { ok: !result.blocked, blocked: result.blocked, reason: result.reason, findings, raw: debug.raw };
}

function auditRemoteDebugBatch(list) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateRemoteDebug(item);
    if (result.blocked) {
      blocked += 1;
      findings.push({ reason: result.reason, address: result.address });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no remote debugging risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.address || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateRemoteDebug,
  evaluateSwitchList,
  auditRemoteDebugBatch,
  describeFindings,
};
