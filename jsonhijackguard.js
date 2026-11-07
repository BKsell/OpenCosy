'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'json-body-empty',
  CALLBACK_PARAM: 'json-callback-param',
  TOP_LEVEL_ARRAY: 'json-top-level-array',
  MIME_MISMATCH: 'json-mime-mismatch',
  NOSNIFF_MISSING: 'json-nosniff-missing',
  OVERSIZED: 'json-oversized',
};

const MAX_JSON = 1048576;
const CALLBACK_PARAMS = ['callback', 'jsonp', 'cb', 'jsoncallback'];

function evaluateJsonResponse(headers, body, options) {
  const opts = options || {};
  const list = Array.isArray(headers) ? headers : [];
  const text = typeof body === 'string' ? body : '';
  if (text.trim() === '') {
    return { ok: false, blocked: true, reason: REASON.EMPTY, findings: [] };
  }
  const findings = [];
  let contentType = '';
  let nosniff = false;
  for (const entry of list) {
    if (!Array.isArray(entry)) continue;
    const name = String(entry[0] || '').toLowerCase();
    if (name === 'content-type') contentType = String(entry[1] || '').toLowerCase();
    if (name === 'x-content-type-options' && String(entry[1] || '').toLowerCase().includes('nosniff')) nosniff = true;
  }
  if (contentType !== '' && !contentType.includes('application/json')) {
    findings.push({ reason: REASON.MIME_MISMATCH, contentType: contentType.slice(0, 48) });
  }
  if (!nosniff) findings.push({ reason: REASON.NOSNIFF_MISSING });
  const trimmed = text.trim();
  if (trimmed.startsWith('[')) findings.push({ reason: REASON.TOP_LEVEL_ARRAY });
  const firstParen = trimmed.indexOf('(');
  if (firstParen !== -1 && !trimmed.endsWith('}')) {
    findings.push({ reason: REASON.CALLBACK_PARAM, at: firstParen });
  }
  if (text.length > (opts.maxBytes || MAX_JSON)) findings.push({ reason: REASON.OVERSIZED, size: text.length });

  if (findings.length > 0) {
    const hardBlock = findings.some((f) => f.reason === REASON.CALLBACK_PARAM || f.reason === REASON.OVERSIZED);
    return { ok: false, blocked: hardBlock, reason: findings[0].reason, findings };
  }
  return { ok: true, blocked: false, reason: REASON.OK, findings: [] };
}

function rejectJsonp(queryString) {
  const query = String(queryString || '').replace(/^\\?/, '');
  if (query === '') return { rejected: false, param: '' };
  const pairs = query.split('&');
  for (const pair of pairs) {
    const eq = pair.indexOf('=');
    const name = (eq === -1 ? pair : pair.slice(0, eq)).toLowerCase();
    if (CALLBACK_PARAMS.includes(name)) {
      return { rejected: true, param: name };
    }
  }
  return { rejected: false, param: '' };
}

module.exports = {
  REASON,
  MAX_JSON,
  CALLBACK_PARAMS,
  evaluateJsonResponse,
  rejectJsonp,
};
