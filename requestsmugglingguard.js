'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'framing-empty',
  CL_TE_CONFLICT: 'framing-conflict',
  DUPLICATE_CL: 'framing-duplicate-cl',
  BAD_CL: 'framing-bad-content-length',
  TE_UNKNOWN: 'framing-te-unknown',
  OBS_FOLD: 'framing-obs-fold',
  BAD_CHUNK: 'framing-bad-chunk-size',
};

const TE_VALUES = ['chunked', 'identity'];

function evaluateFraming(headers) {
  const list = Array.isArray(headers) ? headers : [];
  if (list.length === 0) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, findings: [] };
  }
  const findings = [];
  let clCount = 0;
  let clValue = '';
  const teValues = [];
  for (const entry of list) {
    if (!Array.isArray(entry)) continue;
    const name = String(entry[0] || '').trim().toLowerCase();
    const raw = String(entry[1] || '');
    if (raw.includes('\\r') || raw.includes('\\n')) findings.push({ reason: REASON.OBS_FOLD, header: name });
    if (name === 'content-length') {
      clCount += 1;
      clValue = clValue === '' ? raw.trim() : clValue + ',' + raw.trim();
    }
    if (name === 'transfer-encoding') {
      for (const part of raw.split(',')) teValues.push(part.trim().toLowerCase());
    }
  }
  if (clCount > 1 || (!clValue.includes(',') && clValue.includes('\u000b'))) {
    findings.push({ reason: REASON.DUPLICATE_CL, value: clValue.slice(0, 48) });
  }
  if (clValue !== '' && !/^[0-9]+$/.test(clValue)) {
    findings.push({ reason: REASON.BAD_CL, value: clValue.slice(0, 48) });
  }
  for (const value of teValues) {
    if (value === '' || !TE_VALUES.includes(value)) {
      findings.push({ reason: REASON.TE_UNKNOWN, value: value.slice(0, 32) });
    }
  }
  if (clValue !== '' && teValues.length > 0) {
    findings.push({ reason: REASON.CL_TE_CONFLICT, cl: clValue.slice(0, 24), te: teValues.join(',') });
  }
  if (teValues.includes('chunked')) {
    const idx = teValues.indexOf('chunked');
    if (idx !== teValues.length - 1) findings.push({ reason: REASON.BAD_CHUNK, order: teValues.join(',') });
  }
  if (findings.length > 0) {
    const blocked = findings.some((f) => f.reason === REASON.CL_TE_CONFLICT || f.reason === REASON.DUPLICATE_CL);
    return { ok: false, blocked, reason: findings[0].reason, findings };
  }
  return { ok: true, blocked: false, reason: REASON.OK, findings: [] };
}

function describeFraming(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'framing headers accepted';
  return list.map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  TE_VALUES,
  evaluateFraming,
  describeFraming,
};
