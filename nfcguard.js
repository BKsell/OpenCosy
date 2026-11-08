'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'nfc-empty',
  INSECURE: 'nfc-insecure',
  BAD_RECORD: 'nfc-bad-record',
  SECRET_URI: 'nfc-secret-uri',
  OVERSIZED: 'nfc-oversized',
};

const MAX_RECORDS = 16;
const MAX_BYTES = 4096;

function evaluateNfcRequest(request) {
  const req = request || {};
  const origin = typeof req.origin === 'string' ? req.origin.trim() : '';
  if (origin === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  if (!origin.toLowerCase().startsWith('https://')) {
    return { ok: false, blocked: true, reason: REASON.INSECURE, origin: origin.slice(0, 48) };
  }
  const records = Array.isArray(req.records) ? req.records : [];
  if (records.length > MAX_RECORDS) {
    return { ok: false, blocked: true, reason: REASON.OVERSIZED, count: records.length };
  }
  for (const record of records) {
    const item = record || {};
    if (typeof item.recordType !== 'string' || item.recordType === '') {
      return { ok: false, blocked: true, reason: REASON.BAD_RECORD, field: 'recordType' };
    }
    if (typeof item.data !== 'string') {
      return { ok: false, blocked: true, reason: REASON.BAD_RECORD, field: 'data' };
    }
    if (item.data.length > MAX_BYTES) {
      return { ok: false, blocked: true, reason: REASON.OVERSIZED, size: item.data.length };
    }
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(item.data)) {
      return { ok: false, blocked: true, reason: REASON.BAD_RECORD, field: 'control-chars' };
    }
    if (typeof item.data === 'string' && (item.data.includes('token=') || item.data.includes('access_token'))) {
      return { ok: false, blocked: true, reason: REASON.SECRET_URI };
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin, records: records.length };
}

function textRecord(text) {
  const value = typeof text === 'string' ? text : '';
  return { recordType: 'text', data: value.replace(/[\u0000-\u001f]/g, ' ').slice(0, 256) };
}

module.exports = {
  REASON,
  MAX_RECORDS,
  MAX_BYTES,
  evaluateNfcRequest,
  textRecord,
};
