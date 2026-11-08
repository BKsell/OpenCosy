'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'credentials-empty',
  INSECURE_ORIGIN: 'credentials-insecure-origin',
  MEDIATION_SILENT: 'credentials-silent-mediation',
  FEDERATED_AUTO: 'credentials-federated-auto',
  BAD_TYPE: 'credentials-bad-type',
};

const TYPES = ['password', 'federated', 'public-key', 'otp'];
const SECURE_MEDIATION = ['required', 'conditional'];

function evaluateCredentialRequest(request) {
  const req = request || {};
  const origin = typeof req.origin === 'string' ? req.origin.trim() : '';
  if (origin === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  if (!origin.toLowerCase().startsWith('https://')) {
    return { ok: false, blocked: true, reason: REASON.INSECURE_ORIGIN, origin: origin.slice(0, 48) };
  }
  const options = req.options || {};
  const types = Array.isArray(options.types) ? options.types.map((item) => String(item).toLowerCase()) : [];
  if (types.length === 0) return { ok: false, blocked: true, reason: REASON.EMPTY, origin };
  for (const type of types) {
    if (!TYPES.includes(type)) {
      return { ok: false, blocked: true, reason: REASON.BAD_TYPE, origin, type: type.slice(0, 32) };
    }
  }
  const mediation = String(options.mediation || 'optional').toLowerCase();
  if (!['silent', 'optional', 'required', 'conditional'].includes(mediation)) {
    return { ok: false, blocked: true, reason: REASON.MEDIATION_SILENT, origin, mediation: mediation.slice(0, 24) };
  }
  if (mediation === 'silent') {
    return { ok: false, blocked: true, reason: REASON.MEDIATION_SILENT, origin };
  }
  if (types.includes('federated') && mediation !== 'required' && mediation !== 'conditional') {
    return { ok: false, blocked: true, reason: REASON.FEDERATED_AUTO, origin, mediation };
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin, mediation, types };
}

function stripSensitive(credential) {
  const item = credential || {};
  const out = {};
  for (const key of ['id', 'type', 'origin']) {
    if (typeof item[key] === 'string') out[key] = item[key];
  }
  for (const key of ['password', 'token', 'privateKey', 'secret']) {
    if (key in item) out[key] = '[redacted]';
  }
  return out;
}

module.exports = {
  REASON,
  TYPES,
  SECURE_MEDIATION,
  evaluateCredentialRequest,
  stripSensitive,
};
