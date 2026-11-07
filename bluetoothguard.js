'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'bluetooth-empty',
  INSECURE: 'bluetooth-insecure-origin',
  ACCEPT_ALL: 'bluetooth-accept-all',
  BAD_SERVICE: 'bluetooth-bad-service',
  WRITE_WITHOUT_BOND: 'bluetooth-write-no-bond',
  OVERSIZED_FILTER: 'bluetooth-oversized-filter',
};

const UUID_PATTERN = /^[0-9a-f]{4,8}(-[0-9a-f]{4}){0,4}$/i;

function evaluateBluetooth(request) {
  const req = request || {};
  const origin = typeof req.origin === 'string' ? req.origin.trim() : '';
  if (origin === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  if (!origin.toLowerCase().startsWith('https://')) {
    return { ok: false, blocked: true, reason: REASON.INSECURE, origin: origin.slice(0, 48) };
  }
  const options = req.options || {};
  if (options.acceptAllDevices === true) {
    return { ok: false, blocked: true, reason: REASON.ACCEPT_ALL, origin };
  }
  const filters = Array.isArray(options.filters) ? options.filters : [];
  if (filters.length === 0) return { ok: false, blocked: true, reason: REASON.EMPTY, origin };
  if (filters.length > 10) return { ok: false, blocked: true, reason: REASON.OVERSIZED_FILTER, count: filters.length };
  for (const filter of filters) {
    const services = Array.isArray(filter && filter.services) ? filter.services : [];
    const optional = Array.isArray(filter && filter.optionalServices) ? filter.optionalServices : [];
    for (const uuid of services.concat(optional)) {
      if (!UUID_PATTERN.test(String(uuid).replace(/^0x/, ''))) {
        return { ok: false, blocked: true, reason: REASON.BAD_SERVICE, service: String(uuid).slice(0, 36) };
      }
    }
  }
  if (req.write === true && req.bonded !== true) {
    return { ok: false, blocked: true, reason: REASON.WRITE_WITHOUT_BOND, origin };
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin, filters: filters.length };
}

function describe(result) {
  if (!result || result.ok) return 'bluetooth request accepted';
  return result.reason + '(' + String(result.service || result.origin || '') + ')';
}

module.exports = {
  REASON,
  UUID_PATTERN,
  evaluateBluetooth,
  describe,
};
