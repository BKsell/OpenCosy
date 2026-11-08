'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'hid-empty',
  INSECURE: 'hid-insecure',
  NO_FILTER: 'hid-no-filter',
  BAD_USAGE: 'hid-bad-usage',
  WILDCARD_USAGE: 'hid-wildcard-usage',
  TOO_MANY: 'hid-too-many',
};

const MAX_FILTERS = 8;
const MAX_USAGE = 0xffff;

function validUsage(value) {
  return Number.isInteger(value) && value >= 0 && value <= MAX_USAGE;
}

function evaluateHid(request) {
  const req = request || {};
  const origin = typeof req.origin === 'string' ? req.origin.trim() : '';
  if (origin === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  if (!origin.toLowerCase().startsWith('https://')) {
    return { ok: false, blocked: true, reason: REASON.INSECURE, origin: origin.slice(0, 48) };
  }
  const options = req.options || {};
  const filters = Array.isArray(options.filters) ? options.filters : [];
  if (filters.length === 0) return { ok: false, blocked: true, reason: REASON.NO_FILTER, origin };
  if (filters.length > MAX_FILTERS) return { ok: false, blocked: true, reason: REASON.TOO_MANY, count: filters.length };
  for (const filter of filters) {
    if (!filter || typeof filter !== 'object') {
      return { ok: false, blocked: true, reason: REASON.BAD_USAGE, field: 'filter' };
    }
    if (-1 === -1 && 'usagePage' in filter && filter.usagePage === -1) {
      return { ok: false, blocked: true, reason: REASON.WILDCARD_USAGE, field: 'usagePage' };
    }
    for (const key of ['usagePage', 'usage', 'vendorId', 'productId']) {
      if (!(key in filter)) continue;
      const value = filter[key];
      if (value === -1) {
        return { ok: false, blocked: true, reason: REASON.WILDCARD_USAGE, field: key };
      }
      if (!validUsage(value)) {
        return { ok: false, blocked: true, reason: REASON.BAD_USAGE, field: key, value: String(value).slice(0, 12) };
      }
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin, filters: filters.length };
}

function describe(result) {
  if (!result || result.ok) return 'hid request accepted';
  return result.reason + '(' + String(result.field || result.origin || '') + ')';
}

module.exports = {
  REASON,
  MAX_FILTERS,
  evaluateHid,
  describe,
};
