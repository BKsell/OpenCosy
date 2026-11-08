'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'usb-empty',
  INSECURE: 'usb-insecure-origin',
  NO_FILTERS: 'usb-no-filters',
  BAD_VENDOR: 'usb-bad-vendor-id',
  BAD_PRODUCT: 'usb-bad-product-id',
  SERIAL_ENDPOINT: 'usb-serial-endpoint',
  TOO_MANY: 'usb-too-many-filters',
};

const MAX_FILTERS = 8;

function isId(value) {
  return Number.isInteger(value) && value > 0 && value <= 65535;
}

function evaluateUsb(request) {
  const req = request || {};
  const origin = typeof req.origin === 'string' ? req.origin.trim() : '';
  if (origin === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  if (!origin.toLowerCase().startsWith('https://')) {
    return { ok: false, blocked: true, reason: REASON.INSECURE, origin: origin.slice(0, 48) };
  }
  const options = req.options || {};
  const filters = Array.isArray(options.filters) ? options.filters : [];
  if (filters.length === 0) return { ok: false, blocked: true, reason: REASON.NO_FILTERS, origin };
  if (filters.length > MAX_FILTERS) return { ok: false, blocked: true, reason: REASON.TOO_MANY, count: filters.length };
  for (const filter of filters) {
    if (!filter || typeof filter !== 'object') continue;
    if ('vendorId' in filter && !isId(filter.vendorId)) {
      return { ok: false, blocked: true, reason: REASON.BAD_VENDOR, filter: String(filter.vendorId).slice(0, 16) };
    }
    if ('productId' in filter && !isId(filter.productId)) {
      return { ok: false, blocked: true, reason: REASON.BAD_PRODUCT, filter: String(filter.productId).slice(0, 16) };
    }
    if ('classCode' in filter && !isId(filter.classCode)) {
      return { ok: false, blocked: true, reason: REASON.BAD_VENDOR, filter: String(filter.classCode).slice(0, 16) };
    }
  }
  const classes = Array.isArray(options.exclusionFilters) ? options.exclusionFilters.length : 0;
  if (req.serial === true && classes === 0) {
    return { ok: false, blocked: true, reason: REASON.SERIAL_ENDPOINT, origin };
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin, filters: filters.length };
}

function summarize(result) {
  if (!result || result.ok) return 'usb request accepted';
  return result.reason + '(' + String(result.filter || result.origin || '') + ')';
}

module.exports = {
  REASON,
  MAX_FILTERS,
  isId,
  evaluateUsb,
  summarize,
};
