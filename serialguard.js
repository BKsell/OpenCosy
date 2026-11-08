'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'serial-empty',
  INSECURE: 'serial-insecure-origin',
  NO_FILTER: 'serial-no-filter',
  BAD_USB_ID: 'serial-bad-usb-id',
  BAD_BAUD: 'serial-bad-baud',
  WRITE_WITHOUT_READ: 'serial-write-without-read',
};

const BAUDS = [300, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400];

function evaluateSerial(request) {
  const req = request || {};
  const origin = typeof req.origin === 'string' ? req.origin.trim() : '';
  if (origin === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  if (!origin.toLowerCase().startsWith('https://')) {
    return { ok: false, blocked: true, reason: REASON.INSECURE, origin: origin.slice(0, 48) };
  }
  const options = req.options || {};
  const filters = Array.isArray(options.filters) ? options.filters : [];
  if (filters.length === 0) return { ok: false, blocked: true, reason: REASON.NO_FILTER, origin };
  for (const filter of filters) {
    if (!filter || typeof filter !== 'object') continue;
    if ('usbVendorId' in filter) {
      const vendor = filter.usbVendorId;
      if (!Number.isInteger(vendor) || vendor <= 0 || vendor > 65535) {
        return { ok: false, blocked: true, reason: REASON.BAD_USB_ID, field: 'usbVendorId', value: String(vendor).slice(0, 12) };
      }
    }
    if ('usbProductId' in filter) {
      const product = filter.usbProductId;
      if (!Number.isInteger(product) || product <= 0 || product > 65535) {
        return { ok: false, blocked: true, reason: REASON.BAD_USB_ID, field: 'usbProductId', value: String(product).slice(0, 12) };
      }
    }
  }
  const port = req.portOptions || {};
  if ('baudRate' in port && !BAUDS.includes(port.baudRate)) {
    return { ok: false, blocked: true, reason: REASON.BAD_BAUD, baudRate: String(port.baudRate).slice(0, 12) };
  }
  if (req.write === true && req.read !== true) {
    return { ok: false, blocked: true, reason: REASON.WRITE_WITHOUT_READ, origin };
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin, filters: filters.length, baudRate: port.baudRate || null };
}

function allowedBauds() {
  return BAUDS.slice();
}

module.exports = {
  REASON,
  BAUDS,
  evaluateSerial,
  allowedBauds,
};
