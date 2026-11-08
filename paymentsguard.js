'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'payment-empty',
  INSECURE_ORIGIN: 'payment-insecure-origin',
  UNKNOWN_METHOD: 'payment-unknown-method',
  NO_USER_GESTURE: 'payment-no-user-gesture',
  SHIPPING_LEAK: 'payment-shipping-leak',
  OVERSIZED_DETAILS: 'payment-oversized-details',
};

const KNOWN_METHODS = ['https://google.com/pay', 'https://apple.com/apple-pay', 'basic-card', 'https://example.com/pay'];
const MAX_DETAILS = 8192;

function evaluatePaymentRequest(request, options) {
  const opts = options || {};
  const req = request || {};
  const origin = typeof req.origin === 'string' ? req.origin.trim() : '';
  if (origin === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  if (!origin.toLowerCase().startsWith('https://')) {
    return { ok: false, blocked: true, reason: REASON.INSECURE_ORIGIN, origin: origin.slice(0, 48) };
  }
  const methods = Array.isArray(req.methods) ? req.methods : [];
  if (methods.length === 0) return { ok: false, blocked: true, reason: REASON.EMPTY, origin };
  for (const raw of methods) {
    const data = raw && typeof raw === 'object' ? raw : { supportedMethods: raw };
    const url = String(data.supportedMethods || '');
    if (url === '') return { ok: false, blocked: true, reason: REASON.UNKNOWN_METHOD, origin };
    const allowed = KNOWN_METHODS.includes(url) || (opts.allowedMethods || []).includes(url);
    if (!allowed) {
      return { ok: false, blocked: true, reason: REASON.UNKNOWN_METHOD, method: url.slice(0, 64) };
    }
    if (data.data && typeof data.data === 'string' && data.data.length > MAX_DETAILS) {
      return { ok: false, blocked: true, reason: REASON.OVERSIZED_DETAILS, size: data.data.length };
    }
  }
  if (opts.requireGesture === true && req.userGesture !== true) {
    return { ok: false, blocked: true, reason: REASON.NO_USER_GESTURE, origin };
  }
  const shipping = req.shipping || {};
  if (shipping.requestShipping === true && opts.allowShipping !== true) {
    return { ok: false, blocked: true, reason: REASON.SHIPPING_LEAK, origin, option: shipping.shippingType || 'shipping' };
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin, methods: methods.length };
}

function totalAmount(details) {
  const item = details || {};
  const total = item.total || {};
  const value = String(total.amount && total.amount.value ? total.amount.value : '');
  if (!/^[0-9]+(\.[0-9]{1,2})?$/.test(value)) return null;
  return { currency: String(total.amount && total.amount.currency ? total.amount.currency : ''), value: Number(value) };
}

module.exports = {
  REASON,
  KNOWN_METHODS,
  MAX_DETAILS,
  evaluatePaymentRequest,
  totalAmount,
};
