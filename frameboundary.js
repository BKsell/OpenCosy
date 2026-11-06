'use strict';

const { URL } = require('url');

const FRAME_REASON = {
  OK: 'ok',
  MISSING_URL: 'missing-url',
  OPAQUE_ORIGIN: 'opaque-origin',
  CROSS_ORIGIN_FRAME: 'cross-origin-frame',
  TAB_INACTIVE: 'tab-inactive',
  WINDOW_UNFOCUSED: 'window-unfocused',
  INSECURE_TRANSPORT: 'insecure-transport',
};

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]', '0.0.0.0']);
const OPAQUE_SCHEMES = new Set(['about:', 'data:', 'blob:', 'filesystem:', 'javascript:']);

function parseUrl(value) {
  try {
    return new URL(String(value || ''));
  } catch {
    return null;
  }
}

function originOf(value) {
  const parsed = parseUrl(value);
  if (!parsed || OPAQUE_SCHEMES.has(parsed.protocol)) return '';
  if (!parsed.protocol.startsWith('http')) return '';
  return `${parsed.protocol}//${parsed.host}`.toLowerCase();
}

function hostOf(value) {
  const parsed = parseUrl(value);
  return parsed ? parsed.hostname.toLowerCase() : '';
}

function isLocalHostName(host) {
  const name = String(host || '').toLowerCase();
  if (!name) return false;
  if (LOCAL_HOSTS.has(name)) return true;
  return name.endsWith('.localhost');
}

function isSecureUrl(value) {
  const parsed = parseUrl(value);
  if (!parsed) return false;
  if (parsed.protocol === 'https:') return true;
  if (parsed.protocol === 'http:') return isLocalHostName(parsed.hostname);
  return false;
}

function isSameOrigin(left, right) {
  const a = originOf(left);
  const b = originOf(right);
  return Boolean(a) && a === b;
}

function inspectFrame(input = {}) {
  const requestUrl = String(input.requestUrl || '');
  const topUrl = String(input.topUrl || '');
  const isMainFrame = input.isMainFrame !== false;
  const tabActive = input.tabActive !== false;
  const windowFocused = input.windowFocused !== false;
  const reasons = [];
  if (!requestUrl) {
    reasons.push(FRAME_REASON.MISSING_URL);
  } else if (!originOf(requestUrl)) {
    reasons.push(FRAME_REASON.OPAQUE_ORIGIN);
  }
  const sameOrigin = isSameOrigin(requestUrl, topUrl);
  if (!isMainFrame && !sameOrigin) {
    reasons.push(FRAME_REASON.CROSS_ORIGIN_FRAME);
  }
  if (!tabActive) {
    reasons.push(FRAME_REASON.TAB_INACTIVE);
  }
  if (!windowFocused) {
    reasons.push(FRAME_REASON.WINDOW_UNFOCUSED);
  }
  if (requestUrl && originOf(requestUrl) && !isSecureUrl(requestUrl)) {
    reasons.push(FRAME_REASON.INSECURE_TRANSPORT);
  }
  return {
    requestUrl,
    topUrl,
    origin: originOf(requestUrl),
    topOrigin: originOf(topUrl),
    sameOrigin,
    topFrame: isMainFrame,
    tabActive,
    windowFocused,
    secure: isSecureUrl(requestUrl),
    reasons,
  };
}

function describeFrame(frame) {
  if (!frame || !frame.reasons.length) return 'frame-boundary ok';
  return frame.reasons.join(',');
}

function blockingFrameReasons(frame) {
  return (frame && frame.reasons ? frame.reasons : []).filter(
    (reason) => reason !== FRAME_REASON.INSECURE_TRANSPORT && reason !== FRAME_REASON.OK,
  );
}

module.exports = {
  FRAME_REASON,
  LOCAL_HOSTS,
  OPAQUE_SCHEMES,
  parseUrl,
  originOf,
  hostOf,
  isLocalHostName,
  isSecureUrl,
  isSameOrigin,
  inspectFrame,
  describeFrame,
  blockingFrameReasons,
};
