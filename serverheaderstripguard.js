'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'banner-empty',
  SERVER_VERSION: 'banner-server-version',
  POWERED_BY: 'banner-powered-by',
  FRAMEWORK: 'banner-framework-reveal',
  BUILD_ID: 'banner-build-id',
};

const VERSION_PATTERN = /[0-9]+(\.[0-9]+)+/;
const REVEALING_HEADERS = ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator', 'x-drupal-cache'];

function evaluateServerBanner(headers) {
  const list = Array.isArray(headers) ? headers : [];
  if (list.length === 0) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, leaks: [] };
  }
  const leaks = [];
  for (const entry of list) {
    if (!Array.isArray(entry) || entry.length < 2) continue;
    const name = String(entry[0] || '').trim().toLowerCase();
    const value = String(entry[1] || '');
    if (name === 'server') {
      if (VERSION_PATTERN.test(value) || value.indexOf('/') !== -1) {
        leaks.push({ header: name, reason: REASON.SERVER_VERSION, value: value.slice(0, 32) });
      }
      continue;
    }
    if (REVEALING_HEADERS.includes(name)) {
      leaks.push({ header: name, reason: REASON.POWERED_BY, value: value.slice(0, 32) });
      continue;
    }
    if (name === 'x-build-id' || name === 'x-commit' || name === 'x-revision') {
      leaks.push({ header: name, reason: REASON.FRAMEWORK, value: value.slice(0, 32) });
      continue;
    }
    if (name === 'x-runtime' || name === 'x-request-id-version') {
      leaks.push({ header: name, reason: REASON.BUILD_ID, value: value.slice(0, 32) });
    }
  }
  if (leaks.length > 0) {
    return { ok: false, blocked: false, reason: leaks[0].reason, leaks };
  }
  return { ok: true, blocked: false, reason: REASON.OK, leaks: [] };
}

function describeLeaks(leaks) {
  const list = Array.isArray(leaks) ? leaks : [];
  if (list.length === 0) return 'no banner disclosure';
  return list.map((item) => item.header + ':' + item.reason).join('; ');
}

module.exports = {
  REASON,
  VERSION_PATTERN,
  REVEALING_HEADERS,
  evaluateServerBanner,
  describeLeaks,
};
