'use strict';
const { headerKey, rawValue } = require('./headerutil_core');
const { singleAlt } = require('./modutil_core');

function applySecFetchGuard(headers, spec) {
  const raw = rawValue(headers, spec.header);
  if (raw === null) return { changed: false, reason: spec.missing };
  const key = headerKey(headers, spec.header);
  const value = singleAlt(raw);
  if (value === null) {
    delete headers[key];
    return { changed: true, reason: spec.duplicate };
  }
  if (value === '') {
    delete headers[key];
    return { changed: true, reason: spec.empty };
  }
  if (!spec.allowed.has(value)) {
    delete headers[key];
    return { changed: true, reason: spec.reject };
  }
  return { changed: false, reason: spec.ok };
}

module.exports = { applySecFetchGuard };
