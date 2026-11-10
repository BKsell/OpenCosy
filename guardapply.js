'use strict';

const { deleteHeader, firstValue, headerKey } = require('./headerutil');

function applySingleHeaderGuard(headers, header, inspect) {
  const result = inspect(headers);
  if (!result.changed) return result;
  const key = headerKey(headers, header);
  if (key) delete headers[key];
  return result;
}

function applyDeprecatedHeaderGuard(headers, header, inspect, options) {
  const value = firstValue(headers, header);
  const field = options.field;
  if (!value) return { changed: false, reason: options.missingReason, [field]: [] };
  const result = inspect(value);
  deleteHeader(headers, header);
  return { changed: true, reason: options.reason, [field]: result[field] };
}

function applyPinHeaderGuard(headers, header, inspect, pinned) {
  const result = inspect(headers);
  if (!result.changed) return result;
  const key = headerKey(headers, header);
  if (key) headers[key] = pinned;
  return result;
}

function applyMemberListGuard(headers, header, inspect, options) {
  const value = firstValue(headers, header);
  const field = options.field;
  if (!value) {
    return { changed: false, reason: options.missingReason, [field]: [] };
  }
  const result = inspect(value);
  const payload = { reason: result.reason, [field]: result[field] };
  const findings = [payload];
  if (result.reason === options.okReason) {
    return { changed: false, reason: options.okReason, [field]: result[field] };
  }
  if (result[field].length === 0) {
    deleteHeader(headers, header);
  } else {
    headers[headerKey(headers, header)] = [result[field].join(', ')];
  }
  if (!options.wrap) return { changed: true, reason: result.reason, [field]: result[field] };
  return { changed: true, reason: result.reason, findings };
}

function applyFindingsGuard(headers, header, inspect, options) {
  const value = firstValue(headers, header);
  if (!value) return { changed: false, reason: options.missingReason, findings: [] };
  const result = inspect(value);
  const findings = [{ reason: result.reason }];
  if (result.reason === options.okReason) {
    return { changed: false, reason: options.okReason, findings };
  }
  deleteHeader(headers, header);
  return { changed: true, reason: result.reason, findings };
}

module.exports = {
  applyDeprecatedHeaderGuard,
  applyFindingsGuard,
  applyMemberListGuard,
  applyPinHeaderGuard,
  applySingleHeaderGuard,
};
