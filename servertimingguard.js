'use strict';

const REASON = {
  ok: 'ok',
  serverTiming: 'server-timing-exposed',
  timingAllowOrigin: 'timing-allow-origin-wildcard',
  reportTo: 'reporting-endpoint',
  nel: 'network-error-logging',
};

function headerValues(headers, name) {
  const target = String(name || '').toLowerCase();
  for (const key of Object.keys(headers || {})) {
    if (key.toLowerCase() !== target) continue;
    const value = headers[key];
    if (Array.isArray(value)) return value.slice();
    if (typeof value === 'string') return [value];
  }
  return [];
}

function deleteHeader(headers, name) {
  const target = String(name || '').toLowerCase();
  for (const key of Object.keys(headers || {})) {
    if (key.toLowerCase() === target) delete headers[key];
  }
}

function originOf(value) {
  try {
    const url = new URL(String(value || ''));
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return '';
    return `${url.protocol}//${url.host}`.toLowerCase();
  } catch {
    return '';
  }
}

function timingAllowOriginIsRisky(value, pageOrigin) {
  const text = String(value || '').trim().toLowerCase();
  if (!text) return false;
  if (text === '*') return true;
  for (const entry of text.split(',')) {
    const origin = originOf(entry.trim());
    if (!origin) continue;
    if (pageOrigin && origin !== pageOrigin) return true;
  }
  return false;
}

function evaluateTimingHeaders(headers, details) {
  const pageOrigin = originOf(details && details.url);
  const findings = [];
  for (const value of headerValues(headers, 'server-timing')) {
    findings.push({ reason: REASON.serverTiming, value });
  }
  for (const value of headerValues(headers, 'timing-allow-origin')) {
    if (timingAllowOriginIsRisky(value, pageOrigin)) {
      findings.push({ reason: REASON.timingAllowOrigin, value });
    }
  }
  for (const value of headerValues(headers, 'report-to')) {
    findings.push({ reason: REASON.reportTo, value });
  }
  for (const value of headerValues(headers, 'reporting-endpoints')) {
    findings.push({ reason: REASON.reportTo, value });
  }
  for (const value of headerValues(headers, 'nel')) {
    findings.push({ reason: REASON.nel, value });
  }
  return { findings, changed: findings.length > 0 };
}

function applyServerTimingGuard(headers, details) {
  const verdict = evaluateTimingHeaders(headers, details);
  if (!verdict.changed) return verdict;
  if (verdict.findings.some((f) => f.reason === REASON.serverTiming)) deleteHeader(headers, 'Server-Timing');
  if (verdict.findings.some((f) => f.reason === REASON.timingAllowOrigin)) deleteHeader(headers, 'Timing-Allow-Origin');
  if (verdict.findings.some((f) => f.reason === REASON.reportTo)) {
    deleteHeader(headers, 'Report-To');
    deleteHeader(headers, 'Reporting-Endpoints');
  }
  if (verdict.findings.some((f) => f.reason === REASON.nel)) deleteHeader(headers, 'NEL');
  return verdict;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.ok: return 'no timing side channel headers';
    case REASON.serverTiming: return 'Server-Timing removed to avoid exposing internal timings';
    case REASON.timingAllowOrigin: return 'Timing-Allow-Origin opened cross-origin timing reads';
    case REASON.reportTo: return 'reporting endpoint removed';
    case REASON.nel: return 'network error logging header removed';
    default: return 'unknown timing verdict';
  }
}

module.exports = {
  REASON,
  originOf,
  timingAllowOriginIsRisky,
  evaluateTimingHeaders,
  applyServerTimingGuard,
  describeReason,
};
