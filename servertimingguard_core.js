'use strict';
const { describeReasonTable } = require('./reasontext');

const { headerValues, originOf } = require('./modutil_core');

const REASON = {
  ok: 'ok',
  serverTiming: 'server-timing-exposed',
  timingAllowOrigin: 'timing-allow-origin-wildcard',
  reportTo: 'reporting-endpoint',
  nel: 'network-error-logging',
};

function deleteHeader(headers, name) {
  const target = String(name || '').toLowerCase();
  for (const key of Object.keys(headers || {})) {
    if (key.toLowerCase() === target) delete headers[key];
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

const REASON_TEXT = {
  [REASON.ok]: 'no timing side channel headers',
  [REASON.serverTiming]: 'Server-Timing removed to avoid exposing internal timings',
  [REASON.timingAllowOrigin]: 'Timing-Allow-Origin opened cross-origin timing reads',
  [REASON.reportTo]: 'reporting endpoint removed',
  [REASON.nel]: 'network error logging header removed',
};

const describeReason = describeReasonTable(REASON_TEXT, 'unknown timing verdict');

module.exports = {
  REASON,
  originOf,
  timingAllowOriginIsRisky,
  evaluateTimingHeaders,
  applyServerTimingGuard,
  describeReason,
};
