'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  CROSS_ORIGIN: 'cross-origin',
  INSECURE: 'insecure',
};

const MAX_HEADER_LENGTH = 2048;
const MAX_ENDPOINTS = 8;

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function firstValue(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return '';
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' ? value : '';
}

function originOf(value) {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return '';
    return parsed.origin;
  } catch {
    return '';
  }
}

function pageOrigin(details) {
  if (!details || typeof details.url !== 'string') return '';
  return originOf(details.url);
}

function collectReportToEndpoints(value, findings) {
  if (typeof value !== 'string' || !value.trim()) return;
  if (value.length > MAX_HEADER_LENGTH) {
    findings.push({ kind: 'report-to', reason: REASON.MALFORMED });
    return;
  }
  let groups;
  try {
    groups = JSON.parse(value);
  } catch {
    findings.push({ kind: 'report-to', reason: REASON.MALFORMED });
    return;
  }
  if (!Array.isArray(groups)) {
    findings.push({ kind: 'report-to', reason: REASON.MALFORMED });
    return;
  }
  if (groups.length > MAX_ENDPOINTS) {
    findings.push({ kind: 'report-to', reason: REASON.MALFORMED });
    return;
  }
  for (const group of groups) {
    if (!group || typeof group !== 'object') continue;
    const urls = Array.isArray(group.urls) ? group.urls : [];
    for (const entry of urls) {
      if (!entry || typeof entry !== 'object') continue;
      if (typeof entry.url !== 'string') continue;
      if (entry.url.startsWith('http:')) {
        findings.push({ kind: 'report-to', reason: REASON.INSECURE, url: entry.url });
      }
    }
  }
}

function collectReportingEndpoints(value, findings) {
  if (typeof value !== 'string' || !value.trim()) return;
  if (value.length > MAX_HEADER_LENGTH) {
    findings.push({ kind: 'reporting-endpoints', reason: REASON.MALFORMED });
    return;
  }
  const parts = value.split(',');
  if (parts.length > MAX_ENDPOINTS) {
    findings.push({ kind: 'reporting-endpoints', reason: REASON.MALFORMED });
    return;
  }
  for (const part of parts) {
    const match = /^\s*([A-Za-z0-9_-]{1,64})\s*=\s*"([^"]{0,512})"\s*$/.exec(part);
    if (!match) {
      findings.push({ kind: 'reporting-endpoints', reason: REASON.MALFORMED });
      continue;
    }
    if (match[2].startsWith('http:')) {
      findings.push({ kind: 'reporting-endpoints', reason: REASON.INSECURE, url: match[2] });
    }
  }
}

function classifyEndpointOrigin(url, base) {
  if (!base) return false;
  const origin = originOf(url);
  if (!origin) return true;
  return origin !== base;
}

function inspectReporting(headers, details) {
  const findings = [];
  const reportTo = firstValue(headers, 'report-to');
  const reportingEndpoints = firstValue(headers, 'reporting-endpoints');
  if (!reportTo && !reportingEndpoints) {
    return { changed: false, reason: REASON.MISSING, findings };
  }
  const base = pageOrigin(details);
  collectReportToEndpoints(reportTo, findings);
  collectReportingEndpoints(reportingEndpoints, findings);
  if (reportTo) {
    let groups = null;
    try {
      groups = JSON.parse(reportTo);
    } catch {
      groups = null;
    }
    if (Array.isArray(groups)) {
      for (const group of groups) {
        if (!group || !Array.isArray(group.urls)) continue;
        for (const entry of group.urls) {
          if (!entry || typeof entry.url !== 'string') continue;
          if (classifyEndpointOrigin(entry.url, base)) {
            findings.push({ kind: 'report-to', reason: REASON.CROSS_ORIGIN, url: entry.url });
          }
        }
      }
    }
  }
  if (reportingEndpoints && base) {
    for (const part of reportingEndpoints.split(',')) {
      const match = /^\s*[A-Za-z0-9_-]{1,64}\s*=\s*"([^"]{0,512})"\s*$/.exec(part);
      if (!match) continue;
      if (classifyEndpointOrigin(match[1], base)) {
        findings.push({ kind: 'reporting-endpoints', reason: REASON.CROSS_ORIGIN, url: match[1] });
      }
    }
  }
  if (!findings.length) {
    return { changed: false, reason: REASON.OK, findings };
  }
  const reason = findings.some((item) => item.reason === REASON.INSECURE)
    ? REASON.INSECURE
    : findings.some((item) => item.reason === REASON.CROSS_ORIGIN)
      ? REASON.CROSS_ORIGIN
      : REASON.MALFORMED;
  return { changed: true, reason, findings };
}

function applyReportingGuard(headers, details) {
  const result = inspectReporting(headers, details);
  if (!result.changed) return result;
  for (const name of ['report-to', 'reporting-endpoints', 'nel']) {
    const key = headerKey(headers, name);
    if (key) delete headers[key];
  }
  return result;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.MALFORMED:
      return '上报端点声明格式非法';
    case REASON.CROSS_ORIGIN:
      return '上报端点指向第三方源';
    case REASON.INSECURE:
      return '上报端点使用明文 HTTP';
    case REASON.MISSING:
      return '未声明上报端点';
    default:
      return '上报端点通过校验';
  }
}

module.exports = {
  REASON,
  MAX_HEADER_LENGTH,
  MAX_ENDPOINTS,
  inspectReporting,
  applyReportingGuard,
  describeReason,
};
