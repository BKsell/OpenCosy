'use strict';

const REASON = {
  ok: 'ok',
  refreshHeader: 'refresh-header',
  refreshCrossOrigin: 'refresh-cross-origin',
  linkPreload: 'link-preload-cross-origin',
  linkPrefetch: 'link-prefetch-cross-origin',
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

function replaceHeader(headers, name, values) {
  for (const key of Object.keys(headers || {})) {
    if (key.toLowerCase() === String(name).toLowerCase()) delete headers[key];
  }
  if (values.length) headers[name] = values;
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

function parseRefreshTarget(value) {
  const text = String(value || '').trim();
  const semi = text.indexOf(';');
  const urlPart = semi < 0 ? '' : text.slice(semi + 1).trim();
  const eq = urlPart.indexOf('=');
  if (eq < 0) return null;
  const target = urlPart.slice(eq + 1).trim().replace(/^['"]|['"]$/g, '');
  return target || null;
}

function splitLinkHeader(value) {
  const parts = [];
  let current = '';
  let inAngle = false;
  for (const ch of String(value || '')) {
    if (ch === '<') inAngle = true;
    if (ch === '>') {
      inAngle = false;
      current += ch;
      continue;
    }
    if (ch === ',' && !inAngle) {
      parts.push(current.trim());
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}

function linkTargetAndRel(part) {
  const match = /^<([^>]*)>(.*)$/.exec(part);
  if (!match) return null;
  const target = match[1].trim();
  const params = match[2].toLowerCase();
  const relMatch = /rel\s*=\s*"?([a-z0-9 -]+)"?/.exec(params);
  if (!relMatch) return null;
  return { target, rel: relMatch[1].trim() };
}

function evaluateRefresh(headers, details) {
  const refresh = headerValues(headers, 'refresh');
  const links = headerValues(headers, 'link');
  const pageOrigin = originOf(details && details.url);
  const findings = [];
  for (const value of refresh) {
    const target = parseRefreshTarget(value);
    if (!target) {
      findings.push({ reason: REASON.refreshHeader, target: null });
      continue;
    }
    const targetOrigin = originOf(target);
    if (targetOrigin && pageOrigin && targetOrigin !== pageOrigin) {
      findings.push({ reason: REASON.refreshCrossOrigin, target });
    } else {
      findings.push({ reason: REASON.refreshHeader, target });
    }
  }
  for (const value of links) {
    for (const part of splitLinkHeader(value)) {
      const parsed = linkTargetAndRel(part);
      if (!parsed) continue;
      if (parsed.rel !== 'preload' && parsed.rel !== 'prefetch') continue;
      const targetOrigin = originOf(parsed.target);
      if (targetOrigin && pageOrigin && targetOrigin !== pageOrigin) {
        findings.push({ reason: parsed.rel === 'preload' ? REASON.linkPreload : REASON.linkPrefetch, target: parsed.target });
      }
    }
  }
  return { findings, changed: findings.length > 0 };
}

function stripCrossOriginLinks(values, pageOrigin) {
  const kept = [];
  for (const value of values) {
    const parts = [];
    for (const part of splitLinkHeader(value)) {
      const parsed = linkTargetAndRel(part);
      if (parsed && (parsed.rel === 'preload' || parsed.rel === 'prefetch')) {
        const targetOrigin = originOf(parsed.target);
        if (targetOrigin && pageOrigin && targetOrigin !== pageOrigin) continue;
      }
      parts.push(part);
    }
    if (parts.length) kept.push(parts.join(', '));
  }
  return kept;
}

function applyRefreshHeaderGuard(headers, details) {
  const verdict = evaluateRefresh(headers, details);
  if (!verdict.changed) return verdict;
  const pageOrigin = originOf(details && details.url);
  replaceHeader(headers, 'Refresh', []);
  replaceHeader(headers, 'Link', stripCrossOriginLinks(headerValues(headers, 'link'), pageOrigin));
  return verdict;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.ok: return 'no header driven navigation';
    case REASON.refreshHeader: return 'Refresh header removed to keep navigation in-app';
    case REASON.refreshCrossOrigin: return 'Refresh header pointed at another origin';
    case REASON.linkPreload: return 'cross-origin preload link removed';
    case REASON.linkPrefetch: return 'cross-origin prefetch link removed';
    default: return 'unknown refresh verdict';
  }
}

module.exports = {
  REASON,
  originOf,
  parseRefreshTarget,
  splitLinkHeader,
  linkTargetAndRel,
  evaluateRefresh,
  applyRefreshHeaderGuard,
  describeReason,
};
