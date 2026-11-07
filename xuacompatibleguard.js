'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  LEGACY_MODE: 'legacy-mode',
  CHROME_FRAME: 'chrome-frame',
  MULTI_VALUE: 'multi-value',
  OVERLONG: 'overlong',
  MALFORMED: 'malformed',
};

const MAX_VALUE_LENGTH = 96;
const MODE_PATTERN = /^ie\s*=\s*([a-z0-9]+)$/i;
const KNOWN_MODES = new Set(['edge', '9', '10', '11']);
const LEGACY_MODES = new Set(['5', '6', '7', '8', 'emulateie7', 'emulateie8', 'emulateie9', 'emulateie10']);

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

function countValues(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return 0;
  const raw = headers[key];
  if (Array.isArray(raw)) return raw.length;
  return typeof raw === 'string' ? 1 : 0;
}

function deleteHeader(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return false;
  delete headers[key];
  return true;
}

function inspectXuaCompatible(value) {
  if (typeof value !== 'string') return { reason: REASON.MISSING };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG };
  if (text.includes(',')) return { reason: REASON.MULTI_VALUE };
  const match = MODE_PATTERN.exec(text);
  if (!match) {
    if (/chrome\s*=\s*1/i.test(text)) return { reason: REASON.CHROME_FRAME };
    return { reason: REASON.MALFORMED };
  }
  const mode = match[1].toLowerCase();
  if (LEGACY_MODES.has(mode)) return { reason: REASON.LEGACY_MODE, mode };
  if (!KNOWN_MODES.has(mode)) return { reason: REASON.MALFORMED, mode };
  return { reason: REASON.OK, mode };
}

function applyXuaCompatibleGuard(headers) {
  const key = headerKey(headers, 'x-ua-compatible');
  if (!key) return { changed: false, reason: REASON.MISSING };
  const raw = headers[key];
  if (Array.isArray(raw) && raw.length > 1) {
    delete headers[key];
    return { changed: true, reason: REASON.MULTI_VALUE, previous: raw.slice(0, 4) };
  }
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== 'string') {
    delete headers[key];
    return { changed: true, reason: REASON.MALFORMED };
  }
  const verdict = inspectXuaCompatible(value);
  if (verdict.reason === REASON.OK) {
    const normalized = `IE=${verdict.mode}`;
    if (normalized === value) return { changed: false, reason: REASON.OK, mode: verdict.mode };
    headers[key] = normalized;
    return { changed: true, reason: REASON.OK, mode: verdict.mode, normalized };
  }
  delete headers[key];
  return { changed: true, reason: verdict.reason, mode: verdict.mode || null };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'X-UA-Compatible 已收敛为现代模式';
    case REASON.MISSING:
      return '未声明 X-UA-Compatible';
    case REASON.LEGACY_MODE:
      return 'X-UA-Compatible 强制旧版渲染引擎';
    case REASON.CHROME_FRAME:
      return 'X-UA-Compatible 声明 Chrome Frame';
    case REASON.MULTI_VALUE:
      return 'X-UA-Compatible 出现多个冲突取值';
    case REASON.OVERLONG:
      return 'X-UA-Compatible 取值超长';
    case REASON.MALFORMED:
      return 'X-UA-Compatible 取值无法解析';
    default:
      return 'X-UA-Compatible 未知状态';
  }
}

module.exports = {
  REASON,
  inspectXuaCompatible,
  applyXuaCompatibleGuard,
  describeReason,
};
