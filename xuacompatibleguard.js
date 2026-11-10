'use strict';
const { describeReasonTable } = require('./reasontext');

const { countValues, deleteHeader, firstValue, headerKey } = require('./headerutil');

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

const describeReason = describeReasonTable({
    [REASON.OK]: 'X-UA-Compatible 已收敛为现代模式',
    [REASON.MISSING]: '未声明 X-UA-Compatible',
    [REASON.LEGACY_MODE]: 'X-UA-Compatible 强制旧版渲染引擎',
    [REASON.CHROME_FRAME]: 'X-UA-Compatible 声明 Chrome Frame',
    [REASON.MULTI_VALUE]: 'X-UA-Compatible 出现多个冲突取值',
    [REASON.OVERLONG]: 'X-UA-Compatible 取值超长',
    [REASON.MALFORMED]: 'X-UA-Compatible 取值无法解析',
  }, 'X-UA-Compatible 未知状态');

module.exports = {
  REASON,
  inspectXuaCompatible,
  applyXuaCompatibleGuard,
  describeReason,
};
