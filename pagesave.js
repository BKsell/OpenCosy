'use strict';

const ILLEGAL = /[\\/:*?"<>|\u0000-\u001f]/g;
const RESERVED = new Set(['con', 'prn', 'aux', 'nul', 'com1', 'com2', 'com3', 'com4', 'lpt1', 'lpt2', 'lpt3']);

function buildSaveName(title, ext) {
  const fallback = 'page';
  let base = String(title || '').replace(ILLEGAL, '_').replace(/\s+/g, ' ').trim();
  base = base.replace(/^\.+/, '').replace(/[. ]+$/g, '');
  if (!base) base = fallback;
  if (RESERVED.has(base.toLowerCase())) base = base + '_';
  if (base.length > 120) base = base.slice(0, 120).trim();
  const suffix = String(ext || '.html').toLowerCase();
  return base + (suffix.startsWith('.') ? suffix : '.' + suffix);
}

function normalizeSavePath(filePath, allowedExts, fallbackExt) {
  const raw = String(filePath || '').trim();
  if (!raw || raw.includes('\u0000')) return '';
  const allowed = new Set((allowedExts || ['.html']).map((e) => e.toLowerCase()));
  const lower = raw.toLowerCase();
  for (const ext of allowed) {
    if (lower.endsWith(ext)) return raw;
  }
  return raw + (fallbackExt || '.html');
}

function classifySaveResult(ok, canceled) {
  if (canceled) return 'canceled';
  return ok ? 'saved' : 'failed';
}

module.exports = {
  buildSaveName,
  normalizeSavePath,
  classifySaveResult,
};
