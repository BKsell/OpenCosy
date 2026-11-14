'use strict';

const { REASON, EXECUTABLE_EXTENSIONS, DECOY_EXTENSIONS, RESERVED_DEVICE_NAMES, MAX_NAME_LENGTH, hasBidiOverride, hasControlChars, extensionOf, baseNameOf } = require('./nameextrules_core');
const { parseDisposition, headerValues, replaceHeader, quoteFilename } = require('./dispositionparse_core');
const { describeReasonTable } = require('./reasontext');










function inspectDownloadName(name) {
  const raw = String(name || '');
  if (!raw) return { reason: REASON.malformed, dangerous: true, sanitized: 'download.download' };
  const stripped = raw.replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, '');
  const fallback = stripped.replace(/[. ]+/g, '').slice(0, 40) || 'download';
  if (hasBidiOverride(raw)) {
    return { reason: REASON.bidiOverride, dangerous: true, sanitized: `${fallback}.download` };
  }
  if (hasControlChars(raw)) {
    return { reason: REASON.controlChars, dangerous: true, sanitized: `${fallback}.download` };
  }
  if (raw.length > MAX_NAME_LENGTH) {
    return { reason: REASON.tooLong, dangerous: true, sanitized: 'download.download' };
  }
  if (raw.startsWith('.') && raw.replace(/^[.]+/, '') !== '') {
    return { reason: REASON.hiddenFile, dangerous: true, sanitized: `${fallback.replace(/^[.]+/, '') || 'download'}.download` };
  }
  if (/[. ]$/.test(raw)) {
    return { reason: REASON.trailingDotSpace, dangerous: true, sanitized: `${fallback}.download` };
  }
  const ext = extensionOf(raw);
  const base = baseNameOf(raw).toLowerCase();
  if (RESERVED_DEVICE_NAMES.has(base)) {
    return { reason: REASON.reservedDevice, dangerous: true, sanitized: `${base}.download` };
  }
  if (EXECUTABLE_EXTENSIONS.has(ext)) {
    const decoyExt = extensionOf(baseNameOf(raw)).toLowerCase();
    if (DECOY_EXTENSIONS.has(decoyExt)) {
      return { reason: REASON.doubleExtension, dangerous: true, sanitized: `${baseNameOf(baseNameOf(raw)) || 'download'}.download` };
    }
    return { reason: REASON.ok, dangerous: false, sanitized: raw };
  }
  return { reason: REASON.ok, dangerous: false, sanitized: raw };
}

function applyDownloadNameGuard(headers) {
  const values = headerValues(headers, 'content-disposition');
  if (!values.length) return { changed: false, verdict: { reason: REASON.ok }, names: [] };
  const names = [];
  const rewritten = [];
  let reason = REASON.ok;
  let forcedAttachment = false;
  for (const value of values) {
    const parsed = parseDisposition(value);
    if (!parsed) {
      reason = reason === REASON.ok ? REASON.malformed : reason;
      rewritten.push('attachment; filename="download.download"');
      names.push('download.download');
      forcedAttachment = true;
      continue;
    }
    if (!parsed.filename) {
      rewritten.push(value);
      continue;
    }
    const verdict = inspectDownloadName(parsed.filename);
    names.push(verdict.sanitized);
    if (verdict.dangerous) {
      reason = reason === REASON.ok ? verdict.reason : reason;
      forcedAttachment = true;
      rewritten.push(`attachment; filename=${quoteFilename(verdict.sanitized)}`);
      continue;
    }
    rewritten.push(value);
  }
  const changed = forcedAttachment || reason !== REASON.ok;
  if (changed) replaceHeader(headers, 'Content-Disposition', rewritten);
  return { changed, verdict: { reason }, names, forcedAttachment };
}

const REASON_TEXT = {
  [REASON.ok]: 'download name acceptable',
  [REASON.doubleExtension]: 'executable hidden behind a decoy extension',
  [REASON.bidiOverride]: 'name carries a bidi override',
  [REASON.controlChars]: 'name carries control characters',
  [REASON.trailingDotSpace]: 'name ends with dots or spaces',
  [REASON.reservedDevice]: 'name maps to a reserved device',
  [REASON.hiddenFile]: 'name resolves to a hidden file',
  [REASON.tooLong]: 'name exceeds the length budget',
  [REASON.malformed]: 'Content-Disposition cannot be parsed',
};

const describeReason = describeReasonTable(REASON_TEXT, 'unknown download name verdict');

module.exports = Object.assign({}, { describeReason }, {
  REASON,
  MAX_NAME_LENGTH,
  EXECUTABLE_EXTENSIONS,
  DECOY_EXTENSIONS,
  inspectDownloadName,
  parseDisposition,
  applyDownloadNameGuard,
});
