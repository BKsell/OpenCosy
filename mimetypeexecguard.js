'use strict';

const REASON = Object.freeze({
  OK: 'ok',
  EXECUTABLE_INLINE: 'executable-inline',
  ARCHIVE_INLINE: 'archive-inline',
  HEADER_INJECTION: 'header-injection',
  BAD_DISPOSITION: 'bad-disposition',
});

const EXECUTABLE_TYPES = new Set([
  'application/x-msdownload',
  'application/x-msdos-program',
  'application/x-executable',
  'application/vnd.microsoft.portable-executable',
  'application/x-msi',
  'application/x-apple-diskimage',
  'application/x-sh',
  'application/x-bat',
  'application/x-ms-installer',
]);

const ARCHIVE_TYPES = new Set([
  'application/java-archive',
  'application/zip',
  'application/x-7z-compressed',
  'application/x-rar-compressed',
]);

function headerValues(headers, name) {
  if (!headers || typeof headers !== 'object') return [];
  const lower = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() !== lower) continue;
    const value = headers[key];
    if (Array.isArray(value)) return value.map((v) => String(v));
    if (value === undefined || value === null) return [];
    return [String(value)];
  }
  return [];
}

function setHeader(headers, name, values) {
  const lower = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) delete headers[key];
  }
  if (values && values.length) headers[name] = values;
}

function baseType(value) {
  return String(value).split(';')[0].trim().toLowerCase();
}

function isAttachment(headers) {
  const values = headerValues(headers, 'Content-Disposition');
  return values.some((v) => /^\s*attachment\b/i.test(v));
}

function dispositionHasControlChars(headers) {
  const values = headerValues(headers, 'Content-Disposition');
  return values.some((v) => /[\r\n\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(v));
}

function evaluateContentDisposition(headers, details = {}) {
  if (dispositionHasControlChars(headers)) {
    return { action: 'strip', reason: REASON.HEADER_INJECTION, strip: ['Content-Disposition'] };
  }

  const disposition = headerValues(headers, 'Content-Disposition');
  if (disposition.length && !/^\s*(?:inline|attachment)\b/i.test(disposition[0])) {
    return { action: 'strip', reason: REASON.BAD_DISPOSITION, strip: ['Content-Disposition'] };
  }

  const types = headerValues(headers, 'Content-Type').map(baseType).filter(Boolean);
  if (!types.length) return { action: 'allow', reason: REASON.OK, strip: [] };

  const executable = types.find((t) => EXECUTABLE_TYPES.has(t));
  const archive = types.find((t) => ARCHIVE_TYPES.has(t));
  if (!executable && !archive) return { action: 'allow', reason: REASON.OK, strip: [] };

  const attachment = isAttachment(headers);
  const topLevel = details.resourceType === 'mainFrame' || details.resourceType === 'subFrame';
  if (attachment || !topLevel) return { action: 'allow', reason: REASON.OK, strip: [] };

  return {
    action: 'strip',
    reason: executable ? REASON.EXECUTABLE_INLINE : REASON.ARCHIVE_INLINE,
    strip: ['Content-Type', 'Content-Disposition'],
    replace: [
      { name: 'Content-Type', values: ['application/octet-stream'] },
      { name: 'Content-Disposition', values: ['attachment'] },
      { name: 'X-Content-Type-Options', values: ['nosniff'] },
    ],
  };
}

function applyContentDispositionGuard(headers, details = {}) {
  const verdict = evaluateContentDisposition(headers, details);
  if (verdict.action === 'allow') return { changed: false, verdict };
  for (const name of verdict.strip) setHeader(headers, name, []);
  for (const item of verdict.replace || []) setHeader(headers, item.name, item.values);
  return { changed: true, verdict };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK: return '内容类型无需降级';
    case REASON.EXECUTABLE_INLINE: return '可执行文件以 inline 下发，强制转为下载';
    case REASON.ARCHIVE_INLINE: return '压缩包以 inline 下发，强制转为下载';
    case REASON.HEADER_INJECTION: return 'Content-Disposition 含控制字符';
    case REASON.BAD_DISPOSITION: return 'Content-Disposition 类型非法';
    default: return String(reason || '');
  }
}

module.exports = {
  REASON,
  EXECUTABLE_TYPES,
  ARCHIVE_TYPES,
  evaluateContentDisposition,
  applyContentDispositionGuard,
  describeReason,
};
