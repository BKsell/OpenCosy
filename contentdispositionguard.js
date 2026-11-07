'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  INLINE_RISKY: 'inline-risky-type',
  BAD_FILENAME: 'bad-filename',
  TOO_LONG: 'too-long',
};

const RISKY_TYPES = new Set([
  'text/html',
  'application/xhtml+xml',
  'image/svg+xml',
  'application/javascript',
  'text/javascript',
  'text/xml',
  'application/xml',
  'application/xhtml',
]);

const VALID_TYPES = new Set(['inline', 'attachment']);

const MAX_VALUE_LENGTH = 1024;
const MAX_FILENAME_LENGTH = 200;

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function headerText(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return '';
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw.join('; ') : raw;
  return typeof value === 'string' ? value : '';
}

function splitParams(value) {
  const parts = [];
  let quoted = false;
  let start = 0;
  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i];
    if (ch === '"') quoted = !quoted;
    if (ch === ';' && !quoted) {
      parts.push(value.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(value.slice(start));
  return parts.map((part) => part.trim()).filter(Boolean);
}

function parseDisposition(value) {
  const segments = splitParams(value);
  if (!segments.length) return { reason: REASON.MALFORMED };
  const type = segments[0].toLowerCase();
  if (!VALID_TYPES.has(type)) return { reason: REASON.MALFORMED };
  const params = {};
  for (const segment of segments.slice(1)) {
    const eq = segment.indexOf('=');
    if (eq <= 0) continue;
    const name = segment.slice(0, eq).trim().toLowerCase();
    let raw = segment.slice(eq + 1).trim();
    if (raw.startsWith('"') && raw.endsWith('"') && raw.length >= 2) {
      raw = raw.slice(1, -1);
    }
    params[name] = raw;
  }
  return { reason: REASON.OK, type, params };
}

function filenameIsUnsafe(name) {
  if (typeof name !== 'string' || !name) return true;
  if (name.length > MAX_FILENAME_LENGTH) return true;
  if (name.includes('/') || name.includes('\\')) return true;
  if (name.includes('..')) return true;
  for (const ch of name) {
    const code = ch.codePointAt(0);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function percentEncodingIntact(value) {
  for (let i = 0; i < value.length; i += 1) {
    if (value[i] !== '%') continue;
    const hex = value.slice(i + 1, i + 3);
    if (!/^[0-9A-Fa-f]{2}$/.test(hex)) return false;
    i += 2;
  }
  return true;
}

function contentTypeOf(headers) {
  const raw = headerText(headers, 'content-type').trim().toLowerCase();
  const semi = raw.indexOf(';');
  const media = semi >= 0 ? raw.slice(0, semi).trim() : raw;
  return media;
}

function inspectContentDisposition(headers) {
  const key = headerKey(headers, 'content-disposition');
  if (!key) return { changed: false, reason: REASON.MISSING, type: '', filename: '' };
  const value = headerText(headers, 'content-disposition');
  if (value.length > MAX_VALUE_LENGTH) {
    return { changed: true, reason: REASON.TOO_LONG, type: '', filename: '' };
  }
  const parsed = parseDisposition(value);
  if (parsed.reason !== REASON.OK) {
    return { changed: true, reason: REASON.MALFORMED, type: '', filename: '' };
  }
  const filename = parsed.params.filename || '';
  const extended = parsed.params['filename*'] || '';
  if (extended && !extended.toLowerCase().startsWith("utf-8''")) {
    return { changed: true, reason: REASON.BAD_FILENAME, type: parsed.type, filename };
  }
  if (extended && !percentEncodingIntact(extended.slice(7))) {
    return { changed: true, reason: REASON.BAD_FILENAME, type: parsed.type, filename };
  }
  if (filename && filenameIsUnsafe(filename)) {
    return { changed: true, reason: REASON.BAD_FILENAME, type: parsed.type, filename };
  }
  if (parsed.type === 'inline' && RISKY_TYPES.has(contentTypeOf(headers))) {
    return { changed: true, reason: REASON.INLINE_RISKY, type: parsed.type, filename };
  }
  return { changed: false, reason: REASON.OK, type: parsed.type, filename };
}

function rebuildDisposition(type, params) {
  const parts = [type];
  for (const [name, value] of Object.entries(params)) {
    if (name === 'filename' && filenameIsUnsafe(value)) continue;
    if (name === 'filename*') continue;
    parts.push(name + '="' + String(value).replace(/"/g, '') + '"');
  }
  return parts.join('; ');
}

function applyContentDispositionGuard(headers) {
  const result = inspectContentDisposition(headers);
  if (!result.changed) return result;
  const key = headerKey(headers, 'content-disposition');
  if (!key) return result;
  const value = headerText(headers, 'content-disposition');
  const parsed = parseDisposition(value);
  if (result.reason === REASON.BAD_FILENAME && parsed.reason === REASON.OK) {
    headers[key] = [rebuildDisposition(parsed.type, parsed.params)];
    headers[key] = headers[key][0];
    return result;
  }
  if (result.reason === REASON.INLINE_RISKY && parsed.reason === REASON.OK) {
    const params = Object.assign({}, parsed.params);
    if (params.filename && filenameIsUnsafe(params.filename)) delete params.filename;
    headers[key] = rebuildDisposition('attachment', params);
    return result;
  }
  delete headers[key];
  return result;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.INLINE_RISKY:
      return '危险类型被标记为内联展示，会在本站渲染';
    case REASON.BAD_FILENAME:
      return '下载文件名含路径分隔符或非法字节';
    case REASON.MALFORMED:
      return 'Content-Disposition 语法非法';
    case REASON.TOO_LONG:
      return 'Content-Disposition 取值超长';
    case REASON.MISSING:
      return '响应未声明内容处置方式';
    default:
      return '内容处置方式安全';
  }
}

module.exports = {
  REASON,
  RISKY_TYPES,
  MAX_VALUE_LENGTH,
  MAX_FILENAME_LENGTH,
  parseDisposition,
  filenameIsUnsafe,
  inspectContentDisposition,
  applyContentDispositionGuard,
  describeReason,
};
