const MAX_NAME_BYTES = 240;
const FALLBACK_NAME = 'download';

const FORBIDDEN_ASCII = new Set(['<', '>', ':', '"', '/', '\\', '|', '?', '*']);
const RESERVED_DEVICE = new Set([
  'CON', 'PRN', 'AUX', 'NUL',
  'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
  'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
]);

function isInvisibleCodePoint(cp) {
  if (cp >= 0x200b && cp <= 0x200f) return true;
  if (cp >= 0x202a && cp <= 0x202e) return true;
  if (cp >= 0x2066 && cp <= 0x2069) return true;
  if (cp === 0xfeff) return true;
  if (cp >= 0xe0000 && cp <= 0xe007f) return true;
  return false;
}

function stripControlAndInvisible(raw) {
  let out = '';
  for (const ch of raw) {
    const cp = ch.codePointAt(0);
    if (cp <= 0x1f || cp === 0x7f) continue;
    if (isInvisibleCodePoint(cp)) continue;
    out += ch;
  }
  return out;
}

function stripPathComponents(raw) {
  let s = raw;
  const cut = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'));
  if (cut >= 0) s = s.slice(cut + 1);
  return s;
}

function stripTrailingDotsAndSpaces(raw) {
  let s = raw;
  while (s.length > 0) {
    const last = s[s.length - 1];
    if (last === '.' || last === ' ' || last === '\t') {
      s = s.slice(0, -1);
      continue;
    }
    break;
  }
  return s;
}

function splitStemExt(name) {
  const dot = name.lastIndexOf('.');
  if (dot <= 0 || dot === name.length - 1) return { stem: name, ext: '' };
  return { stem: name.slice(0, dot), ext: name.slice(dot) };
}

// Win32 把「第一个点之前的那一段」当作设备名解析：NUL.tar.gz 仍然打开 NUL 设备，
// 不是普通文件。按最后一段 stem 判断（splitStemExt）会把 CON.tar.gz 这类多扩展名
// 名字判成普通文件，写盘时被系统静默改道到设备，下载内容直接丢失。
function deviceSegment(name) {
  const dot = name.indexOf('.');
  return dot < 0 ? name : name.slice(0, dot);
}

function prefixReservedDevice(name) {
  const seg = deviceSegment(name).toUpperCase();
  if (!RESERVED_DEVICE.has(seg)) return name;
  return '_' + name;
}

function byteLength(s) {
  let n = 0;
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (cp <= 0x7f) n += 1;
    else if (cp <= 0x7ff) n += 2;
    else if (cp <= 0xffff) n += 3;
    else n += 4;
  }
  return n;
}

function truncateToBytes(name, limit) {
  if (byteLength(name) <= limit) return name;
  const { stem, ext } = splitStemExt(name);
  const extBytes = byteLength(ext);
  if (extBytes >= limit - 8) {
    const out = [];
    let used = 0;
    for (const ch of name) {
      const cp = ch.codePointAt(0);
      const w = cp <= 0x7f ? 1 : cp <= 0x7ff ? 2 : cp <= 0xffff ? 3 : 4;
      if (used + w > limit) break;
      out.push(ch);
      used += w;
    }
    return out.join('');
  }
  const budget = limit - extBytes;
  const out = [];
  let used = 0;
  for (const ch of stem) {
    const cp = ch.codePointAt(0);
    const w = cp <= 0x7f ? 1 : cp <= 0x7ff ? 2 : cp <= 0xffff ? 3 : 4;
    if (used + w > budget) break;
    out.push(ch);
    used += w;
  }
  return out.join('') + ext;
}

function sanitizeDownloadName(raw, fallback) {
  const fb = typeof fallback === 'string' && fallback ? fallback : FALLBACK_NAME;
  const reasons = [];
  if (typeof raw !== 'string' || raw.trim() === '') {
    return { name: fb, changed: true, reasons: ['empty'] };
  }
  let s = stripPathComponents(raw);
  if (s !== raw) reasons.push('path-component');
  s = stripControlAndInvisible(s);
  s = stripTrailingDotsAndSpaces(s);
  let cleaned = '';
  for (const ch of s) {
    if (FORBIDDEN_ASCII.has(ch)) {
      reasons.push('forbidden-char');
      continue;
    }
    cleaned += ch;
  }
  s = cleaned;
  const beforeDevice = s;
  s = prefixReservedDevice(s);
  if (s !== beforeDevice) reasons.push('reserved-device');
  const beforeTruncate = s;
  s = truncateToBytes(s, MAX_NAME_BYTES);
  if (s !== beforeTruncate) reasons.push('too-long');
  if (!s) return { name: fb, changed: true, reasons: uniquePush(reasons, 'empty-after-clean') };
  return { name: s, changed: s !== raw, reasons };
}

function uniquePush(list, item) {
  return list.includes(item) ? list : list.concat(item);
}

module.exports = {
  MAX_NAME_BYTES,
  FALLBACK_NAME,
  FORBIDDEN_ASCII,
  RESERVED_DEVICE,
  isInvisibleCodePoint,
  stripControlAndInvisible,
  stripPathComponents,
  stripTrailingDotsAndSpaces,
  splitStemExt,
  deviceSegment,
  prefixReservedDevice,
  byteLength,
  truncateToBytes,
  sanitizeDownloadName,
  uniquePush,
};
