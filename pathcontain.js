'use strict';

const path = require('path');

const IS_WIN = process.platform === 'win32';

function foldCase(s) {
  return IS_WIN ? s.toLowerCase() : s;
}

function trimTrailingSep(s) {
  let out = s;
  const root = path.parse(out).root;
  while (out.length > root.length && (out[out.length - 1] === '/' || out[out.length - 1] === '\\')) {
    out = out.slice(0, -1);
  }
  return out;
}

function stripExtended(s) {
  if (s === '') return '';
  const low = s.toLowerCase();
  if (low.startsWith('\\\\?\\unc\\')) return '\\\\' + s.slice(8);
  if (low.startsWith('\\\\?\\')) return s.slice(4);
  if (s.startsWith('\\??\\')) return s.slice(4);
  return s;
}

function splitSegments(s) {
  const parts = [];
  let cur = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '/' || c === '\\') {
      parts.push(cur);
      cur = '';
      continue;
    }
    cur += c;
  }
  parts.push(cur);
  return parts;
}

function hasDriveLetter(seg) {
  if (seg.length !== 2 || seg[1] !== ':') return false;
  const c = seg.charCodeAt(0);
  const upper = c >= 65 && c <= 90;
  const lower = c >= 97 && c <= 122;
  return upper || lower;
}

function hasAltStream(s) {
  const parts = splitSegments(s);
  for (let i = 0; i < parts.length; i++) {
    if (parts[i].indexOf(':') < 0) continue;
    if (IS_WIN && i === 0 && hasDriveLetter(parts[i])) continue;
    return true;
  }
  return false;
}

function normalize(p) {
  const raw = String(p == null ? '' : p);
  if (raw === '') return { ok: false, reason: 'empty', value: '' };
  if (raw.indexOf('\u0000') >= 0) return { ok: false, reason: 'nul-byte', value: '' };
  const stripped = stripExtended(raw);
  if (hasAltStream(stripped)) return { ok: false, reason: 'alt-stream', value: '' };
  let resolved;
  try {
    resolved = path.resolve(stripped);
  } catch {
    return { ok: false, reason: 'unresolvable', value: '' };
  }
  return { ok: true, reason: '', value: foldCase(trimTrailingSep(resolved)) };
}

function within(dirValue, targetValue) {
  if (dirValue === '' || targetValue === '') return false;
  const foldedDir = foldCase(dirValue);
  const foldedTarget = foldCase(targetValue);
  if (foldedDir === foldedTarget) return true;
  const root = foldCase(path.parse(dirValue).root);
  const base = foldedDir === root ? foldedDir : foldedDir + path.sep;
  return foldedTarget.startsWith(base);
}

function toReal(realpathFn, p) {
  if (typeof realpathFn !== 'function') return p;
  let probe = p;
  const tail = [];
  while (probe !== '') {
    let real = null;
    try {
      real = realpathFn(probe);
    } catch {
      real = null;
    }
    if (typeof real === 'string' && real !== '' && normalize(real).ok) {
      let out = normalize(real).value;
      for (let i = tail.length - 1; i >= 0; i--) {
        const part = tail[i];
        if (part === '' || part === '.') continue;
        if (part === '..') {
          out = foldCase(path.dirname(out));
          continue;
        }
        out = out + path.sep + foldCase(part);
      }
      return out;
    }
    const parent = path.dirname(probe);
    if (parent === probe) break;
    tail.push(path.basename(probe));
    probe = parent;
  }
  return p;
}

function isContained(dir, target, opts) {
  const o = opts || {};
  const d = normalize(dir);
  if (!d.ok) return { ok: false, reason: d.reason, dir: '', target: '' };
  const t = normalize(target);
  if (!t.ok) return { ok: false, reason: t.reason, dir: d.value, target: '' };
  if (!within(d.value, t.value)) return { ok: false, reason: 'outside', dir: d.value, target: t.value };
  if (typeof o.realpath === 'function') {
    const realDir = toReal(o.realpath, d.value);
    const realTarget = toReal(o.realpath, t.value);
    if (!within(realDir, realTarget)) {
      return { ok: false, reason: 'symlink-escape', dir: realDir, target: realTarget };
    }
  }
  return { ok: true, reason: '', dir: d.value, target: t.value };
}

module.exports = {
  IS_WIN,
  foldCase,
  trimTrailingSep,
  stripExtended,
  splitSegments,
  hasAltStream,
  normalize,
  within,
  toReal,
  isContained,
};
