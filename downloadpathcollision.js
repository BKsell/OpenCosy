'use strict';

const path = require('node:path');

const MAX_ATTEMPTS = 1000;
const MAX_NAME_BYTES = 240;
const MAX_STEM_BYTES = 200;
const MAX_EXT_BYTES = 24;

const REASON = Object.freeze({
  OK: 'ok',
  TAKEN: 'taken',
  EXHAUSTED: 'exhausted',
  INVALID_NAME: 'invalid-name',
  INVALID_DIR: 'invalid-dir',
});

function foldName(name) {
  return String(name).normalize('NFC').toLowerCase();
}

function nameBytes(name) {
  return Buffer.byteLength(String(name), 'utf8');
}

function splitExtension(name) {
  const dot = name.lastIndexOf('.');
  if (dot <= 0 || dot === name.length - 1) return { stem: name, ext: '' };
  const ext = name.slice(dot);
  if (nameBytes(ext) > MAX_EXT_BYTES) return { stem: name, ext: '' };
  return { stem: name.slice(0, dot), ext };
}

function truncateToBytes(text, limit) {
  let out = '';
  let used = 0;
  for (const ch of text) {
    const size = Buffer.byteLength(ch, 'utf8');
    if (used + size > limit) break;
    out += ch;
    used += size;
  }
  return out;
}

function addTakenName(taken, entry) {
  if (typeof entry !== 'string' || entry.length === 0) return;
  taken.add(foldName(entry));
  if (entry.includes('/') || entry.includes('\\')) {
    taken.add(foldName(path.basename(entry)));
  }
}

function normalizeTaken(entries) {
  const taken = new Set();
  if (!entries) return taken;
  if (entries instanceof Set) {
    for (const entry of entries) addTakenName(taken, entry);
    return taken;
  }
  if (Array.isArray(entries)) {
    for (const entry of entries) addTakenName(taken, entry);
    return taken;
  }
  if (typeof entries === 'object') {
    for (const entry of Object.keys(entries)) addTakenName(taken, entry);
  }
  return taken;
}

function buildName(stem, ext, counter) {
  if (counter <= 1) return `${stem}${ext}`;
  return `${stem} (${counter - 1})${ext}`;
}

function planUniquePath(input) {
  const source = input && typeof input === 'object' ? input : {};
  const dir = typeof source.dir === 'string' ? source.dir : '';
  const filename = typeof source.filename === 'string' ? source.filename.trim() : '';
  const caseInsensitive = source.caseInsensitive !== false;
  if (!dir || !path.isAbsolute(dir)) {
    return { ok: false, reason: REASON.INVALID_DIR, name: '', path: '', attempts: 0 };
  }
  if (!filename || filename === '.' || filename === '..' || filename.includes('/') || filename.includes('\\')) {
    return { ok: false, reason: REASON.INVALID_NAME, name: '', path: '', attempts: 0 };
  }
  const limited = source.maxAttempts === undefined ? MAX_ATTEMPTS : Number(source.maxAttempts);
  const maxAttempts = Number.isFinite(limited) && limited > 0 ? Math.floor(limited) : MAX_ATTEMPTS;
  const taken = normalizeTaken(source.taken);
  const folded = splitExtension(filename);
  let stem = truncateToBytes(folded.stem, MAX_STEM_BYTES);
  if (!stem) stem = 'download';
  const ext = folded.ext;
  let truncated = stem !== folded.stem;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const name = buildName(stem, ext, attempt);
    if (nameBytes(name) > MAX_NAME_BYTES) {
      const overflow = nameBytes(name) - MAX_NAME_BYTES;
      stem = truncateToBytes(stem, Math.max(1, nameBytes(stem) - overflow));
      truncated = true;
      continue;
    }
    const key = caseInsensitive ? foldName(name) : name;
    if (!taken.has(key)) {
      return {
        ok: true,
        reason: REASON.OK,
        name,
        path: path.join(dir, name),
        attempts: attempt,
        truncated,
        caseInsensitive,
      };
    }
  }
  return {
    ok: false,
    reason: REASON.EXHAUSTED,
    name: '',
    path: '',
    attempts: maxAttempts,
    truncated,
  };
}

function describeAllocation(plan) {
  if (!plan || typeof plan !== 'object') return '下载文件名分配结果缺失';
  switch (plan.reason) {
    case REASON.OK:
      return plan.attempts > 1
        ? `已避开重名，保存为 ${plan.name}（第 ${plan.attempts} 次尝试）`
        : `保存为 ${plan.name}`;
    case REASON.EXHAUSTED:
      return `同名文件过多，${plan.attempts} 次尝试后仍无法分配文件名`;
    case REASON.INVALID_NAME:
      return '下载文件名为空或含路径分隔符';
    case REASON.INVALID_DIR:
      return '下载目录不是绝对路径';
    default:
      return `文件名分配失败：${String(plan.reason || 'unknown')}`;
  }
}

function reserveIndex(entries, name, caseInsensitive) {
  if (typeof name !== 'string' || name.length === 0) return false;
  const key = caseInsensitive === false ? name : foldName(name);
  if (Array.isArray(entries)) {
    const exists = entries.some((entry) => typeof entry === 'string'
      && ((caseInsensitive === false ? entry : foldName(entry)) === key));
    if (exists) return false;
    entries.push(name);
    return true;
  }
  if (entries instanceof Set) {
    const exists = [...entries].some((entry) => typeof entry === 'string'
      && ((caseInsensitive === false ? entry : foldName(entry)) === key));
    if (exists) return false;
    entries.add(name);
    return true;
  }
  if (entries && typeof entries === 'object') {
    const exists = Object.keys(entries).some((entry) => (caseInsensitive === false ? entry : foldName(entry)) === key);
    if (exists) return false;
    entries[name] = true;
    return true;
  }
  return false;
}

module.exports = {
  MAX_ATTEMPTS,
  MAX_NAME_BYTES,
  MAX_STEM_BYTES,
  MAX_EXT_BYTES,
  REASON,
  foldName,
  nameBytes,
  splitExtension,
  truncateToBytes,
  normalizeTaken,
  planUniquePath,
  describeAllocation,
  reserveIndex,
};
