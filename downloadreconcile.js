'use strict';

const VERDICT = {
  OK: 'ok',
  SKIPPED: 'skipped',
  MISSING: 'missing',
  SIZE_MISMATCH: 'size-mismatch',
  UNREADABLE: 'unreadable',
};

const DEFAULT_MAX_VERIFY = 200;

function safeInt(value, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.trunc(n);
}

function describeVerdict(verdict) {
  switch (verdict) {
    case VERDICT.OK: return '落盘文件与记录一致';
    case VERDICT.SKIPPED: return '未做文件核对';
    case VERDICT.MISSING: return '记录存在但文件已被移除';
    case VERDICT.SIZE_MISMATCH: return '落盘文件大小与记录不一致';
    case VERDICT.UNREADABLE: return '无法读取落盘文件状态';
    default: return '未知核对结果';
  }
}

function reconcileEntry(entry, options = {}) {
  if (!entry || typeof entry !== 'object') {
    return { entry, change: null, verdict: VERDICT.SKIPPED };
  }
  const target = typeof entry.savePath === 'string' && entry.savePath ? entry.savePath : '';
  if (!target) return { entry: { ...entry, fileCheck: VERDICT.SKIPPED }, change: null, verdict: VERDICT.SKIPPED };
  const exists = typeof options.exists === 'function' ? options.exists : () => true;
  const sizeOf = typeof options.sizeOf === 'function' ? options.sizeOf : () => null;
  let present = false;
  try {
    present = !!exists(target);
  } catch {
    return { entry: { ...entry, fileCheck: VERDICT.UNREADABLE }, change: null, verdict: VERDICT.UNREADABLE };
  }
  if (!present) {
    const change = entry.fileCheck === VERDICT.MISSING ? null : { id: entry.id, from: entry.fileCheck || VERDICT.SKIPPED, to: VERDICT.MISSING };
    return { entry: { ...entry, fileCheck: VERDICT.MISSING }, change, verdict: VERDICT.MISSING };
  }
  let actual = null;
  try {
    actual = sizeOf(target);
  } catch {
    return { entry: { ...entry, fileCheck: VERDICT.UNREADABLE }, change: null, verdict: VERDICT.UNREADABLE };
  }
  const expected = safeInt(entry.receivedBytes, 0);
  if (actual === null || !Number.isFinite(actual)) {
    return { entry: { ...entry, fileCheck: VERDICT.UNREADABLE }, change: null, verdict: VERDICT.UNREADABLE };
  }
  actual = safeInt(actual, 0);
  if (expected > 0 && actual !== expected) {
    const change = entry.fileCheck === VERDICT.SIZE_MISMATCH ? null : { id: entry.id, from: entry.fileCheck || VERDICT.SKIPPED, to: VERDICT.SIZE_MISMATCH };
    return {
      entry: { ...entry, fileCheck: VERDICT.SIZE_MISMATCH, fileBytes: actual },
      change,
      verdict: VERDICT.SIZE_MISMATCH,
    };
  }
  const change = entry.fileCheck === VERDICT.OK && entry.fileBytes === actual
    ? null
    : { id: entry.id, from: entry.fileCheck || VERDICT.SKIPPED, to: VERDICT.OK };
  return { entry: { ...entry, fileCheck: VERDICT.OK, fileBytes: actual }, change, verdict: VERDICT.OK };
}

function reconcileEntries(entries, options = {}) {
  const list = Array.isArray(entries) ? entries : [];
  const maxVerify = safeInt(options.maxVerify, DEFAULT_MAX_VERIFY);
  const changes = [];
  const summary = { checked: 0, ok: 0, missing: 0, sizeMismatch: 0, unreadable: 0, skipped: 0 };
  const out = [];
  for (const entry of list) {
    if (!entry || typeof entry !== 'object') {
      out.push(entry);
      summary.skipped += 1;
      continue;
    }
    if (summary.checked >= maxVerify) {
      out.push({ ...entry, fileCheck: VERDICT.SKIPPED });
      summary.skipped += 1;
      continue;
    }
    summary.checked += 1;
    const result = reconcileEntry(entry, options);
    out.push(result.entry);
    if (result.change) changes.push(result.change);
    if (result.verdict === VERDICT.OK) summary.ok += 1;
    else if (result.verdict === VERDICT.MISSING) summary.missing += 1;
    else if (result.verdict === VERDICT.SIZE_MISMATCH) summary.sizeMismatch += 1;
    else if (result.verdict === VERDICT.UNREADABLE) summary.unreadable += 1;
    else summary.skipped += 1;
  }
  return { entries: out, changes, summary };
}

function summarizeReconcile(summary) {
  if (!summary) return '未执行下载记录核对';
  const parts = [`核对 ${safeInt(summary.checked, 0)} 条`];
  if (summary.ok) parts.push(`${summary.ok} 条正常`);
  if (summary.missing) parts.push(`${summary.missing} 条文件缺失`);
  if (summary.sizeMismatch) parts.push(`${summary.sizeMismatch} 条大小不符`);
  if (summary.unreadable) parts.push(`${summary.unreadable} 条无法读取`);
  return parts.join('，');
}

module.exports = {
  VERDICT,
  DEFAULT_MAX_VERIFY,
  describeVerdict,
  reconcileEntry,
  reconcileEntries,
  summarizeReconcile,
};
