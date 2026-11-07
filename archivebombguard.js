'use strict';

const REASON = {
  OK: 'ok',
  TOO_MANY_ENTRIES: 'archive-too-many-entries',
  RATIO_EXCEEDED: 'archive-ratio-exceeded',
  ENTRY_TRAVERSAL: 'archive-entry-traversal',
  ABSOLUTE_ENTRY: 'archive-absolute-entry',
  ENTRY_TOO_LARGE: 'archive-entry-too-large',
  TOTAL_TOO_LARGE: 'archive-total-too-large',
  NESTED_ARCHIVE: 'archive-nested-bomb',
};

const DEFAULTS = {
  maxEntries: 20000,
  maxRatio: 120,
  maxEntryBytes: 512 * 1024 * 1024,
  maxTotalBytes: 2 * 1024 * 1024 * 1024,
  maxDepth: 2,
};

function normalizeEntry(name) {
  return String(name || '').replace(/\\/g, '/');
}

function evaluateArchiveEntry(entry, options) {
  const opts = { ...DEFAULTS, ...(options || {}) };
  const name = normalizeEntry(entry && entry.name);
  if (name === '') return { ok: false, blocked: true, reason: REASON.ENTRY_TRAVERSAL, name };
  if (name.startsWith('/') || /^[A-Za-z]:/.test(name)) {
    return { ok: false, blocked: true, reason: REASON.ABSOLUTE_ENTRY, name };
  }
  if (name.split('/').some((seg) => seg === '..')) {
    return { ok: false, blocked: true, reason: REASON.ENTRY_TRAVERSAL, name };
  }
  const size = Number(entry && entry.size);
  const compressed = Number(entry && entry.compressed);
  if (!Number.isFinite(size) || size < 0) {
    return { ok: false, blocked: true, reason: REASON.ENTRY_TOO_LARGE, name };
  }
  if (size > opts.maxEntryBytes) {
    return { ok: false, blocked: true, reason: REASON.ENTRY_TOO_LARGE, name, size };
  }
  if (compressed > 0 && size / compressed > opts.maxRatio) {
    return { ok: false, blocked: true, reason: REASON.RATIO_EXCEEDED, name, ratio: Math.round(size / compressed) };
  }
  return { ok: true, blocked: false, reason: REASON.OK, name, size };
}

function evaluateArchive(archive, options) {
  const opts = { ...DEFAULTS, ...(options || {}) };
  const item = archive || {};
  const entries = Array.isArray(item.entries) ? item.entries : [];
  const findings = [];
  let blocked = 0;
  let total = 0;
  if (entries.length > opts.maxEntries) {
    blocked += 1;
    findings.push({ reason: REASON.TOO_MANY_ENTRIES, count: entries.length });
  }
  for (const entry of entries) {
    const result = evaluateArchiveEntry(entry, opts);
    if (Number.isFinite(Number(entry && entry.size))) total += Number(entry.size);
    if (result.blocked) {
      blocked += 1;
      findings.push({ reason: result.reason, name: result.name, ratio: result.ratio });
    }
  }
  if (total > opts.maxTotalBytes) {
    blocked += 1;
    findings.push({ reason: REASON.TOTAL_TOO_LARGE, total });
  }
  if (Number(item.depth || 0) > opts.maxDepth) {
    blocked += 1;
    findings.push({ reason: REASON.NESTED_ARCHIVE, depth: item.depth });
  }
  return { ok: blocked === 0, blocked: blocked > 0, reason: blocked ? findings[0].reason : REASON.OK, findings, total };
}

function auditArchiveBatch(list, options) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateArchive(item, options);
    if (result.blocked) {
      blocked += 1;
      findings.push(...result.findings);
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no archive bomb risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.name || f.count || f.total || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  DEFAULTS,
  evaluateArchiveEntry,
  evaluateArchive,
  auditArchiveBatch,
  describeFindings,
};
