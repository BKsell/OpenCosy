'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'cache-partition-empty',
  TOO_LONG: 'cache-partition-too-long',
  INVALID_CHARS: 'cache-partition-invalid-chars',
  SHARED_PARTITION: 'cache-partition-shared',
  PATH_TRAVERSAL: 'cache-partition-traversal',
  RESERVED_NAME: 'cache-partition-reserved',
};

const MAX_PARTITION = 64;
const RESERVED = new Set(['default', 'persist', 'shared', 'system', 'temp']);
const ALLOWED = /^[a-z0-9][a-z0-9._-]*$/;

function evaluateCachePartition(value, options) {
  const opts = options || {};
  const name = String(value || '').trim().toLowerCase();
  if (name === '') return { ok: false, blocked: true, reason: REASON.EMPTY, partition: name };
  if (name.length > MAX_PARTITION) return { ok: false, blocked: true, reason: REASON.TOO_LONG, partition: name };
  if (name.includes('..') || name.includes('/') || name.includes('\\')) {
    return { ok: false, blocked: true, reason: REASON.PATH_TRAVERSAL, partition: name };
  }
  if (!ALLOWED.test(name)) {
    return { ok: false, blocked: true, reason: REASON.INVALID_CHARS, partition: name };
  }
  if (opts.allowShared !== true && (RESERVED.has(name) || name.startsWith('shared')) && opts.allowReserved !== true) {
    return { ok: false, blocked: true, reason: REASON.SHARED_PARTITION, partition: name };
  }
  return { ok: true, blocked: false, reason: REASON.OK, partition: name, scoped: opts.allowShared !== true };
}

function evaluateSessionPartitions(session) {
  const s = session || {};
  const partitions = s.partitions || {};
  const findings = [];
  let blocked = 0;
  const defaults = partitions.default;
  const result = evaluateCachePartition(defaults || 'browser', { allowShared: false });
  if (result.blocked) {
    blocked += 1;
    findings.push({ partition: result.partition, reason: result.reason });
  }
  if (typeof partitions === 'object' && partitions !== null) {
    for (const key of Object.keys(partitions)) {
      if (key === 'default') continue;
      const value = partitions[key];
      const item = evaluateCachePartition(key, { allowReserved: true });
      if (item.blocked) {
        blocked += 1;
        findings.push({ partition: item.partition, reason: item.reason });
      }
      if (value && typeof value === 'string' && value.startsWith('persist:')) {
        const persist = evaluateCachePartition(value.slice('persist:'.length), { allowReserved: true });
        if (persist.blocked) {
          blocked += 1;
          findings.push({ partition: persist.partition, reason: persist.reason });
        }
      }
    }
  }
  return { ok: blocked === 0, blocked: blocked > 0, findings };
}

function auditPartitionBatch(list) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateCachePartition(item);
    if (result.blocked) {
      blocked += 1;
      findings.push({ partition: result.partition, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no cache partition risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.partition || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateCachePartition,
  evaluateSessionPartitions,
  auditPartitionBatch,
  describeFindings,
};
