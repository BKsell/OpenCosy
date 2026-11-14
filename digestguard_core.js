'use strict';
const { describeReasonTable } = require('./reasontext');

const { firstValue, headerKey } = require('./headerutil_core');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  WEAK_ALGORITHM: 'weak-algorithm',
  DUPLICATE: 'duplicate',
};

const WEAK_ALGORITHMS = new Set(['md5', 'sha', 'sha-1', 'sha1', 'adler32', 'crc32', 'crc32c']);
const STRONG_ALGORITHMS = new Set(['sha-256', 'sha-512', 'sha-384', 'sha-512/256', 'sha3-256', 'blake3']);
const MAX_ENTRIES = 8;
const MAX_VALUE_LENGTH = 1024;

function normalizeAlgorithm(raw) {
  return raw.trim().toLowerCase();
}

function parseStructuredEntry(entry) {
  const eq = entry.indexOf('=');
  if (eq <= 0) return null;
  const algorithm = normalizeAlgorithm(entry.slice(0, eq));
  let value = entry.slice(eq + 1).trim();
  if (value.startsWith(':') && value.endsWith(':') && value.length >= 2) {
    value = value.slice(1, -1);
  }
  if (value.length > 512) return null;
  if (!/^[A-Za-z0-9+/=_-]+$/.test(value)) return null;
  return { algorithm, value };
}

function inspectDigests(headers, name) {
  const value = firstValue(headers, name);
  if (!value) return { present: false, findings: [], kept: [] };
  const findings = [];
  if (value.length > MAX_VALUE_LENGTH) {
    return { present: true, findings: [{ reason: REASON.MALFORMED }], kept: [] };
  }
  const rawEntries = value.split(',');
  if (rawEntries.length > MAX_ENTRIES) {
    return { present: true, findings: [{ reason: REASON.MALFORMED }], kept: [] };
  }
  const seen = new Set();
  const kept = [];
  for (const entry of rawEntries) {
    const parsed = parseStructuredEntry(entry);
    if (!parsed) {
      findings.push({ reason: REASON.MALFORMED, entry });
      continue;
    }
    if (WEAK_ALGORITHMS.has(parsed.algorithm)) {
      findings.push({ reason: REASON.WEAK_ALGORITHM, entry, algorithm: parsed.algorithm });
      continue;
    }
    if (!STRONG_ALGORITHMS.has(parsed.algorithm)) {
      findings.push({ reason: REASON.MALFORMED, entry, algorithm: parsed.algorithm });
      continue;
    }
    if (seen.has(parsed.algorithm)) {
      findings.push({ reason: REASON.DUPLICATE, entry, algorithm: parsed.algorithm });
      continue;
    }
    seen.add(parsed.algorithm);
    kept.push(entry.trim());
  }
  return { present: true, findings, kept };
}

function inspectDigest(headers) {
  const content = inspectDigests(headers, 'content-digest');
  const repr = inspectDigests(headers, 'repr-digest');
  const legacy = inspectDigests(headers, 'digest');
  const findings = content.findings.concat(repr.findings, legacy.findings);
  const present = content.present || repr.present || legacy.present;
  if (!present) return { changed: false, reason: REASON.MISSING, findings: [] };
  let reason = REASON.OK;
  if (findings.some((item) => item.reason === REASON.MALFORMED)) reason = REASON.MALFORMED;
  else if (findings.some((item) => item.reason === REASON.WEAK_ALGORITHM)) reason = REASON.WEAK_ALGORITHM;
  else if (findings.some((item) => item.reason === REASON.DUPLICATE)) reason = REASON.DUPLICATE;
  return { changed: findings.length > 0, reason, findings };
}

function rewriteHeader(headers, name, result) {
  if (!result.present) return;
  const key = headerKey(headers, name);
  if (!key) return;
  if (!result.kept.length) {
    delete headers[key];
    return;
  }
  headers[key] = [result.kept.join(', ')];
}

function applyDigestGuard(headers) {
  const content = inspectDigests(headers, 'content-digest');
  const repr = inspectDigests(headers, 'repr-digest');
  const legacy = inspectDigests(headers, 'digest');
  const result = inspectDigest(headers);
  if (!result.changed) return result;
  rewriteHeader(headers, 'content-digest', content);
  rewriteHeader(headers, 'repr-digest', repr);
  rewriteHeader(headers, 'digest', legacy);
  return result;
}

const describeReason = describeReasonTable({
    [REASON.MALFORMED]: '摘要字段格式非法或算法未知',
    [REASON.WEAK_ALGORITHM]: '摘要使用已淘汰的弱算法',
    [REASON.DUPLICATE]: '同一算法重复声明摘要',
    [REASON.MISSING]: '未声明内容摘要',
  }, '内容摘要通过校验');

module.exports = {
  REASON,
  WEAK_ALGORITHMS,
  STRONG_ALGORITHMS,
  MAX_ENTRIES,
  inspectDigests,
  inspectDigest,
  applyDigestGuard,
  describeReason,
};
