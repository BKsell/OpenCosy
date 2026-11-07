'use strict';

const crypto = require('node:crypto');

const REASON = {
  OK: 'ok',
  EMPTY: 'empty',
  MALFORMED: 'malformed',
  WEAK_ALGORITHM: 'weak-algorithm',
  NO_STRONG: 'no-strong-algorithm',
  DIGEST_LENGTH: 'digest-length',
  MISMATCH: 'integrity-mismatch',
  NOT_BUFFER: 'not-buffer',
};

const STRONG_ALGORITHMS = ['sha256', 'sha384', 'sha512'];
const DIGEST_BYTES = { sha256: 32, sha384: 48, sha512: 64 };
const MAX_TOKEN_LENGTH = 128;

function parseSri(value) {
  if (typeof value !== 'string') return { ok: false, reason: REASON.EMPTY, tokens: [] };
  const text = value.trim();
  if (!text) return { ok: false, reason: REASON.EMPTY, tokens: [] };
  if (text.length > MAX_TOKEN_LENGTH * 4) return { ok: false, reason: REASON.MALFORMED, tokens: [] };
  const tokens = text.split(/\s+/).filter(Boolean);
  const parsed = [];
  let sawWeak = false;
  for (const token of tokens) {
    if (token.startsWith('?') || token.length > MAX_TOKEN_LENGTH) return { ok: false, reason: REASON.MALFORMED, tokens: [] };
    const dash = token.indexOf('-');
    if (dash <= 0) return { ok: false, reason: REASON.MALFORMED, tokens: [] };
    const algorithm = token.slice(0, dash).toLowerCase();
    const digest = token.slice(dash + 1);
    if (!STRONG_ALGORITHMS.includes(algorithm)) {
      if (algorithm === 'sha1' || algorithm === 'md5') {
        sawWeak = true;
        continue;
      }
      return { ok: false, reason: REASON.MALFORMED, tokens: [] };
    }
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(digest)) return { ok: false, reason: REASON.MALFORMED, tokens: [] };
    let decoded;
    try {
      decoded = Buffer.from(digest, 'base64');
    } catch (err) {
      return { ok: false, reason: REASON.MALFORMED, tokens: [] };
    }
    if (decoded.length !== DIGEST_BYTES[algorithm]) return { ok: false, reason: REASON.DIGEST_LENGTH, tokens: [] };
    parsed.push({ algorithm, digest });
  }
  if (parsed.length === 0) {
    return { ok: false, reason: sawWeak ? REASON.NO_STRONG : REASON.MALFORMED, tokens: [] };
  }
  return { ok: true, reason: REASON.OK, tokens: parsed, weakPresent: sawWeak };
}

function verifyIntegrity(buffer, value) {
  if (!Buffer.isBuffer(buffer)) return { ok: false, reason: REASON.NOT_BUFFER, matched: false, algorithms: [] };
  const parsed = parseSri(value);
  if (!parsed.ok) return { ok: false, reason: parsed.reason, matched: false, algorithms: [] };
  const algorithms = parsed.tokens.map((token) => token.algorithm);
  for (const token of parsed.tokens) {
    const actual = crypto.createHash(token.algorithm).update(buffer).digest('base64');
    if (actual === token.digest) {
      return { ok: true, reason: REASON.OK, matched: true, algorithms };
    }
  }
  return { ok: false, reason: REASON.MISMATCH, matched: false, algorithms };
}

function applySriGuard(buffer, value) {
  const result = verifyIntegrity(buffer, value);
  return { changed: !result.ok, reason: result.reason, matched: result.matched, algorithms: result.algorithms };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.EMPTY:
      return '未声明完整性校验值';
    case REASON.MALFORMED:
      return '完整性校验值格式非法';
    case REASON.WEAK_ALGORITHM:
      return '完整性校验使用弱算法';
    case REASON.NO_STRONG:
      return '完整性校验缺少强算法';
    case REASON.DIGEST_LENGTH:
      return '完整性校验摘要长度不符';
    case REASON.MISMATCH:
      return '资源内容与完整性校验值不匹配';
    case REASON.NOT_BUFFER:
      return '待校验内容不是二进制缓冲';
    default:
      return '资源完整性校验通过';
  }
}

module.exports = {
  REASON,
  STRONG_ALGORITHMS,
  DIGEST_BYTES,
  parseSri,
  verifyIntegrity,
  applySriGuard,
  describeReason,
};
