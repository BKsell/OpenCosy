'use strict';
const { describeReasonFrom } = require('./reasontext');

const REASON = {
  OK: 'ok',
  EMPTY: 'empty',
  BAD_NONCE: 'bad-nonce',
  SHORT_NONCE: 'short-nonce',
  CSP_MISSING: 'csp-missing',
  CSP_NO_NONCE: 'csp-no-nonce',
  UNSAFE_INLINE: 'unsafe-inline',
  WILDCARD: 'wildcard-source',
  DUPLICATE_DIRECTIVE: 'duplicate-directive',
};

const MIN_NONCE_BYTES = 16;
const MAX_NONCE_LENGTH = 128;
const NONCE_PATTERN = /^[A-Za-z0-9+/]{8,126}(?:==|=)?$/;
const DIRECTIVE_SPLIT = /;/;

function inspectNonce(nonce) {
  if (typeof nonce !== 'string' || !nonce) return { ok: false, reason: REASON.EMPTY };
  if (nonce.length > MAX_NONCE_LENGTH) return { ok: false, reason: REASON.BAD_NONCE };
  if (!NONCE_PATTERN.test(nonce)) return { ok: false, reason: REASON.BAD_NONCE };
  const decoded = Buffer.from(nonce, 'base64');
  if (decoded.length < MIN_NONCE_BYTES) return { ok: false, reason: REASON.SHORT_NONCE };
  return { ok: true, reason: REASON.OK };
}

function parseDirectives(csp) {
  const directives = new Map();
  let duplicate = false;
  for (const part of csp.split(DIRECTIVE_SPLIT)) {
    const text = part.trim();
    if (!text) continue;
    const pieces = text.split(/\s+/);
    const name = pieces[0].toLowerCase();
    if (directives.has(name)) duplicate = true;
    directives.set(name, pieces.slice(1));
  }
  return { directives, duplicate };
}

function inspectCspNonce(csp, nonce) {
  const nonceResult = inspectNonce(nonce);
  if (!nonceResult.ok) return { ok: false, reason: nonceResult.reason };
  if (typeof csp !== 'string' || !csp.trim()) return { ok: false, reason: REASON.CSP_MISSING };
  const parsed = parseDirectives(csp);
  if (parsed.duplicate) return { ok: false, reason: REASON.DUPLICATE_DIRECTIVE };
  const names = ['script-src', 'default-src'];
  for (const name of names) {
    const sources = parsed.directives.get(name);
    if (!sources) continue;
    for (const source of sources) {
      if (source === "'unsafe-inline'") return { ok: false, reason: REASON.UNSAFE_INLINE };
      if (source === '*') return { ok: false, reason: REASON.WILDCARD };
    }
  }
  for (const name of names) {
    const sources = parsed.directives.get(name);
    if (!sources) continue;
    const token = "'nonce-" + nonce + "'";
    if (sources.includes(token)) return { ok: true, reason: REASON.OK, directive: name };
  }
  return { ok: false, reason: REASON.CSP_NO_NONCE };
}

function applyCspNonceGuard(csp, nonce) {
  const result = inspectCspNonce(csp, nonce);
  return { changed: !result.ok, reason: result.reason };
}

function describeReason(reason) {
  return describeReasonFrom({
    [REASON.EMPTY]: 'CSP nonce 为空',
    [REASON.BAD_NONCE]: 'CSP nonce 不是合法 base64',
    [REASON.SHORT_NONCE]: 'CSP nonce 随机熵不足',
    [REASON.CSP_MISSING]: '缺少 Content-Security-Policy 头',
    [REASON.CSP_NO_NONCE]: 'CSP 未绑定当前响应 nonce',
    [REASON.UNSAFE_INLINE]: 'CSP 允许 unsafe-inline',
    [REASON.WILDCARD]: 'CSP 使用通配来源',
    [REASON.DUPLICATE_DIRECTIVE]: 'CSP 存在重复指令',
  }, reason, 'CSP 与 nonce 绑定正确');
}

module.exports = {
  REASON,
  MIN_NONCE_BYTES,
  MAX_NONCE_LENGTH,
  inspectNonce,
  parseDirectives,
  inspectCspNonce,
  applyCspNonceGuard,
  describeReason,
};
