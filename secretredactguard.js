'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'empty',
  NOT_TEXT: 'not-text',
  REDACTED: 'redacted',
  TOO_LARGE: 'too-large',
};

const MAX_BYTES = 512 * 1024;
const MASK = '[REDACTED]';

const PATTERNS = [
  { name: 'private-key', re: /-----BEGIN [A-Z ]{0,20}PRIVATE KEY-----/g },
  { name: 'bearer', re: /(\bbearer\s+)[A-Za-z0-9._~+/=-]{8,200}/gi },
  { name: 'basic', re: /(\bbasic\s+)[A-Za-z0-9+/=]{8,200}/gi },
  { name: 'aws-access-key', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{20,60}\b/g },
  { name: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{30,45}\b/g },
  { name: 'slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,60}\b/g },
  { name: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,200}\.[A-Za-z0-9_-]{10,200}\.[A-Za-z0-9_-]{10,200}\b/g },
  { name: 'password-field', re: /(\b(?:password|passwd|pwd|secret|token|api[_-]?key)\b["']?\s*[=:]\s*)([^&\s"',;]{6,200})/gi },
];

function redactSecrets(text, options) {
  const limit = (options && options.maxBytes) || MAX_BYTES;
  if (typeof text !== 'string') return { changed: false, reason: REASON.NOT_TEXT, text: '', hits: 0 };
  if (!text) return { changed: false, reason: REASON.EMPTY, text: '', hits: 0 };
  if (Buffer.byteLength(text, 'utf8') > limit) return { changed: false, reason: REASON.TOO_LARGE, text: '', hits: 0 };
  let output = text;
  let hits = 0;
  for (const pattern of PATTERNS) {
    pattern.re.lastIndex = 0;
    output = output.replace(pattern.re, (match, prefix) => {
      hits += 1;
      if (typeof prefix === 'string' && prefix.length && match.startsWith(prefix)) {
        return prefix + MASK;
      }
      return MASK;
    });
  }
  if (hits === 0) return { changed: false, reason: REASON.OK, text: output, hits: 0 };
  return { changed: true, reason: REASON.REDACTED, text: output, hits };
}

function applySecretRedactGuard(text, options) {
  const result = redactSecrets(text, options);
  return { changed: result.changed, reason: result.reason, text: result.text, hits: result.hits };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.EMPTY:
      return '待脱敏文本为空';
    case REASON.NOT_TEXT:
      return '待脱敏内容不是文本';
    case REASON.REDACTED:
      return '文本中的凭据已脱敏';
    case REASON.TOO_LARGE:
      return '待脱敏文本超过体积上限';
    default:
      return '文本未包含可识别凭据';
  }
}

module.exports = {
  REASON,
  MAX_BYTES,
  MASK,
  PATTERNS,
  redactSecrets,
  applySecretRedactGuard,
  describeReason,
};
