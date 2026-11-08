'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  PROXY_HEADER: 'proxy-header',
  INSECURE_BASIC: 'insecure-basic',
  NTLM_LEAK: 'ntlm-leak',
  MALFORMED: 'malformed',
  TOO_MANY: 'too-many',
};

const MAX_CHALLENGE_LENGTH = 256;
const MAX_CHALLENGES = 5;
const PROXY_HEADERS = ['proxy-authenticate', 'proxy-authentication-info', 'proxy-authorization'];
const LEAKY_SCHEMES = new Set(['ntlm', 'negotiate', 'kerberos']);

function lowerKeys(headers) {
  const map = {};
  if (!headers || typeof headers !== 'object') return map;
  for (const key of Object.keys(headers)) map[key.toLowerCase()] = key;
  return map;
}

function requestProtocol(details) {
  try {
    return new URL(details && details.url ? details.url : 'https://localhost/').protocol;
  } catch {
    return 'https:';
  }
}

function requestHost(details) {
  try {
    return new URL(details && details.url ? details.url : 'https://localhost/').hostname.toLowerCase();
  } catch {
    return '';
  }
}

function parseChallenges(value) {
  if (typeof value !== 'string') return null;
  if (value.length > MAX_CHALLENGE_LENGTH) return null;
  const challenges = [];
  let current = '';
  let quoted = false;
  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i];
    if (ch === '"' && value[i - 1] !== '\\') quoted = !quoted;
    if (ch === ',' && !quoted) {
      challenges.push(current.trim());
      current = '';
      continue;
    }
    current += ch;
  }
  challenges.push(current.trim());
  const parsed = [];
  for (const item of challenges) {
    if (!item) return null;
    const scheme = item.split(/\s+/)[0].toLowerCase();
    if (!/^[a-z][a-z0-9-]{0,30}$/.test(scheme)) return null;
    parsed.push({ scheme, raw: item });
  }
  return parsed;
}

function inspectProxyAuth(headers, details) {
  const keys = lowerKeys(headers);
  if (!headers || typeof headers !== 'object' || !Object.keys(headers).length) {
    return { changed: false, findings: [] };
  }
  const findings = [];
  for (const name of PROXY_HEADERS) {
    if (keys[name]) {
      delete headers[keys[name]];
      findings.push({ header: name, reason: REASON.PROXY_HEADER });
    }
  }
  const wwwKey = keys['www-authenticate'];
  if (wwwKey) {
    const raw = headers[wwwKey];
    const value = Array.isArray(raw) ? raw[0] : raw;
    const parsed = parseChallenges(value);
    if (!parsed) {
      delete headers[wwwKey];
      findings.push({ header: 'www-authenticate', reason: REASON.MALFORMED });
    } else {
      const protocol = requestProtocol(details);
      const host = requestHost(details);
      const isIpLiteral = /^[\d.]+$/.test(host) || host.includes(':');
      const leaky = parsed.some((c) => LEAKY_SCHEMES.has(c.scheme));
      if (parsed.length > MAX_CHALLENGES) {
        delete headers[wwwKey];
        findings.push({ header: 'www-authenticate', reason: REASON.TOO_MANY });
      } else if (leaky && (protocol !== 'https:' || isIpLiteral)) {
        delete headers[wwwKey];
        findings.push({ header: 'www-authenticate', reason: REASON.NTLM_LEAK });
      } else if (protocol !== 'https:' && parsed.some((c) => c.scheme === 'basic')) {
        delete headers[wwwKey];
        findings.push({ header: 'www-authenticate', reason: REASON.INSECURE_BASIC });
      }
    }
  }
  return { changed: findings.length > 0, findings };
}

function applyProxyAuthGuard(headers, details) {
  return inspectProxyAuth(headers, details || {});
}

function describeReason(reason) {
  switch (reason) {
    case REASON.PROXY_HEADER:
      return '剥离代理认证头';
    case REASON.INSECURE_BASIC:
      return '明文链路上剥离 Basic 认证挑战';
    case REASON.NTLM_LEAK:
      return '剥离可泄露凭据的 NTLM/Negotiate 挑战';
    case REASON.MALFORMED:
      return '认证挑战结构非法';
    case REASON.TOO_MANY:
      return '认证挑战数量超限';
    default:
      return '认证头通过校验';
  }
}

module.exports = {
  REASON,
  MAX_CHALLENGE_LENGTH,
  MAX_CHALLENGES,
  parseChallenges,
  inspectProxyAuth,
  applyProxyAuthGuard,
  describeReason,
};
