'use strict';

const REASON = Object.freeze({
  OK: 'ok',
  PROXY_CHALLENGE: 'proxy-challenge',
  NEGOTIATE_SCHEME: 'negotiate-scheme',
  NTLM_SCHEME: 'ntlm-scheme',
  SUBRESOURCE_CHALLENGE: 'subresource-challenge',
  INSECURE_TRANSPORT: 'insecure-transport',
  NON_HTTP_SCHEME: 'non-http-scheme',
});

const SILENT_SCHEMES = new Set(['NTLM', 'NEGOTIATE', 'KERBEROS']);
const CHALLENGE_SPLIT = /(?=\b(?:Basic|Digest|Bearer|NTLM|Negotiate|Kerberos|AWS4-HMAC-SHA256)\b)/i;

function headerValues(headers, name) {
  if (!headers || typeof headers !== 'object') return [];
  const lower = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() !== lower) continue;
    const value = headers[key];
    if (Array.isArray(value)) return value.map((v) => String(v));
    if (value === undefined || value === null) return [];
    return [String(value)];
  }
  return [];
}

function setHeader(headers, name, values) {
  const lower = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) delete headers[key];
  }
  if (values && values.length) headers[name] = values;
}

function schemeOf(challenge) {
  const match = /^\s*([A-Za-z0-9_-]+)/.exec(String(challenge));
  return match ? match[1].toUpperCase() : '';
}

function splitChallenges(values) {
  const out = [];
  for (const value of values) {
    const parts = String(value).split(CHALLENGE_SPLIT);
    for (const part of parts) {
      const trimmed = part.trim();
      if (trimmed) out.push(trimmed);
    }
  }
  return out;
}

function evaluateAuthChallenge(headers, details = {}) {
  const proxy = headerValues(headers, 'Proxy-Authenticate');
  if (proxy.length) {
    return { action: 'strip', reason: REASON.PROXY_CHALLENGE, strip: ['Proxy-Authenticate'] };
  }

  const values = headerValues(headers, 'WWW-Authenticate');
  if (!values.length) return { action: 'allow', reason: REASON.OK, strip: [] };

  const url = typeof details.url === 'string' ? details.url : '';
  if (url && !url.startsWith('https://') && !url.startsWith('http://')) {
    return { action: 'strip', reason: REASON.NON_HTTP_SCHEME, strip: ['WWW-Authenticate'] };
  }
  if (url.startsWith('http://')) {
    return { action: 'strip', reason: REASON.INSECURE_TRANSPORT, strip: ['WWW-Authenticate'] };
  }
  if (details.resourceType && details.resourceType !== 'mainFrame') {
    return { action: 'strip', reason: REASON.SUBRESOURCE_CHALLENGE, strip: ['WWW-Authenticate'] };
  }

  const challenges = splitChallenges(values);
  const silent = challenges.filter((c) => SILENT_SCHEMES.has(schemeOf(c)));
  if (!silent.length) return { action: 'allow', reason: REASON.OK, strip: [] };

  const reason = silent.some((c) => schemeOf(c) === 'NTLM') ? REASON.NTLM_SCHEME : REASON.NEGOTIATE_SCHEME;
  const kept = challenges.filter((c) => !SILENT_SCHEMES.has(schemeOf(c)));
  return {
    action: 'strip',
    reason,
    strip: ['WWW-Authenticate'],
    replace: { name: 'WWW-Authenticate', values: kept.length ? [kept.join(', ')] : [] },
  };
}

function applyAuthChallengeGuard(headers, details = {}) {
  const verdict = evaluateAuthChallenge(headers, details);
  if (verdict.action === 'allow') return { changed: false, verdict };
  for (const name of verdict.strip) setHeader(headers, name, []);
  if (verdict.replace) setHeader(headers, verdict.replace.name, verdict.replace.values);
  return { changed: true, verdict };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK: return '认证挑战正常';
    case REASON.PROXY_CHALLENGE: return '代理认证挑战已移除';
    case REASON.NEGOTIATE_SCHEME: return 'Negotiate/Kerberos 会静默复用域凭据';
    case REASON.NTLM_SCHEME: return 'NTLM 会静默复用系统凭据';
    case REASON.SUBRESOURCE_CHALLENGE: return '子资源触发认证弹框';
    case REASON.INSECURE_TRANSPORT: return '明文 HTTP 上的认证挑战';
    case REASON.NON_HTTP_SCHEME: return '非 HTTP 协议上的认证挑战';
    default: return String(reason || '');
  }
}

module.exports = {
  REASON,
  evaluateAuthChallenge,
  applyAuthChallengeGuard,
  describeReason,
  splitChallenges,
  schemeOf,
};
