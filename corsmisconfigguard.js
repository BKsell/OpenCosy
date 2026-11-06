'use strict';

const REASON = Object.freeze({
  OK: 'ok',
  WILDCARD_CREDENTIALS: 'wildcard-credentials',
  NULL_ORIGIN: 'null-origin',
  MULTIPLE_ORIGINS: 'multiple-origins',
  CREDENTIALS_WITHOUT_ORIGIN: 'credentials-without-origin',
  TRACE_METHOD: 'trace-method',
  EXPOSED_SENSITIVE_HEADER: 'exposed-sensitive-header',
  PRIVATE_NETWORK: 'private-network',
});

const SENSITIVE_EXPOSE = new Set([
  'set-cookie',
  'set-cookie2',
  'authorization',
  'proxy-authorization',
  'cookie',
  'x-api-key',
  'x-auth-token',
]);

const UNSAFE_METHODS = new Set(['TRACE', 'TRACK', 'CONNECT']);

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

function splitTokens(values) {
  const out = [];
  for (const value of values) {
    for (const token of String(value).split(',')) {
      const trimmed = token.trim();
      if (trimmed) out.push(trimmed);
    }
  }
  return out;
}

function evaluateCors(headers) {
  const acao = headerValues(headers, 'Access-Control-Allow-Origin');
  const acac = headerValues(headers, 'Access-Control-Allow-Credentials');
  const methods = headerValues(headers, 'Access-Control-Allow-Methods');
  const expose = headerValues(headers, 'Access-Control-Expose-Headers');
  const privateNetwork = headerValues(headers, 'Access-Control-Allow-Private-Network');

  if (acao.length > 1) {
    return { action: 'strip', reason: REASON.MULTIPLE_ORIGINS, strip: ['Access-Control-Allow-Origin', 'Access-Control-Allow-Credentials'] };
  }

  if (acao.length === 1 && acao[0].trim() === 'null') {
    return { action: 'strip', reason: REASON.NULL_ORIGIN, strip: ['Access-Control-Allow-Origin', 'Access-Control-Allow-Credentials'] };
  }

  const origin = acao.length === 1 ? acao[0].trim() : '';
  const wildcard = origin === '*';
  const credentials = acac.length === 1 && acac[0].trim().toLowerCase() === 'true';

  if (wildcard && credentials) {
    return { action: 'strip', reason: REASON.WILDCARD_CREDENTIALS, strip: ['Access-Control-Allow-Credentials'] };
  }

  if (credentials && !origin) {
    return { action: 'strip', reason: REASON.CREDENTIALS_WITHOUT_ORIGIN, strip: ['Access-Control-Allow-Credentials'] };
  }

  const unsafe = splitTokens(methods).map((m) => m.toUpperCase()).filter((m) => UNSAFE_METHODS.has(m));
  if (unsafe.length) {
    const kept = splitTokens(methods).filter((m) => !UNSAFE_METHODS.has(m.toUpperCase()));
    return {
      action: 'strip',
      reason: REASON.TRACE_METHOD,
      strip: ['Access-Control-Allow-Methods'],
      replace: { name: 'Access-Control-Allow-Methods', values: kept.length ? [kept.join(', ')] : [] },
    };
  }

  const exposed = splitTokens(expose);
  const leaked = exposed.filter((h) => SENSITIVE_EXPOSE.has(h.toLowerCase()));
  if (leaked.length) {
    const kept = exposed.filter((h) => !SENSITIVE_EXPOSE.has(h.toLowerCase()));
    return {
      action: 'strip',
      reason: REASON.EXPOSED_SENSITIVE_HEADER,
      strip: ['Access-Control-Expose-Headers'],
      replace: { name: 'Access-Control-Expose-Headers', values: kept.length ? [kept.join(', ')] : [] },
    };
  }

  if (privateNetwork.length && splitTokens(privateNetwork).some((v) => v.toLowerCase() === 'true')) {
    return { action: 'strip', reason: REASON.PRIVATE_NETWORK, strip: ['Access-Control-Allow-Private-Network'] };
  }

  return { action: 'allow', reason: REASON.OK, strip: [] };
}

function applyCorsGuard(headers) {
  const verdict = evaluateCors(headers);
  if (verdict.action === 'allow') return { changed: false, verdict };
  for (const name of verdict.strip) setHeader(headers, name, []);
  if (verdict.replace) setHeader(headers, verdict.replace.name, verdict.replace.values);
  return { changed: true, verdict };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK: return 'CORS 配置正常';
    case REASON.WILDCARD_CREDENTIALS: return '通配来源同时允许携带凭据';
    case REASON.NULL_ORIGIN: return '允许 null 来源，沙箱页面可越权读取';
    case REASON.MULTIPLE_ORIGINS: return '响应中出现多个 Allow-Origin';
    case REASON.CREDENTIALS_WITHOUT_ORIGIN: return '允许凭据但未声明来源';
    case REASON.TRACE_METHOD: return 'CORS 允许 TRACE 等方法';
    case REASON.EXPOSED_SENSITIVE_HEADER: return 'CORS 暴露敏感响应头';
    case REASON.PRIVATE_NETWORK: return '允许私有网络访问请求';
    default: return String(reason || '');
  }
}

module.exports = {
  REASON,
  evaluateCors,
  applyCorsGuard,
  describeReason,
  headerValues,
  setHeader,
};
