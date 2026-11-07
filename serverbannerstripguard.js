'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BANNER_LEAK: 'banner-leak',
  PROXY_LEAK: 'proxy-leak',
  MALFORMED: 'malformed',
  SERVER_SANITIZED: 'server-sanitized',
};

const STACK_HEADERS = [
  'x-powered-by',
  'x-aspnet-version',
  'x-aspnetmvc-version',
  'x-generator',
  'x-drupal-cache',
  'x-drupal-dynamic-cache',
  'x-runtime',
  'x-version',
  'x-debug-token',
  'x-debug-token-link',
  'x-served-by',
  'x-backend-server',
  'x-cache',
  'x-cache-lookup',
  'x-varnish',
  'x-node',
  'x-php-version',
];

const PROXY_HEADERS = ['via', 'x-forwarded-server', 'x-real-ip', 'x-origin-server'];

const MAX_SERVER_LENGTH = 128;

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function firstValue(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return '';
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' ? value : '';
}

function cleanServerBanner(value) {
  if (typeof value !== 'string') return '';
  const trimmed = value.trim();
  if (!trimmed) return '';
  if (trimmed.length > MAX_SERVER_LENGTH) return '';
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) return '';
  const product = trimmed.split(/[\s(/]/)[0];
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(product)) return '';
  return product;
}

function collectBanners(headers) {
  const findings = [];
  const removed = [];
  let serverValue = null;
  let normalized = false;
  for (const name of STACK_HEADERS) {
    const key = headerKey(headers, name);
    if (!key) continue;
    findings.push({ header: name, reason: REASON.BANNER_LEAK });
    removed.push(key);
  }
  const serverKey = headerKey(headers, 'server');
  if (serverKey) {
    const cleaned = cleanServerBanner(firstValue(headers, 'server'));
    if (!cleaned) {
      findings.push({ header: 'server', reason: REASON.MALFORMED });
      removed.push(serverKey);
    } else {
      const raw = firstValue(headers, 'server').trim();
      serverValue = { key: serverKey, value: cleaned };
      const rawValues = headers[serverKey];
      if (raw !== cleaned) normalized = true;
      if (Array.isArray(rawValues) && rawValues.length > 1) normalized = true;
    }
  }
  for (const name of PROXY_HEADERS) {
    const key = headerKey(headers, name);
    if (!key) continue;
    findings.push({ header: name, reason: REASON.PROXY_LEAK });
    removed.push(key);
  }
  return { findings, removed, serverValue, normalized };
}

function reasonOf(findings) {
  if (findings.some((item) => item.reason === REASON.PROXY_LEAK)) return REASON.PROXY_LEAK;
  if (findings.some((item) => item.reason === REASON.BANNER_LEAK)) return REASON.BANNER_LEAK;
  return REASON.MALFORMED;
}

function inspectServerBanners(headers) {
  const { findings, serverValue, normalized } = collectBanners(headers);
  if (!findings.length && !normalized) {
    return { changed: false, reason: REASON.MISSING, findings };
  }
  const reason = findings.length ? reasonOf(findings) : REASON.SERVER_SANITIZED;
  return { changed: true, reason, findings, serverValue };
}

function applyServerBannerStripGuard(headers) {
  const { findings, removed, serverValue, normalized } = collectBanners(headers);
  for (const key of removed) {
    delete headers[key];
  }
  if (serverValue) {
    headers[serverValue.key] = [serverValue.value];
  }
  if (!findings.length && !normalized) {
    return { changed: false, reason: REASON.MISSING, findings };
  }
  const reason = findings.length ? reasonOf(findings) : REASON.SERVER_SANITIZED;
  return { changed: true, reason, findings };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.BANNER_LEAK:
      return '响应头泄露技术栈指纹';
    case REASON.PROXY_LEAK:
      return '响应头泄露代理/内网拓扑';
    case REASON.MALFORMED:
      return 'Server 头格式非法已清空';
    case REASON.SERVER_SANITIZED:
      return 'Server 头版本号已剥离';
    case REASON.MISSING:
      return '未发现技术栈指纹头';
    default:
      return '响应头已脱敏';
  }
}

module.exports = {
  REASON,
  STACK_HEADERS,
  PROXY_HEADERS,
  MAX_SERVER_LENGTH,
  cleanServerBanner,
  inspectServerBanners,
  applyServerBannerStripGuard,
  describeReason,
};
