'use strict';

const net = require('net');

const ACTION = { ALLOW: 'allow', WARN: 'warn', BLOCK: 'block' };

const REASON = {
  OK: 'ok',
  BAD_SCHEME: 'bad-scheme',
  EMPTY_HOST: 'empty-host',
  USERINFO: 'userinfo',
  CONTROL_CHAR: 'control-char',
  TOO_LONG: 'too-long',
  INVALID_URL: 'invalid-url',
  PRIVATE_ADDRESS: 'private-address',
  LOCAL_HOST: 'local-host',
  RESTRICTED_PORT: 'restricted-port',
  PUNYCODE_HOST: 'punycode-host',
  INSECURE_SCHEME: 'insecure-scheme',
};

const MAX_URL_BYTES = 8192;
const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

const RESTRICTED_PORTS = new Set([
  1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79,
  87, 95, 101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137,
  139, 143, 161, 179, 389, 427, 445, 465, 512, 513, 514, 515, 526, 530, 531, 532,
  540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993, 995, 1080, 2049, 3659,
  4045, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668, 6669, 6697, 10080,
]);

const LOCAL_HOST_SUFFIXES = ['.local', '.localhost', '.internal', '.lan'];

function lower(value) {
  return String(value || '').toLowerCase();
}

function isPrivateIPv4(host) {
  const parts = host.split('.').map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return false;
  }
  const [a, b, c, d] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  return a === 255 && b === 255 && c === 255 && d === 255;
}

function isPrivateIPv6(host) {
  const normalized = lower(host).replace(/^\[|\]$/g, '');
  if (normalized === '::' || normalized === '::1') return true;
  if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) {
    return true;
  }
  return normalized.startsWith('fc') || normalized.startsWith('fd');
}

function isLocalHostName(host) {
  const name = lower(host).replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (name === 'localhost') return true;
  return LOCAL_HOST_SUFFIXES.some((suffix) => name.endsWith(suffix));
}

function isPrivateHost(host) {
  const bare = host.replace(/^\[|\]$/g, '');
  if (net.isIP(bare) === 4) return isPrivateIPv4(bare);
  if (net.isIP(bare) === 6) return isPrivateIPv6(bare);
  return false;
}

function hasUnsafeChar(rawUrl) {
  for (const ch of String(rawUrl || '')) {
    const code = ch.codePointAt(0);
    if (code <= 0x1f || code === 0x7f || code === 0x20) return true;
  }
  return false;
}

function evaluateDownloadUrl(rawUrl, options = {}) {
  const url = String(rawUrl || '');
  const base = {
    action: ACTION.ALLOW,
    reason: REASON.OK,
    url,
    protocol: '',
    host: '',
    port: 0,
    detail: '',
  };

  if (url.length > MAX_URL_BYTES) {
    return Object.assign(base, { action: ACTION.BLOCK, reason: REASON.TOO_LONG, detail: `URL 超过 ${MAX_URL_BYTES} 字节` });
  }
  if (hasUnsafeChar(url)) {
    return Object.assign(base, { action: ACTION.BLOCK, reason: REASON.CONTROL_CHAR, detail: 'URL 含空白或控制字符' });
  }

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return Object.assign(base, { action: ACTION.BLOCK, reason: REASON.INVALID_URL, detail: 'URL 无法解析' });
  }

  let host = '';
  try {
    host = parsed.hostname || '';
  } catch {
    host = '';
  }
  const protocol = lower(parsed.protocol);
  const port = parsed.port ? Number(parsed.port) : (protocol === 'https:' ? 443 : 80);
  Object.assign(base, { protocol, host, port });

  if (!ALLOWED_PROTOCOLS.has(protocol)) {
    return Object.assign(base, { action: ACTION.BLOCK, reason: REASON.BAD_SCHEME, detail: `协议 ${protocol || '(空)'} 不允许发起下载` });
  }
  if (!host) {
    return Object.assign(base, { action: ACTION.BLOCK, reason: REASON.EMPTY_HOST, detail: 'URL 缺少主机名' });
  }
  if (parsed.username || parsed.password) {
    return Object.assign(base, { action: ACTION.BLOCK, reason: REASON.USERINFO, detail: 'URL 内嵌账号密码' });
  }
  if (isPrivateHost(host)) {
    return Object.assign(base, { action: ACTION.BLOCK, reason: REASON.PRIVATE_ADDRESS, detail: `目标 ${host} 属于内网地址` });
  }
  if (isLocalHostName(host)) {
    return Object.assign(base, { action: ACTION.BLOCK, reason: REASON.LOCAL_HOST, detail: `目标 ${host} 属于本机域名` });
  }
  if (RESTRICTED_PORTS.has(port)) {
    return Object.assign(base, { action: ACTION.BLOCK, reason: REASON.RESTRICTED_PORT, detail: `端口 ${port} 属于浏览器受限端口` });
  }
  if (protocol === 'http:' && options.requireHttps === true) {
    return Object.assign(base, { action: ACTION.BLOCK, reason: REASON.INSECURE_SCHEME, detail: 'HTTPS-only 模式下拒绝明文下载' });
  }
  if (protocol === 'http:') {
    return Object.assign(base, { action: ACTION.WARN, reason: REASON.INSECURE_SCHEME, detail: '明文 HTTP 下载可能被中间人篡改' });
  }
  if (lower(host).includes('xn--')) {
    return Object.assign(base, { action: ACTION.WARN, reason: REASON.PUNYCODE_HOST, detail: '主机名使用 punycode，存在同形字仿冒风险' });
  }
  return base;
}

function describeDownloadUrl(decision) {
  if (!decision || decision.reason === REASON.OK) return '下载地址通过校验';
  return `${decision.reason}: ${decision.detail || ''}`.trim();
}

module.exports = {
  ACTION,
  REASON,
  MAX_URL_BYTES,
  RESTRICTED_PORTS,
  evaluateDownloadUrl,
  describeDownloadUrl,
  isPrivateHost,
  isLocalHostName,
};
