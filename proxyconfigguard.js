'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'empty',
  INVALID_MODE: 'invalid-mode',
  INSECURE_PAC: 'insecure-pac',
  PAC_FILE: 'pac-file-url',
  USERINFO: 'url-userinfo',
  BAD_SCHEME: 'bad-scheme',
  BAD_HOST: 'bad-host',
  BAD_PORT: 'bad-port',
  BAD_BYPASS: 'bad-bypass',
};

const MODES = new Set(['direct', 'system', 'fixed_servers', 'pac_script']);
const SCHEMES = new Set(['http', 'https', 'socks4', 'socks5']);
const HOST_PATTERN = /^[a-z0-9.-]{1,253}$/i;

function parseHostPort(value) {
  if (typeof value !== 'string' || !value) return null;
  const text = value.trim();
  const match = /^([^:]+):(\d{1,5})$/.exec(text);
  if (!match) return null;
  const host = match[1];
  const port = Number(match[2]);
  if (!HOST_PATTERN.test(host)) return null;
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host, port };
}

function inspectPacScript(pacScript) {
  if (!pacScript || typeof pacScript !== 'object') return { ok: false, reason: REASON.INSECURE_PAC };
  const url = typeof pacScript.url === 'string' ? pacScript.url.trim() : '';
  if (!url) return { ok: false, reason: REASON.INSECURE_PAC };
  if (url.toLowerCase().startsWith('file:')) return { ok: false, reason: REASON.PAC_FILE };
  let parsed;
  try {
    parsed = new URL(url);
  } catch (err) {
    return { ok: false, reason: REASON.INSECURE_PAC };
  }
  if (parsed.protocol !== 'https:') return { ok: false, reason: REASON.INSECURE_PAC };
  if (parsed.username || parsed.password) return { ok: false, reason: REASON.USERINFO };
  return { ok: true, reason: REASON.OK };
}

function inspectBypassEntry(entry) {
  if (typeof entry !== 'string' || !entry.trim()) return false;
  const text = entry.trim();
  if (text === '<local>') return true;
  if (text.includes('://') || text.includes('@')) return false;
  const match = /^[^:]+:(\d{1,5})$/.exec(text);
  if (match) {
    const port = Number(match[1]);
    return port >= 1 && port <= 65535;
  }
  return HOST_PATTERN.test(text) || /^[^.]+\.(?:[a-z0-9-]+\.)*[a-z0-9-]+$/i.test(text);
}

function inspectProxyConfig(config) {
  if (!config || typeof config !== 'object') return { ok: false, reason: REASON.EMPTY, sanitized: null };
  if (!MODES.has(config.mode)) return { ok: false, reason: REASON.INVALID_MODE, sanitized: null };
  if (config.mode === 'pac_script') {
    const pac = inspectPacScript(config.pacScript);
    if (!pac.ok) return { ok: false, reason: pac.reason, sanitized: null };
    return { ok: true, reason: REASON.OK, sanitized: { mode: 'pac_script', pacScript: { url: config.pacScript.url.trim(), mandatory: true } } };
  }
  if (config.mode === 'fixed_servers') {
    const rules = config.rules;
    if (!rules || typeof rules !== 'object') return { ok: false, reason: REASON.EMPTY, sanitized: null };
    const scheme = rules.scheme || 'http';
    if (!SCHEMES.has(scheme)) return { ok: false, reason: REASON.BAD_SCHEME, sanitized: null };
    const hostPort = parseHostPort(rules.host ? rules.host + ':' + rules.port : '');
    if (!hostPort) return { ok: false, reason: REASON.BAD_HOST, sanitized: null };
    const bypassList = Array.isArray(rules.bypassList) ? rules.bypassList : [];
    for (const entry of bypassList) {
      if (!inspectBypassEntry(entry)) return { ok: false, reason: REASON.BAD_BYPASS, sanitized: null };
    }
    return {
      ok: true,
      reason: REASON.OK,
      sanitized: { mode: 'fixed_servers', rules: { scheme, host: hostPort.host, port: hostPort.port, bypassList } },
    };
  }
  return { ok: true, reason: REASON.OK, sanitized: { mode: config.mode } };
}

function applyProxyConfigGuard(config) {
  const result = inspectProxyConfig(config);
  return { changed: !result.ok, reason: result.reason, sanitized: result.sanitized };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.EMPTY:
      return '代理配置为空';
    case REASON.INVALID_MODE:
      return '代理模式非法';
    case REASON.INSECURE_PAC:
      return 'PAC 脚本地址不是 HTTPS';
    case REASON.PAC_FILE:
      return 'PAC 脚本指向本地文件';
    case REASON.USERINFO:
      return '代理地址内嵌账号密码';
    case REASON.BAD_SCHEME:
      return '代理协议不受支持';
    case REASON.BAD_HOST:
      return '代理主机或端口非法';
    case REASON.BAD_BYPASS:
      return '代理绕过列表包含非法条目';
    default:
      return '代理配置合法';
  }
}

module.exports = {
  REASON,
  MODES,
  SCHEMES,
  inspectProxyConfig,
  applyProxyConfigGuard,
  describeReason,
};
