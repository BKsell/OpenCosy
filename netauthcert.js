const KNOWN_AUTH_SCHEMES = new Set(['basic', 'digest', 'ntlm', 'negotiate']);

// 弹框限流：同一认证主体在滑动窗口内最多弹多少次，超限后进入冷却。
// 数值故意偏保守——正常用户极少在一分钟内对同一台主机连续 401 五次。
const DEFAULT_MAX_PROMPTS_IN_WINDOW = 5;
const DEFAULT_PROMPT_WINDOW_MS = 60 * 1000;
const DEFAULT_PROMPT_COOLDOWN_MS = 5 * 60 * 1000;

// 一次认证弹框等待用户的最长时间。超时自动取消，避免悬挂的回调卡住请求，
// 也避免攻击者用一堆永不交互的 401 堆积待处理项。
const AUTH_PROMPT_TIMEOUT_MS = 60 * 1000;

// 待处理认证请求的总量上限（跨所有主机），防止内存被无限堆积。
const MAX_PENDING_PROMPTS = 32;

// 入站字符串长度上限，超长一律截断/拒绝，防止异常输入撑爆日志与 IPC。
const MAX_REALM_CHARS = 300;
const MAX_HOST_CHARS = 255;
const MAX_USERNAME_CHARS = 512;
const MAX_PASSWORD_CHARS = 4096;

function clampText(value, max) {
  if (typeof value !== 'string') return '';
  const cleaned = value.replace(/[\x00-\x1f\x7f]/g, ' ').trim();
  return cleaned.length > max ? cleaned.slice(0, max) : cleaned;
}

function lowerTrim(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

// parseHttpUrl 只接受 http/https，其它协议（file/ftp/javascript/...）返回 null。
function parseHttpUrl(raw) {
  if (typeof raw !== 'string' || raw === '') return null;
  let u;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  return u;
}

// authHostKey 是限流 / 记忆的主体键：scheme + host(:port)。不带路径，避免同一
// 主机换个 URL 就绕过限流；显式端口参与键，区分同一主机上的不同服务。
function authHostKey(rawUrl) {
  const u = parseHttpUrl(rawUrl);
  if (!u) return '';
  let host = u.hostname.toLowerCase();
  if (host.length > MAX_HOST_CHARS) host = host.slice(0, MAX_HOST_CHARS);
  if (u.port) return `${u.protocol}//${host}:${u.port}`;
  return `${u.protocol}//${host}`;
}

function normalizeScheme(authInfo) {
  return lowerTrim(authInfo && authInfo.scheme);
}

// classifyServerAuth 判定一次“服务器 401”该如何处理。
// 返回 { decision:'prompt'|'cancel', reason, key, scheme, realm, host }。
function classifyServerAuth({ url, isMainFrame, authInfo } = {}) {
  const u = parseHttpUrl(url);
  const key = authHostKey(url);
  const scheme = normalizeScheme(authInfo);
  const realm = clampText(authInfo && authInfo.realm, MAX_REALM_CHARS);
  const base = { key, scheme, realm, host: u ? u.hostname : '' };

  if (!u || !key) return { ...base, decision: 'cancel', reason: 'non-http-url' };
  // 子框架（iframe / 跨源媒体）的 401 静默失败，这是凭据探测的主要入口。
  if (isMainFrame !== true) {
    return { ...base, decision: 'cancel', reason: 'subframe-credential-probe' };
  }
  if (!KNOWN_AUTH_SCHEMES.has(scheme)) {
    return { ...base, decision: 'cancel', reason: 'unknown-auth-scheme' };
  }
  return { ...base, decision: 'prompt', reason: 'main-frame-401' };
}

// classifyProxyAuth 判定一次“代理 407”。代理认证同样限流，但没有主/子框架之分；
// 只认已知方案，且 key 以 proxy: 前缀与服务器认证区分。
function classifyProxyAuth({ url, authInfo } = {}) {
  const scheme = normalizeScheme(authInfo);
  const u = parseHttpUrl(url);
  const proxyHost = clampText(authInfo && authInfo.host, MAX_HOST_CHARS);
  const proxyPort = Number(authInfo && authInfo.port);
  let key = 'proxy:';
  if (proxyHost) {
    key += Number.isInteger(proxyPort) && proxyPort > 0 ? `${proxyHost}:${proxyPort}` : proxyHost;
  } else if (u) {
    key += 'session';
  } else {
    key += 'unknown';
  }
  const realm = clampText(authInfo && authInfo.realm, MAX_REALM_CHARS);
  if (!KNOWN_AUTH_SCHEMES.has(scheme)) {
    return { decision: 'cancel', reason: 'unknown-auth-scheme', key, scheme, realm, host: proxyHost };
  }
  return { decision: 'prompt', reason: 'proxy-407', key, scheme, realm, host: proxyHost };
}

// AuthPromptRateLimiter 是按 key 的滑动窗口限流器，并在触发上限后给该主体一段
// 冷却期（冷却期内直接拒绝，不再计数）。时间由调用方注入，便于单测。
class AuthPromptRateLimiter {
  constructor({
    max = DEFAULT_MAX_PROMPTS_IN_WINDOW,
    windowMs = DEFAULT_PROMPT_WINDOW_MS,
    cooldownMs = DEFAULT_PROMPT_COOLDOWN_MS,
  } = {}) {
    this.max = max;
    this.windowMs = windowMs;
    this.cooldownMs = cooldownMs;
    this.hits = new Map();   // key -> number[] 时间戳
    this.coolingUntil = new Map(); // key -> 冷却结束时间戳
  }

  // 返回 { allow, reason }。allow=false 时 reason 为 'cooldown' 或 'rate-limited'。
  request(key, now) {
    if (typeof key !== 'string' || key === '') return { allow: false, reason: 'bad-key' };
    const t = Number.isFinite(now) ? now : Date.now();

    const until = this.coolingUntil.get(key) || 0;
    if (t < until) return { allow: false, reason: 'cooldown' };
    if (t >= until && until !== 0) this.coolingUntil.delete(key);

    const cutoff = t - this.windowMs;
    const stamps = (this.hits.get(key) || []).filter(ts => ts > cutoff);
    if (stamps.length >= this.max) {
      this.coolingUntil.set(key, t + this.cooldownMs);
      this.hits.set(key, stamps);
      return { allow: false, reason: 'rate-limited' };
    }
    stamps.push(t);
    this.hits.set(key, stamps);
    return { allow: true, reason: 'ok' };
  }

  // 用户成功完成一次认证后调用：清掉计数与冷却，避免合法输入被历史轰炸拖累。
  reset(key) {
    this.hits.delete(key);
    this.coolingUntil.delete(key);
  }

  // 仅供测试 / 面板观察，不参与安全决策。
  size() {
    return this.hits.size;
  }
}

// normalizeCertFingerprint 统一 Electron 客户端证书指纹。
// Electron 给出的 certificate.fingerprint 形如 "SHA256:AB:CD:.."，冒号大小写
// 不一。这里去掉冒号并小写，得到稳定的十六进制，便于和“记住的选择”比较。

module.exports = {
  KNOWN_AUTH_SCHEMES,
  DEFAULT_MAX_PROMPTS_IN_WINDOW,
  DEFAULT_PROMPT_WINDOW_MS,
  DEFAULT_PROMPT_COOLDOWN_MS,
  AUTH_PROMPT_TIMEOUT_MS,
  MAX_PENDING_PROMPTS,
  MAX_REALM_CHARS,
  MAX_HOST_CHARS,
  MAX_USERNAME_CHARS,
  MAX_PASSWORD_CHARS,
  clampText,
  lowerTrim,
  parseHttpUrl,
  authHostKey,
  normalizeScheme,
  classifyServerAuth,
  classifyProxyAuth,
  AuthPromptRateLimiter,
};
