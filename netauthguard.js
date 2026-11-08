
const { KNOWN_AUTH_SCHEMES, DEFAULT_MAX_PROMPTS_IN_WINDOW, DEFAULT_PROMPT_WINDOW_MS, DEFAULT_PROMPT_COOLDOWN_MS, AUTH_PROMPT_TIMEOUT_MS, MAX_PENDING_PROMPTS, MAX_REALM_CHARS, MAX_HOST_CHARS, MAX_USERNAME_CHARS, MAX_PASSWORD_CHARS, clampText, lowerTrim, parseHttpUrl, authHostKey, normalizeScheme, classifyServerAuth, classifyProxyAuth, AuthPromptRateLimiter } = require('./netauthcert');

const { MAX_ISSUER_CHARS, MAX_REMEMBERED_CERT_HOSTS, MAX_SERIAL_CHARS, MAX_SUBJECT_CHARS, RememberedClientCertStore, certHostKey, chooseClientCertificate, describeAuthScheme, normalizeCertFingerprint, sanitizeAuthSubmit, sanitizeCertChoiceRecord, summarizeClientCert } = require('./netauthguard_prompt');
const MAX_STATS_KEYS = 200;

class AuthPromptStats {
  constructor() {
    this.total = 0;                 // 进入认证流程的事件总数
    this.prompted = 0;             // 真正向用户弹框的次数
    this.cancelled = 0;            // 被策略静默取消的次数
    this.succeeded = 0;            // 用户成功提交并通过的次数
    this.rateLimited = 0;          // 触发限流/冷却的次数
    this.certSuppressed = 0;       // 客户端证书被默认不发送的次数
    this.byReason = new Map();     // reason -> count
    this.byScheme = new Map();     // scheme -> count
  }

  bump(mapRef, key) {
    const k = String(key || 'unknown');
    if (mapRef.size >= MAX_STATS_KEYS && !mapRef.has(k)) return;
    mapRef.set(k, (mapRef.get(k) || 0) + 1);
  }

  recordEvent({ decision, reason, scheme } = {}) {
    this.total++;
    if (scheme) this.bump(this.byScheme, lowerTrim(scheme));
    if (reason) this.bump(this.byReason, reason);
    if (decision === 'prompt') this.prompted++;
    if (decision === 'cancel') this.cancelled++;
  }

  recordRateLimited() {
    this.rateLimited++;
  }

  recordSuccess() {
    this.succeeded++;
  }

  recordCertSuppressed() {
    this.certSuppressed++;
  }

  toJSON() {
    return {
      total: this.total,
      prompted: this.prompted,
      cancelled: this.cancelled,
      succeeded: this.succeeded,
      rateLimited: this.rateLimited,
      certSuppressed: this.certSuppressed,
      byReason: Object.fromEntries(this.byReason),
      byScheme: Object.fromEntries(this.byScheme),
    };
  }
}

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
  MAX_REMEMBERED_CERT_HOSTS,
  MAX_ISSUER_CHARS,
  MAX_SUBJECT_CHARS,
  MAX_SERIAL_CHARS,
  MAX_STATS_KEYS,
  parseHttpUrl,
  authHostKey,
  normalizeScheme,
  classifyServerAuth,
  classifyProxyAuth,
  AuthPromptRateLimiter,
  normalizeCertFingerprint,
  chooseClientCertificate,
  sanitizeAuthSubmit,
  describeAuthScheme,
  certHostKey,
  summarizeClientCert,
  sanitizeCertChoiceRecord,
  RememberedClientCertStore,
  AuthPromptStats,
};
