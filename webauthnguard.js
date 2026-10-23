'use strict';

// webauthnguard.js —— WebAuthn navigator.credentials.create/get（公钥认证）裁决内核。
//
// 威胁模型：
//   1. 钓鱼站在非安全上下文/仿冒域发起 navigator.credentials.get，用条件式自动补全
//      （mediation:'conditional'）静默探测已保存 passkey 并尝试登录；
//   2. create() 被滥用注册攻击者控制的设备公钥（无用户验证、无手势），实现账户持久化；
//   3. rp.id 放宽到可注册后缀（example.com.cn 之于 example.com 的后缀误配）、
//      rp.id 与当前域不匹配；
//   4. userVerification 被设为 discouraged 绕过 PIN/生物识别；
//   5. attestation:'direct' 强制收集设备证明（可关联硬件指纹）；
//   6. 超时过长挂起授权 UI；excludeCredentials 缺失导致重复注册；
//   7. transports 含内部/非预期通道，或 allowCredentials 空数组配合 conditional 探测。
//
// 纯逻辑；域名后缀关系用字符比较，不用正则。

const WA_DENY = 'deny';
const WA_PROMPT = 'prompt';

const WA_REASON = Object.freeze({
  INSECURE_CONTEXT: 'wa-insecure-context',
  BAD_ORIGIN: 'wa-bad-origin',
  BLOCKED_ORIGIN: 'wa-blocked-origin',
  RP_ID_MISMATCH: 'wa-rp-id-mismatch',
  RP_ID_NOT_REGISTRABLE_SUFFIX: 'wa-rp-id-not-registrable-suffix',
  UV_DISCOURAGED: 'wa-user-verification-discouraged',
  ATTESTATION_DIRECT_FORBIDDEN: 'wa-attestation-direct-forbidden',
  TIMEOUT_TOO_LONG: 'wa-timeout-too-long',
  TIMEOUT_TOO_SHORT: 'wa-timeout-too-short',
  CONDITIONAL_WITHOUT_ALLOWED: 'wa-conditional-not-allowed',
  EMPTY_ALLOW_CREDENTIALS: 'wa-empty-allow-credentials',
  MISSING_EXCLUDE_CREDENTIALS: 'wa-missing-exclude-credentials',
  REQUEST_THROTTLED: 'wa-request-throttled',
  UNKNOWN_OPERATION: 'wa-unknown-operation',
});

function defaultWebauthnPolicy() {
  return {
    requireSecureContext: true,
    requireUserVerification: true, // 强制 preferred/required
    allowDirectAttestation: false,
    minTimeoutMs: 10000,
    maxTimeoutMs: 120000,
    allowConditionalMediation: true,
    requestMinIntervalMs: 1500,
    requireExcludeCredentialsOnCreate: false,
  };
}

function originHost(origin) {
  if (typeof origin !== 'string') return '';
  const idx = origin.indexOf('://');
  if (idx <= 0) return '';
  const scheme = origin.slice(0, idx).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') return '';
  let rest = origin.slice(idx + 3);
  const cut = ['/', '?', '#', ':'];
  let end = rest.length;
  for (const ch of cut) {
    const p = rest.indexOf(ch);
    if (p >= 0 && p < end) end = p;
  }
  return rest.slice(0, end).toLowerCase();
}

// registrableSuffixMatch 判断 host 是否“等于或为 rpId 的子域”，且边界必须落在点上，
// 防止 example.com 误匹配 example.com.cn / notexample.com。
function hostMatchesRpId(host, rpId) {
  if (typeof host !== 'string' || typeof rpId !== 'string' || rpId === '') return false;
  const h = host.toLowerCase();
  const r = rpId.toLowerCase();
  if (h === r) return true;
  if (h.length > r.length && h.endsWith('.' + r)) return true;
  return false;
}

function isIpLike(host) {
  const p = host.split('.');
  if (p.length !== 4) return false;
  for (const seg of p) {
    if (seg.length === 0) return false;
    for (const ch of seg) {
      if (!(ch >= '0' && ch <= '9')) return false;
    }
  }
  return true;
}

function asLower(v) {
  return typeof v === 'string' ? v.toLowerCase() : '';
}

class WebauthnGuard {
  constructor(policy) {
    this.policy = policy || defaultWebauthnPolicy();
    this.lastRequest = new Map();
  }

  _base(ctx) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { ok: false, reason: WA_REASON.BAD_ORIGIN };
    if (pol.requireSecureContext && ctx.isSecureContext !== true) {
      return { ok: false, reason: WA_REASON.INSECURE_CONTEXT };
    }
    const host = originHost(ctx.origin);
    if (!host) return { ok: false, reason: WA_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { ok: false, reason: WA_REASON.BLOCKED_ORIGIN };
    const now = ctx.now || 0;
    if (this.lastRequest.has(host) && now - this.lastRequest.get(host) < pol.requestMinIntervalMs) {
      return { ok: false, reason: WA_REASON.REQUEST_THROTTLED };
    }
    return { ok: true, host, now };
  }

  _checkCommonOptions(opts, problems) {
    const pol = this.policy;
    const timeout = opts && typeof opts.timeout === 'number' ? opts.timeout : 0;
    if (timeout > pol.maxTimeoutMs) problems.push(WA_REASON.TIMEOUT_TOO_LONG);
    if (timeout > 0 && timeout < pol.minTimeoutMs) problems.push(WA_REASON.TIMEOUT_TOO_SHORT);
    if (pol.requireUserVerification && opts && asLower(opts.userVerification) === 'discouraged') {
      problems.push(WA_REASON.UV_DISCOURAGED);
    }
  }

  // decideCreate 裁决 navigator.credentials.create({publicKey})。
  decideCreate(ctx, options) {
    const b = this._base(ctx);
    if (!b.ok) return { decision: WA_DENY, reason: b.reason };
    const pk = options && options.publicKey ? options.publicKey : null;
    if (!pk) return { decision: WA_DENY, reason: WA_REASON.RP_ID_MISMATCH };
    const problems = [];
    this._checkCommonOptions(pk, problems);

    const rpId = pk.rp && typeof pk.rp.id === 'string' ? pk.rp.id : '';
    if (rpId === '' || !hostMatchesRpId(b.host, rpId)) {
      problems.push(WA_REASON.RP_ID_MISMATCH);
    } else if (isIpLike(rpId)) {
      problems.push(WA_REASON.RP_ID_NOT_REGISTRABLE_SUFFIX);
    }
    if (asLower(pk.attestation) === 'direct' && !this.policy.allowDirectAttestation) {
      problems.push(WA_REASON.ATTESTATION_DIRECT_FORBIDDEN);
    }
    if (this.policy.requireExcludeCredentialsOnCreate) {
      const ex = pk.excludeCredentials;
      if (!Array.isArray(ex) || ex.length === 0) problems.push(WA_REASON.MISSING_EXCLUDE_CREDENTIALS);
    }
    if (problems.length) return { decision: WA_DENY, reason: problems[0], allReasons: problems };
    this.lastRequest.set(b.host, b.now);
    return { decision: WA_PROMPT, reason: '', operation: 'create' };
  }

  // decideGet 裁决 navigator.credentials.get({publicKey})。
  decideGet(ctx, options) {
    const b = this._base(ctx);
    if (!b.ok) return { decision: WA_DENY, reason: b.reason };
    const pk = options && options.publicKey ? options.publicKey : null;
    if (!pk) return { decision: WA_DENY, reason: WA_REASON.RP_ID_MISMATCH };
    const problems = [];
    this._checkCommonOptions(pk, problems);

    const rpId = typeof pk.rpId === 'string' ? pk.rpId : '';
    if (rpId === '' || !hostMatchesRpId(b.host, rpId)) {
      problems.push(WA_REASON.RP_ID_MISMATCH);
    }
    const allow = pk.allowCredentials;
    if (Array.isArray(allow) && allow.length === 0) {
      problems.push(WA_REASON.EMPTY_ALLOW_CREDENTIALS);
    }
    const mediation = options && asLower(options.mediation);
    if (mediation === 'conditional' && !this.policy.allowConditionalMediation) {
      problems.push(WA_REASON.CONDITIONAL_WITHOUT_ALLOWED);
    }
    if (problems.length) return { decision: WA_DENY, reason: problems[0], allReasons: problems };
    this.lastRequest.set(b.host, b.now);
    return { decision: WA_PROMPT, reason: '', operation: 'get' };
  }
}

module.exports = {
  WA_DENY, WA_PROMPT, WA_REASON,
  defaultWebauthnPolicy, originHost, hostMatchesRpId, isIpLike, WebauthnGuard,
};
