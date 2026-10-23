'use strict';

// credentialguard.js —— Credential Management API（PasswordCredential / FederatedCredential /
// WebOTP）与自动填充凭据读写裁决内核。
//
// 与 webauthnguard 的分工：后者管公钥（passkey）；本模块管密码型/联合登录型凭据与短信 OTP。
//
// 威胁模型：
//   1. 钓鱼站静默 navigator.credentials.get({password:true}) 尝试自动填出已保存账号密码；
//   2. 恶意站 store() 把攻击者已知的账号密码写入浏览器密码库，实现凭据投毒；
//   3. FederatedCredential 被用来探测用户在第三方 IdP（Google/Facebook）的登录状态；
//   4. WebOTP（SMS Receiver）页面无手势、跨域 iframe 拦截短信验证码；
//   5. 非安全上下文、后台、被拦截来源读取/写入凭据；
//   6. mediation:'silent' 在后台持续探测登录态。
//
// 纯逻辑模块。

const CR_DENY = 'deny';
const CR_ALLOW = 'allow';

const CR_REASON = Object.freeze({
  INSECURE_CONTEXT: 'cr-insecure-context',
  BAD_ORIGIN: 'cr-bad-origin',
  BLOCKED_ORIGIN: 'cr-blocked-origin',
  BACKGROUND: 'cr-background',
  NO_GESTURE_GET: 'cr-get-requires-gesture',
  STORE_FORBIDDEN: 'cr-store-forbidden',
  FEDERATED_PROVIDER_NOT_ALLOWED: 'cr-federated-provider-not-allowed',
  SILENT_MEDIATION_FORBIDDEN: 'cr-silent-mediation-forbidden',
  WEBOTP_PERMISSION_DENIED: 'cr-webotp-permission-denied',
  GET_THROTTLED: 'cr-get-throttled',
  EMPTY_ID_FIELD: 'cr-empty-id-field',
  UNKNOWN_CREDENTIAL_KIND: 'cr-unknown-credential-kind',
});

const KIND = Object.freeze({ PASSWORD: 'password', FEDERATED: 'federated', OTP: 'otp' });

function defaultCredentialPolicy() {
  return {
    requireSecureContext: true,
    denyBackground: true,
    getRequireGesture: true,
    allowStorePassword: false, // 默认禁止网页把密码写进密码库
    allowFederated: true,
    allowedFederatedProviders: [], // 空=不限制 provider（仍受手势/上下文约束）
    allowSilentMediation: false,
    allowWebOtp: true,
    getMinIntervalMs: 2000,
  };
}

function originHost(origin) {
  if (typeof origin !== 'string') return '';
  const idx = origin.indexOf('://');
  if (idx <= 0) return '';
  const scheme = origin.slice(0, idx).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') return '';
  let rest = origin.slice(idx + 3);
  for (const ch of ['/', '?', '#', ':']) {
    const p = rest.indexOf(ch);
    if (p >= 0) rest = rest.slice(0, p);
  }
  return rest.toLowerCase();
}

function asLower(v) {
  return typeof v === 'string' ? v.toLowerCase() : '';
}

class CredentialGuard {
  constructor(policy) {
    this.policy = policy || defaultCredentialPolicy();
    this.lastGet = new Map();
  }

  _base(ctx) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { ok: false, reason: CR_REASON.BAD_ORIGIN };
    if (pol.requireSecureContext && ctx.isSecureContext !== true) {
      return { ok: false, reason: CR_REASON.INSECURE_CONTEXT };
    }
    const host = originHost(ctx.origin);
    if (!host) return { ok: false, reason: CR_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { ok: false, reason: CR_REASON.BLOCKED_ORIGIN };
    if (pol.denyBackground && ctx.isBackground === true) {
      return { ok: false, reason: CR_REASON.BACKGROUND };
    }
    return { ok: true, host, now: ctx.now || 0 };
  }

  // decideGet 裁决 navigator.credentials.get(query)。
  // query: {password, federated:{providers}, otp, mediation}
  decideGet(ctx, query) {
    const b = this._base(ctx);
    if (!b.ok) return { decision: CR_DENY, reason: b.reason };
    const pol = this.policy;

    const mediation = query && asLower(query.mediation);
    if (mediation === 'silent' && !pol.allowSilentMediation) {
      return { decision: CR_DENY, reason: CR_REASON.SILENT_MEDIATION_FORBIDDEN };
    }
    // silent 之外的主动读取要求手势。
    if (mediation !== 'silent' && pol.getRequireGesture && ctx.hasUserGesture !== true) {
      return { decision: CR_DENY, reason: CR_REASON.NO_GESTURE_GET };
    }
    if (this.lastGet.has(b.host) && b.now - this.lastGet.get(b.host) < pol.getMinIntervalMs) {
      return { decision: CR_DENY, reason: CR_REASON.GET_THROTTLED };
    }

    if (query && query.otp === true) {
      if (!pol.allowWebOtp) return { decision: CR_DENY, reason: CR_REASON.WEBOTP_PERMISSION_DENIED };
      // WebOTP 还要求顶层安全框架，调用方传入 isTopFrame=false 时拒绝。
      if (ctx.isTopFrame === false) return { decision: CR_DENY, reason: CR_REASON.WEBOTP_PERMISSION_DENIED };
    }
    if (query && query.federated) {
      if (!pol.allowFederated) return { decision: CR_DENY, reason: CR_REASON.FEDERATED_PROVIDER_NOT_ALLOWED };
      const providers = query.federated.providers || [];
      if (pol.allowedFederatedProviders.length) {
        for (const p of providers) {
          const host = originHost(p) || asLower(p);
          const ok = pol.allowedFederatedProviders.some((a) => host === a || host.endsWith('.' + a));
          if (!ok) return { decision: CR_DENY, reason: CR_REASON.FEDERATED_PROVIDER_NOT_ALLOWED, provider: p };
        }
      }
    }
    this.lastGet.set(b.host, b.now);
    const kinds = [];
    if (query && query.password === true) kinds.push(KIND.PASSWORD);
    if (query && query.federated) kinds.push(KIND.FEDERATED);
    if (query && query.otp === true) kinds.push(KIND.OTP);
    if (kinds.length === 0) return { decision: CR_DENY, reason: CR_REASON.UNKNOWN_CREDENTIAL_KIND };
    return { decision: CR_ALLOW, reason: '', kinds };
  }

  // decideStore 裁决 navigator.credentials.store(credential)（凭据投毒防护）。
  decideStore(ctx, credential) {
    const b = this._base(ctx);
    if (!b.ok) return { decision: CR_DENY, reason: b.reason };
    const kind = credential && asLower(credential.kind);
    if (kind === 'password' && !this.policy.allowStorePassword) {
      return { decision: CR_DENY, reason: CR_REASON.STORE_FORBIDDEN };
    }
    if (kind === 'password') {
      const id = credential && typeof credential.id === 'string' ? credential.id : '';
      if (id.trim() === '') return { decision: CR_DENY, reason: CR_REASON.EMPTY_ID_FIELD };
    }
    if (kind === 'federated' && !this.policy.allowFederated) {
      return { decision: CR_DENY, reason: CR_REASON.FEDERATED_PROVIDER_NOT_ALLOWED };
    }
    if (kind !== 'password' && kind !== 'federated' && kind !== 'otp') {
      return { decision: CR_DENY, reason: CR_REASON.UNKNOWN_CREDENTIAL_KIND };
    }
    return { decision: CR_ALLOW, reason: '', kind };
  }
}

module.exports = {
  CR_ALLOW, CR_DENY, CR_REASON, KIND,
  defaultCredentialPolicy, originHost, CredentialGuard,
};
