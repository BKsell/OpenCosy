'use strict';

// fedcmguard.js —— Federated Credential Management（navigator.credentials.get({identity}))
// 联合登录（FedCM）账号选择与 IdP/RP 配对裁决内核。
//
// 威胁模型：
//   1. RP（依赖方）页面通过 identity.providers 指向攻击者控制的 configURL，把登录流量导向
//      恶意 IdP，再用 loginHint 预填受害者账号做登录 CSRF / 账号关联（账号拼接攻击）；
//   2. configURL/clientId/nonce 脏值、非 https、跨站 config 与声明的 IdP 域不一致；
//   3. 同一调用塞多个 IdP provider 做"哪个有会话"探测（IdP 追踪）；
//   4. auto:reauthn / auto:new 用户无感知续登，或 context 用 use/continue/signup 绕过提示；
//   5. 后台/无手势/不可见页面弹账号选择器，构成点击劫持。
//
// 纯逻辑。

const FC_ALLOW = 'allow';
const FC_DENY = 'deny';

const FC_REASON = Object.freeze({
  BAD_CONTEXT: 'fc-bad-context',
  NO_GESTURE: 'fc-no-gesture',
  NOT_VISIBLE: 'fc-not-visible',
  INSECURE_ORIGIN: 'fc-insecure-origin',
  NO_PROVIDERS: 'fc-no-providers',
  TOO_MANY_PROVIDERS: 'fc-too-many-providers',
  BAD_CONFIG_URL: 'fc-bad-config-url',
  CONFIG_HOST_MISMATCH: 'fc-config-host-mismatch',
  BAD_CLIENT_ID: 'fc-bad-client-id',
  BAD_LOGIN_HINT: 'fc-bad-login-hint',
  HINT_CROSS_USER: 'fc-hint-cross-user',
  NONCE_BAD_OR_REUSED: 'fc-nonce-bad-or-reused',
  AUTO_REAUTHN_DISABLED: 'fc-auto-reauthn-disabled',
  UNKNOWN_MODE: 'fc-unknown-mode',
});

const FC_VALID_MODES = Object.freeze(['button', 'widget', 'active']);

function defaultFedCMPolicy() {
  return {
    requireHttps: true,
    requireUserGesture: true,
    requireVisible: true,
    maxProvidersPerCall: 1,
    trustedIdpHosts: [], // 空=仅校验 configURL https 与自洽
    requireClientId: true,
    maxClientIdLength: 256,
    maxLoginHintLength: 128,
    allowLoginHint: true,
    requireFreshNonce: false,
    allowAutoReauthn: false,
  };
}

function schemeOf(url) {
  if (typeof url !== 'string') return '';
  const c = url.indexOf(':');
  return c > 0 ? url.slice(0, c).toLowerCase() : '';
}
function hostOf(url) {
  if (typeof url !== 'string') return '';
  const i = url.indexOf('://');
  if (i <= 0) return '';
  let rest = url.slice(i + 3);
  for (const ch of ['/', '?', '#']) {
    const p = rest.indexOf(ch);
    if (p >= 0) rest = rest.slice(0, p);
  }
  if (rest.indexOf('@') >= 0) rest = rest.slice(rest.lastIndexOf('@') + 1);
  if (rest.indexOf('[') === 0) {
    const rb = rest.indexOf(']');
    rest = rb > 0 ? rest.slice(1, rb) : rest;
  } else {
    const pc = rest.lastIndexOf(':');
    if (pc > 0) rest = rest.slice(0, pc);
  }
  return rest.toLowerCase();
}
function regSite(host) {
  const labels = host.split('.');
  return labels.length >= 2 ? labels.slice(-2).join('.') : host;
}
function hasControlChar(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return true;
  }
  return false;
}

class FedCMGuard {
  constructor(policy) {
    this.policy = policy || defaultFedCMPolicy();
    this.seenNonces = new Set();
  }

  // decideGet 裁决 credentials.get({identity:{providers, context, nonce}})。
  decideGet(ctx, identity) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return { decision: FC_DENY, reason: FC_REASON.BAD_CONTEXT };
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return { decision: FC_DENY, reason: FC_REASON.INSECURE_ORIGIN };
    if (pol.requireUserGesture && ctx.userGesture !== true) return { decision: FC_DENY, reason: FC_REASON.NO_GESTURE };
    if (pol.requireVisible && ctx.visible === false) return { decision: FC_DENY, reason: FC_REASON.NOT_VISIBLE };

    const providers = identity && Array.isArray(identity.providers) ? identity.providers : null;
    if (!providers || providers.length === 0) return { decision: FC_DENY, reason: FC_REASON.NO_PROVIDERS };
    if (providers.length > pol.maxProvidersPerCall) return { decision: FC_DENY, reason: FC_REASON.TOO_MANY_PROVIDERS };

    // mode：widget/button/active；FedCM 还可能带 auto 提示（automaticSilentPresent 等）。
    const mode = identity.mode || 'widget';
    if (FC_VALID_MODES.indexOf(mode) < 0) return { decision: FC_DENY, reason: FC_REASON.UNKNOWN_MODE, mode };
    if (identity.auto === true || identity.autoSelected === true) {
      if (!pol.allowAutoReauthn) return { decision: FC_DENY, reason: FC_REASON.AUTO_REAUTHN_DISABLED };
    }

    if (pol.requireFreshNonce && typeof identity.nonce === 'string') {
      const n = identity.nonce;
      if (n.length < 16 || n.length > 256 || hasControlChar(n) || this.seenNonces.has(n)) {
        return { decision: FC_DENY, reason: FC_REASON.NONCE_BAD_OR_REUSED };
      }
      this.seenNonces.add(n);
    }

    for (let i = 0; i < providers.length; i++) {
      const pv = providers[i];
      const cfg = pv.configURL;
      if (typeof cfg !== 'string' || schemeOf(cfg) !== 'https') {
        return { decision: FC_DENY, reason: FC_REASON.BAD_CONFIG_URL, index: i, configURL: cfg };
      }
      const host = hostOf(cfg);
      // config 文件应位于其声明的 IdP 主机（/fedcm.json 等），不允许明显跨主机的代理。
      if (typeof pv.idpHost === 'string' && pv.idpHost) {
        const declared = hostOf(pv.idpHost.indexOf('://') >= 0 ? pv.idpHost : 'https://' + pv.idpHost);
        if (regSite(host) !== regSite(declared)) {
          return { decision: FC_DENY, reason: FC_REASON.CONFIG_HOST_MISMATCH, configHost: host, idpHost: declared };
        }
      }
      if (pol.trustedIdpHosts.length > 0 && pol.trustedIdpHosts.indexOf(regSite(host)) < 0) {
        return { decision: FC_DENY, reason: FC_REASON.CONFIG_HOST_MISMATCH, host };
      }
      if (pol.requireClientId) {
        const cid = pv.clientId;
        if (typeof cid !== 'string' || cid.length === 0 || cid.length > pol.maxClientIdLength || hasControlChar(cid)) {
          return { decision: FC_DENY, reason: FC_REASON.BAD_CLIENT_ID, index: i };
        }
      }
      if (typeof pv.loginHint === 'string' && pv.loginHint.length > 0) {
        if (!pol.allowLoginHint) return { decision: FC_DENY, reason: FC_REASON.HINT_CROSS_USER };
        const hint = pv.loginHint;
        if (hint.length > pol.maxLoginHintLength || hasControlChar(hint) || hint.indexOf('@') >= 0 && hint.indexOf(' ') >= 0) {
          return { decision: FC_DENY, reason: FC_REASON.BAD_LOGIN_HINT, hint };
        }
        // loginHint 与当前已登录用户不一致即账号拼接风险。
        if (typeof ctx.currentAccountHint === 'string' && ctx.currentAccountHint &&
            hint !== ctx.currentAccountHint) {
          return { decision: FC_DENY, reason: FC_REASON.HINT_CROSS_USER, hint };
        }
      }
    }
    return { decision: FC_ALLOW, reason: '' };
  }
}

module.exports = {
  FC_ALLOW, FC_DENY, FC_REASON, FC_VALID_MODES,
  defaultFedCMPolicy, schemeOf, hostOf, regSite, FedCMGuard,
};
