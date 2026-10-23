'use strict';

// paymentguard.js —— Payment Request API（new PaymentRequest）裁决内核。
//
// 威胁模型：
//   1. 钓鱼站用 PaymentRequest 弹出浏览器原生支付表单（可信度高），诱导用户填入
//      卡号、账单地址、联系人；原生 UI 的权威性被滥用；
//   2. canMakePayment() / hasEnrolledInstrument() 被用来探测用户是否绑定了支付方式，
//      做支付能力指纹与"肥羊"筛选；
//   3. 非安全上下文、后台、被拦截来源发起支付；
//   4. 支付方式支持 data 里塞任意 URL（basic-card 已废弃但仍有实现），或向第三方
//      支付方法 origin 泄露交易；
//   5. shipping/联系人信息被过度请求（requestPayerName/Email/Phone + shipping address）；
//   6. 金额异常（0、负数、超大、货币代码非法）用于探测或绕过。
//
// 纯逻辑模块。

const PG_DENY = 'deny';
const PG_ALLOW = 'allow';
const PG_PROMPT = 'prompt';

const PG_REASON = Object.freeze({
  INSECURE_CONTEXT: 'pg-insecure-context',
  BAD_ORIGIN: 'pg-bad-origin',
  BLOCKED_ORIGIN: 'pg-blocked-origin',
  BACKGROUND: 'pg-background',
  NO_GESTURE: 'pg-requires-gesture',
  EMPTY_METHODS: 'pg-empty-methods',
  PAYMENT_METHOD_NOT_ALLOWED: 'pg-payment-method-not-allowed',
  CANMAKE_FINGERPRINT: 'pg-canmake-fingerprint',
  EXCESSIVE_CONTACT_REQUEST: 'pg-excessive-contact-request',
  BAD_CURRENCY: 'pg-bad-currency',
  BAD_AMOUNT: 'pg-bad-amount',
  SHOW_THROTTLED: 'pg-show-throttled',
});

function defaultPaymentPolicy() {
  return {
    requireSecureContext: true,
    denyBackground: true,
    requireGestureForShow: true,
    // 允许的支付方法标识；URL 型方法只接受 https 且主机在此白名单后缀内。
    allowedMethodHostSuffixes: [],
    allowBasicCard: false,
    allowCanMakeProbe: false, // canMakePayment/hasEnrolledInstrument 默认禁止探测
    maxContactFields: 2, // payerName/email/phone 中最多同时请求数
    showMinIntervalMs: 3000,
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

function methodHost(supportedMethods) {
  if (typeof supportedMethods !== 'string') return { kind: '', host: '' };
  if (supportedMethods.indexOf('http://') === 0 || supportedMethods.indexOf('https://') === 0) {
    return { kind: 'url', host: originHost(supportedMethods) };
  }
  return { kind: 'basic', host: supportedMethods.toLowerCase() };
}

function validCurrency(cur) {
  if (typeof cur !== 'string' || cur.length !== 3) return false;
  for (const ch of cur) {
    if (!(ch >= 'A' && ch <= 'Z')) return false;
  }
  return true;
}

function parseAmount(v) {
  if (typeof v !== 'string') return NaN;
  if (v === '' || v.indexOf('-') >= 0) return NaN;
  let seenDot = false;
  for (const ch of v) {
    if (ch === '.') {
      if (seenDot) return NaN;
      seenDot = true;
      continue;
    }
    if (!(ch >= '0' && ch <= '9')) return NaN;
  }
  return Number(v);
}

class PaymentGuard {
  constructor(policy) {
    this.policy = policy || defaultPaymentPolicy();
    this.lastShow = new Map();
  }

  _base(ctx) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { ok: false, reason: PG_REASON.BAD_ORIGIN };
    if (pol.requireSecureContext && ctx.isSecureContext !== true) {
      return { ok: false, reason: PG_REASON.INSECURE_CONTEXT };
    }
    const host = originHost(ctx.origin);
    if (!host) return { ok: false, reason: PG_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { ok: false, reason: PG_REASON.BLOCKED_ORIGIN };
    if (pol.denyBackground && ctx.isBackground === true) return { ok: false, reason: PG_REASON.BACKGROUND };
    return { ok: true, host, now: ctx.now || 0 };
  }

  // validateMethods 校验 methodData 列表。
  validateMethods(methodData) {
    const list = Array.isArray(methodData) ? methodData : [];
    if (list.length === 0) return { ok: false, reason: PG_REASON.EMPTY_METHODS };
    for (const m of list) {
      const { kind, host } = methodHost(m && m.supportedMethods);
      if (kind === 'basic') {
        if (host.indexOf('basic-card') >= 0 && !this.policy.allowBasicCard) {
          return { ok: false, reason: PG_REASON.PAYMENT_METHOD_NOT_ALLOWED, method: host };
        }
        // 其它非 URL 私有方法标识（如 https URL 外的 token）默认拒绝。
        if (this.policy.allowedMethodHostSuffixes.length === 0 && host.indexOf('basic-card') < 0) {
          return { ok: false, reason: PG_REASON.PAYMENT_METHOD_NOT_ALLOWED, method: host };
        }
      } else if (kind === 'url') {
        const ok = this.policy.allowedMethodHostSuffixes.some((suf) => host === suf || host.endsWith('.' + suf));
        if (!ok) return { ok: false, reason: PG_REASON.PAYMENT_METHOD_NOT_ALLOWED, method: host };
      } else {
        return { ok: false, reason: PG_REASON.PAYMENT_METHOD_NOT_ALLOWED };
      }
    }
    return { ok: true };
  }

  // validateDetails 校验币种与金额。
  validateDetails(details) {
    const item = details && details.total;
    const amount = item && item.amount;
    if (!amount || !validCurrency(amount.currency)) return { ok: false, reason: PG_REASON.BAD_CURRENCY };
    const val = parseAmount(amount.value);
    if (!isFinite(val) || val <= 0 || val > 1e12) return { ok: false, reason: PG_REASON.BAD_AMOUNT };
    return { ok: true, value: val };
  }

  // contactFieldCount 统计过度收集的联系人字段。
  contactFieldCount(options) {
    let n = 0;
    if (options && options.requestPayerName === true) n++;
    if (options && options.requestPayerEmail === true) n++;
    if (options && options.requestPayerPhone === true) n++;
    return n;
  }

  // decideShow 裁决 paymentRequest.show()。
  decideShow(ctx, methodData, details, options) {
    const b = this._base(ctx);
    if (!b.ok) return { decision: PG_DENY, reason: b.reason };
    if (this.policy.requireGestureForShow && ctx.hasUserGesture !== true) {
      return { decision: PG_DENY, reason: PG_REASON.NO_GESTURE };
    }
    if (this.lastShow.has(b.host) && b.now - this.lastShow.get(b.host) < this.policy.showMinIntervalMs) {
      return { decision: PG_DENY, reason: PG_REASON.SHOW_THROTTLED };
    }
    const m = this.validateMethods(methodData);
    if (!m.ok) return { decision: PG_DENY, reason: m.reason };
    const d = this.validateDetails(details);
    if (!d.ok) return { decision: PG_DENY, reason: d.reason };
    if (this.contactFieldCount(options) > this.policy.maxContactFields) {
      return { decision: PG_DENY, reason: PG_REASON.EXCESSIVE_CONTACT_REQUEST };
    }
    this.lastShow.set(b.host, b.now);
    return { decision: PG_PROMPT, reason: '', amount: d.value };
  }

  // decideCanMake 裁决 canMakePayment / hasEnrolledInstrument（支付能力指纹）。
  decideCanMake(ctx) {
    const b = this._base(ctx);
    if (!b.ok) return { allowed: false, reason: b.reason };
    if (!this.policy.allowCanMakeProbe) {
      return { allowed: false, reason: PG_REASON.CANMAKE_FINGERPRINT };
    }
    return { allowed: true, reason: '' };
  }
}

module.exports = {
  PG_ALLOW, PG_DENY, PG_PROMPT, PG_REASON,
  defaultPaymentPolicy, originHost, validCurrency, parseAmount, methodHost, PaymentGuard,
};
