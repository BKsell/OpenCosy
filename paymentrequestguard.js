'use strict';

// paymentrequestguard.js —— Payment Request API（new PaymentRequest）支付参数与收货信息裁决内核。
//
// 威胁模型：
//   1. 支付单由页面构造，methodData 里塞第三方/私有支付方式标识（android-pay 数据里的
//      gateway、merchantId）可把交易导向攻击者网关；supportedMethods 用通配 basic-card 仍会
//      触发表单式卡号收集；
//   2. requestShipping + 索取 address/收件人/电话，在纯数字商品场景过度收集 PII；
//   3. currency/value 脏值（负金额、NaN、超大金额、非 ISO 货币码）造成记账混乱或钓鱼；
//   4. show(detailsPromise) 长时间不 resolve 悬挂支付 UI；canMakePayment/hasEnrolledInstrument
//      被反复调用做持卡状态探测；
//   5. PaymentInstruments 持久保存卡号别名。
//
// 纯逻辑。

const PR_ALLOW = 'allow';
const PR_DENY = 'deny';

const PR_REASON = Object.freeze({
  BAD_CONTEXT: 'pr-bad-context',
  INSECURE_ORIGIN: 'pr-insecure-origin',
  NO_METHOD_DATA: 'pr-no-method-data',
  UNKNOWN_PAYMENT_METHOD: 'pr-unknown-payment-method',
  GATEWAY_NOT_ALLOWED: 'pr-gateway-not-allowed',
  BASIC_CARD_DISABLED: 'pr-basic-card-disabled',
  SHIPPING_OVERCOLLECTION: 'pr-shipping-overcollection',
  BAD_CURRENCY: 'pr-bad-currency',
  BAD_AMOUNT: 'pr-bad-amount',
  SHOW_TIMEOUT: 'pr-show-timeout',
  ENROLLMENT_PROBE: 'pr-enrollment-probe',
});

const PR_KNOWN_METHODS = Object.freeze([
  'https://play.google.com/billing',
  'https://apple.com/apple-pay',
  'https://google.com/pay',
]);

function defaultPaymentRequestPolicy() {
  return {
    requireHttps: true,
    allowedMethods: PR_KNOWN_METHODS.slice(),
    allowBasicCard: false,
    allowedGateways: ['stripe', 'adyen', 'braintree', 'checkoutljs'],
    requireShippingForDigitalGoods: false,
    maxShippingFields: 4,
    allowedCurrencies: [], // 空=接受任意 3 字母 ISO
    maxAmount: 100000000,
    maxShowResolveMs: 15000,
    maxEnrollmentProbesPerMinute: 4,
  };
}

function isDigits(s) {
  if (typeof s !== 'string' || s.length === 0) return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 48 || c > 57) return false;
  }
  return true;
}
// parseAmount 解析十进制金额，返回以最小单位放大 100 倍的整数（最多两位小数）。
function parseAmount(s) {
  if (typeof s !== 'string') return null;
  if (s.length === 0 || s.length > 15) return null;
  const dot = s.indexOf('.');
  let whole = s;
  let frac = '';
  if (dot >= 0) {
    whole = s.slice(0, dot);
    frac = s.slice(dot + 1);
  }
  if (whole.length === 0 || !isDigits(whole)) return null;
  if (dot >= 0) {
    if (frac.length === 0 || frac.length > 2 || !isDigits(frac)) return null;
  }
  while (frac.length < 2) frac += '0';
  return Number(whole) * 100 + Number(frac);
}

class PaymentRequestGuard {
  constructor(policy, clock) {
    this.policy = policy || defaultPaymentRequestPolicy();
    this.clock = typeof clock === 'function' ? clock : (() => Date.now());
    this.probeTimes = [];
  }

  // decideConstruct 裁决 new PaymentRequest(methodData, details, options)。
  decideConstruct(ctx, methodData, details, options) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return { decision: PR_DENY, reason: PR_REASON.BAD_CONTEXT };
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return { decision: PR_DENY, reason: PR_REASON.INSECURE_ORIGIN };
    if (!Array.isArray(methodData) || methodData.length === 0) return { decision: PR_DENY, reason: PR_REASON.NO_METHOD_DATA };

    for (const md of methodData) {
      const method = md && md.supportedMethods;
      if (method === 'basic-card') {
        if (!pol.allowBasicCard) return { decision: PR_DENY, reason: PR_REASON.BASIC_CARD_DISABLED };
        continue;
      }
      if (pol.allowedMethods.indexOf(method) < 0) {
        return { decision: PR_DENY, reason: PR_REASON.UNKNOWN_PAYMENT_METHOD, method };
      }
      const data = md.data;
      if (data && typeof data === 'object') {
        if (data.environment === 'production' && typeof data.gateway === 'string' &&
            pol.allowedGateways.indexOf(data.gateway) < 0) {
          return { decision: PR_DENY, reason: PR_REASON.GATEWAY_NOT_ALLOWED, gateway: data.gateway };
        }
      }
    }

    // 金额/币种。
    const total = details && details.total && details.total.amount;
    if (!total || typeof total.currency !== 'string' || total.currency.length !== 3) {
      return { decision: PR_DENY, reason: PR_REASON.BAD_CURRENCY };
    }
    const cur = total.currency.toUpperCase();
    for (let i = 0; i < cur.length; i++) {
      const c = cur.charCodeAt(i);
      if (c < 65 || c > 90) return { decision: PR_DENY, reason: PR_REASON.BAD_CURRENCY };
    }
    if (pol.allowedCurrencies.length > 0 && pol.allowedCurrencies.indexOf(cur) < 0) {
      return { decision: PR_DENY, reason: PR_REASON.BAD_CURRENCY, currency: cur };
    }
    const cents = parseAmount(total.value);
    if (cents === null || cents <= 0 || cents > pol.maxAmount * 100) {
      return { decision: PR_DENY, reason: PR_REASON.BAD_AMOUNT, value: total.value };
    }

    // 数字商品不应索取收货 PII。
    const opt = options && typeof options === 'object' ? options : {};
    if (opt.requestShipping && ctx.goodsType === 'digital' && !pol.requireShippingForDigitalGoods) {
      return { decision: PR_DENY, reason: PR_REASON.SHIPPING_OVERCOLLECTION };
    }
    return { decision: PR_ALLOW, reason: '', amountCents: cents, currency: cur };
  }

  // decideShow 裁决 show(detailsPromise)：detailsPromise 必须在限期内 resolve。
  decideShow(resolveMs) {
    const pol = this.policy;
    if (typeof resolveMs === 'number' && resolveMs > pol.maxShowResolveMs) {
      return { decision: PR_DENY, reason: PR_REASON.SHOW_TIMEOUT, resolveMs };
    }
    return { decision: PR_ALLOW, reason: '' };
  }

  // decideEnrollmentProbe 裁决 hasEnrolledInstrument/canMakePayment 探测频率。
  decideEnrollmentProbe() {
    const pol = this.policy;
    const now = this.clock();
    this.probeTimes = this.probeTimes.filter((ts) => now - ts < 60000);
    if (this.probeTimes.length >= pol.maxEnrollmentProbesPerMinute) {
      return { decision: PR_DENY, reason: PR_REASON.ENROLLMENT_PROBE };
    }
    this.probeTimes.push(now);
    return { decision: PR_ALLOW, reason: '' };
  }
}

module.exports = {
  PR_ALLOW, PR_DENY, PR_REASON, PR_KNOWN_METHODS,
  defaultPaymentRequestPolicy, parseAmount, PaymentRequestGuard,
};
