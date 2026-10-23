'use strict';

// digitalcredentialguard.js —— Digital Credentials API（navigator.credentials.get({digital})）
// 移动证件/mDoc/可验证凭证（VC）过度索取裁决内核。
//
// 威胁模型：
//   1. 页面通过 DigitalCredential 请求移动驾照（mDL）/年龄凭证/学历 VC，一旦用户同意，
//      协议返回的字段可能远多于展示所需（姓名、住址、证件号、出生日期、照片），是强身份数据；
//   2. 用一个过宽的 docType（org.iso.18013.5.1 整本驾照）+ requests 里列全字段，等价于
//      抄走整份证件；年龄校验本只需要 age_over_18 布尔却索取真实生日；
//   3. credential 提供方（provider）被指向非系统钱包的第三方 origin，凭证可能被中转；
//   4. 无手势/不可见页面弹系统级证件选择器构成点击劫持；
//   5. 多个 protocol（mdoc/vc-sd-jwt）叠加请求、海量字段是脏数据与过度收集。
//
// 纯逻辑。

const DC_ALLOW = 'allow';
const DC_DENY = 'deny';

const DC_REASON = Object.freeze({
  BAD_CONTEXT: 'dc-bad-context',
  NO_GESTURE: 'dc-no-gesture',
  NOT_VISIBLE: 'dc-not-visible',
  INSECURE_ORIGIN: 'dc-insecure-origin',
  NO_REQUEST: 'dc-no-request',
  UNKNOWN_PROTOCOL: 'dc-unknown-protocol',
  DOC_TYPE_NOT_ALLOWED: 'dc-doc-type-not-allowed',
  FIELD_NOT_ALLOWED: 'dc-field-not-allowed',
  AGE_SHOULD_USE_PREDICATE: 'dc-age-should-use-predicate',
  TOO_MANY_FIELDS: 'dc-too-many-fields',
  TOO_MANY_CREDENTIALS: 'dc-too-many-credentials',
  PROVIDER_NOT_TRUSTED: 'dc-provider-not-trusted',
  NONCE_REUSED_OR_BAD: 'dc-nonce-reused-or-bad',
});

// 各 docType 允许的"最小必要"字段白名单。
const DC_DOCTYPE_FIELDS = Object.freeze({
  'org.iso.18013.5.1': Object.freeze([
    'family_name', 'given_name', 'issue_date', 'expiry_date',
    'age_over_18', 'age_over_21', 'age_in_years',
  ]),
  'org.idms.age.1': Object.freeze(['age_over_18', 'age_over_21']),
  'OpenBadgeCredential': Object.freeze(['name', 'description', 'issuer']),
});
// 真实生日相关字段：年龄场景应使用 age_over_* 谓词而非这些。
const DC_BIRTH_FIELDS = Object.freeze(['birth_date', 'birthdate', 'dob', 'age_birth_year']);
const DC_KNOWN_PROTOCOLS = Object.freeze(['org.iso.18013.5-1', 'mdoc', 'vc+sd-jwt', 'openid4vp']);

function defaultDigitalCredentialPolicy() {
  return {
    requireHttps: true,
    requireUserGesture: true,
    requireVisible: true,
    allowedDocTypes: Object.keys(DC_DOCTYPE_FIELDS),
    maxFieldsPerRequest: 6,
    maxCredentialsPerCall: 2,
    trustedProviders: [], // 钱包提供方 origin 白名单；空=仅允许系统默认（无显式 provider）
    requireFreshNonce: true,
  };
}

function byteLen(s) {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    n += c < 0x80 ? 1 : (c < 0x800 ? 2 : 3);
  }
  return n;
}

class DigitalCredentialGuard {
  constructor(policy) {
    this.policy = policy || defaultDigitalCredentialPolicy();
    this.seenNonces = new Set();
  }

  // decideGet 裁决 credentials.get({digital:{requests,providers,nonce}})。
  decideGet(ctx, options) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return { decision: DC_DENY, reason: DC_REASON.BAD_CONTEXT };
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return { decision: DC_DENY, reason: DC_REASON.INSECURE_ORIGIN };
    if (pol.requireUserGesture && ctx.userGesture !== true) return { decision: DC_DENY, reason: DC_REASON.NO_GESTURE };
    if (pol.requireVisible && ctx.visible === false) return { decision: DC_DENY, reason: DC_REASON.NOT_VISIBLE };

    const dig = options && typeof options === 'object' ? options.digital : null;
    const requests = dig && Array.isArray(dig.requests) ? dig.requests : null;
    if (!requests || requests.length === 0) return { decision: DC_DENY, reason: DC_REASON.NO_REQUEST };
    if (requests.length > pol.maxCredentialsPerCall) return { decision: DC_DENY, reason: DC_REASON.TOO_MANY_CREDENTIALS, count: requests.length };

    // 显式第三方 provider 必须受信；未提供 provider 视为系统钱包。
    const providers = dig && Array.isArray(dig.providers) ? dig.providers : [];
    for (const pv of providers) {
      const origin = typeof pv === 'string' ? pv : (pv && pv.origin);
      if (pol.trustedProviders.length === 0 || pol.trustedProviders.indexOf(origin) < 0) {
        return { decision: DC_DENY, reason: DC_REASON.PROVIDER_NOT_TRUSTED, provider: origin };
      }
    }

    if (pol.requireFreshNonce) {
      const nonce = dig && typeof dig.nonce === 'string' ? dig.nonce : '';
      if (byteLen(nonce) < 16 || byteLen(nonce) > 256 || this.seenNonces.has(nonce)) {
        return { decision: DC_DENY, reason: DC_REASON.NONCE_REUSED_OR_BAD };
      }
      this.seenNonces.add(nonce);
    }

    let totalFields = 0;
    for (let i = 0; i < requests.length; i++) {
      const req = requests[i];
      const proto = req && req.protocol;
      if (DC_KNOWN_PROTOCOLS.indexOf(proto) < 0) return { decision: DC_DENY, reason: DC_REASON.UNKNOWN_PROTOCOL, index: i, protocol: proto };
      const docType = req.docType || req.credentialDefinition && req.credentialDefinition.type;
      if (pol.allowedDocTypes.indexOf(docType) < 0) {
        return { decision: DC_DENY, reason: DC_REASON.DOC_TYPE_NOT_ALLOWED, index: i, docType };
      }
      const fields = Array.isArray(req.requestedFields) ? req.requestedFields :
        (Array.isArray(req.fields) ? req.fields : []);
      totalFields += fields.length;
      if (totalFields > pol.maxFieldsPerRequest) return { decision: DC_DENY, reason: DC_REASON.TOO_MANY_FIELDS, count: totalFields };

      const allowed = DC_DOCTYPE_FIELDS[docType] || [];
      const ageScene = req.purpose === 'age_verification';
      for (const fld of fields) {
        if (DC_BIRTH_FIELDS.indexOf(fld) >= 0 && ageScene) {
          return { decision: DC_DENY, reason: DC_REASON.AGE_SHOULD_USE_PREDICATE, field: fld };
        }
        if (allowed.indexOf(fld) < 0) {
          return { decision: DC_DENY, reason: DC_REASON.FIELD_NOT_ALLOWED, index: i, field: fld, docType };
        }
      }
    }
    return { decision: DC_ALLOW, reason: '' };
  }
}

module.exports = {
  DC_ALLOW, DC_DENY, DC_REASON,
  DC_DOCTYPE_FIELDS, DC_BIRTH_FIELDS, DC_KNOWN_PROTOCOLS,
  defaultDigitalCredentialPolicy, byteLen, DigitalCredentialGuard,
};
