'use strict';

// webotpguard.js —— WebOTP（OTPCredential / SMS Receiver）短信验证码自动读取裁决内核。
//
// 威胁模型：
//   1. 页面调用 navigator.credentials.get({otp:{transport:['sms']}}) 可在用户无感时读取下一条
//      含 @/# 应用绑定码的短信，恶意站把自己域名写进短信体即可劫持验证码；
//   2. 短信里的 @ 域（来源）与当前文档 origin 不一致时，验证码会被错付给钓鱼站；
//   3. 后台/不可见页面挂起 OTP 读取，等验证码一到就取走；
//   4. 无手势反复发起读取形成对短信通道的轮询；
//   5. App 绑定码（# 后）被忽略校验时，同设备恶意 App 可联动。
//
// 纯逻辑：把短信体解析为 {realm, otp} 并与调用上下文核对。

const OTP_ALLOW = 'allow';
const OTP_DENY = 'deny';

const OTP_REASON = Object.freeze({
  BAD_CONTEXT: 'otp-bad-context',
  INSECURE_ORIGIN: 'otp-insecure-origin',
  NOT_VISIBLE: 'otp-not-visible',
  RATE_LIMIT: 'otp-rate-limit',
  MALFORMED_SMS: 'otp-malformed-sms',
  REALM_MISMATCH: 'otp-realm-mismatch',
  OTP_BAD_FORMAT: 'otp-bad-format',
  APP_BINDING_REQUIRED: 'otp-app-binding-required',
});

function defaultWebOtpPolicy() {
  return {
    requireHttps: true,
    requireVisible: true,
    maxRequestsPerMinute: 3,
    minOtpLength: 4,
    maxOtpLength: 10,
    requireAppBindingCode: false,
  };
}

// parseSms 解析 WebOTP 约定的最后一段：
// @example.com #123456 或 @example.com #123456 app-code
function parseSms(body) {
  if (typeof body !== 'string') return null;
  const at = body.lastIndexOf('\n@');
  const seg = at >= 0 ? body.slice(at + 1) : (body.indexOf('@') === 0 ? body : null);
  if (!seg) return null;
  const nl = seg.indexOf('\n');
  const line = nl >= 0 ? seg.slice(0, nl) : seg;
  const hash = line.indexOf('#');
  if (hash < 0) return null;
  const realmPart = line.slice(0, hash).trim();
  const tokens = splitSpaces(line.slice(hash + 1).trim());
  if (realmPart.charAt(0) !== '@') return null;
  const realm = realmPart.slice(1);
  const code = tokens[0];
  const appBinding = tokens.length > 1 ? tokens.slice(1).join(' ') : '';
  if (!realm || !code) return null;
  return { realm, code, appBinding };
}

// splitSpaces 按空白（空格/制表）纯字符切分，不使用正则。
function splitSpaces(s) {
  const out = [];
  let cur = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charAt(i);
    if (c === ' ' || c === '\t') {
      if (cur.length > 0) { out.push(cur); cur = ''; }
    } else {
      cur += c;
    }
  }
  if (cur.length > 0) out.push(cur);
  return out;
}

function hostOf(origin) {
  if (typeof origin !== 'string') return '';
  const i = origin.indexOf('://');
  if (i <= 0) return '';
  let rest = origin.slice(i + 3);
  for (const ch of ['/', '?', '#', ':']) {
    const p = rest.indexOf(ch);
    if (p >= 0) rest = rest.slice(0, p);
  }
  return rest.toLowerCase();
}
function isDigits(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 48 || c > 57) return false;
  }
  return true;
}

class WebOtpGuard {
  constructor(policy, clock) {
    this.policy = policy || defaultWebOtpPolicy();
    this.clock = typeof clock === 'function' ? clock : (() => Date.now());
    this.times = [];
  }

  // decideRead 裁决一次 OTP 读取。ctx: {origin, visible}；sms 为收到的短信体。
  decideRead(ctx, sms) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return { decision: OTP_DENY, reason: OTP_REASON.BAD_CONTEXT };
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return { decision: OTP_DENY, reason: OTP_REASON.INSECURE_ORIGIN };
    if (pol.requireVisible && ctx.visible === false) return { decision: OTP_DENY, reason: OTP_REASON.NOT_VISIBLE };

    const now = this.clock();
    this.times = this.times.filter((t) => now - t < 60000);
    if (this.times.length >= pol.maxRequestsPerMinute) return { decision: OTP_DENY, reason: OTP_REASON.RATE_LIMIT };
    this.times.push(now);

    const parsed = parseSms(sms);
    if (!parsed) return { decision: OTP_DENY, reason: OTP_REASON.MALFORMED_SMS };
    if (!isDigits(parsed.code) || parsed.code.length < pol.minOtpLength || parsed.code.length > pol.maxOtpLength) {
      return { decision: OTP_DENY, reason: OTP_REASON.OTP_BAD_FORMAT, code: parsed.code };
    }
    if (pol.requireAppBindingCode && !parsed.appBinding) {
      return { decision: OTP_DENY, reason: OTP_REASON.APP_BINDING_REQUIRED };
    }
    const host = hostOf(ctx.origin);
    if (host !== parsed.realm.toLowerCase() && host.indexOf('.' + parsed.realm.toLowerCase()) < 0) {
      return { decision: OTP_DENY, reason: OTP_REASON.REALM_MISMATCH, realm: parsed.realm, host };
    }
    return { decision: OTP_ALLOW, reason: '', code: parsed.code, realm: parsed.realm };
  }
}

module.exports = {
  OTP_ALLOW, OTP_DENY, OTP_REASON,
  defaultWebOtpPolicy, parseSms, hostOf, WebOtpGuard,
};
