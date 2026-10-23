'use strict';

// clipboardguard.js —— 异步剪贴板 API（navigator.clipboard.read/readText/
// write/writeText）与敏感内容识别内核。
//
// 与 selectionguard 的分工：selectionguard 管 copy/cut 事件劫持与选区回落；
// 本模块专注页面“主动、静默读取系统剪贴板”这条更高危的路径。
//
// 威胁模型：
//   1. 页面在获得焦点后无提示轮询 clipboard.readText()，偷走验证码、密码、
//      钱包助记词、信用卡号；
//   2. 非安全上下文、后台标签页、无手势发起异步读取；
//   3. 高频读取做剪贴板内容变化监控（监听用户复制行为）；
//   4. 写入 javascript:/data:text/html 富文本，用户粘贴到地址栏/其它页面触发 XSS；
//   5. 写入超大内容做内存放大；
//   6. 把页面伪装成系统，诱导“粘贴以验证”，读取后立刻外发。
//
// 纯逻辑；敏感识别全部用字符运算，不用正则。

const CB_DENY = 'deny';
const CB_ALLOW = 'allow';
const CB_CONFIRM = 'confirm'; // 读到疑似敏感内容时上层应提示用户

const CB_REASON = Object.freeze({
  INSECURE_CONTEXT: 'cb-insecure-context',
  BAD_ORIGIN: 'cb-bad-origin',
  BLOCKED_ORIGIN: 'cb-blocked-origin',
  BACKGROUND_READ: 'cb-background-read',
  NOT_FOCUSED: 'cb-not-focused',
  NO_GESTURE: 'cb-requires-gesture',
  READ_THROTTLED: 'cb-read-throttled',
  WRITE_THROTTLED: 'cb-write-throttled',
  DANGEROUS_HTML: 'cb-dangerous-html',
  WRITE_TOO_LARGE: 'cb-write-too-large',
  EMPTY_CLIPBOARD: 'cb-empty-clipboard',
});

const SENS = Object.freeze({
  NONE: 'none',
  CREDIT_CARD: 'credit-card',
  PRIVATE_KEY: 'private-key',
  MNEMONIC: 'mnemonic',
  LONG_HEX_SECRET: 'long-hex-secret',
  OTP_CODE: 'otp-code',
  BEARER_TOKEN: 'bearer-token',
  PASSWORD_LINE: 'password-line',
});

function defaultClipboardPolicy() {
  return {
    requireSecureContext: true,
    requireGestureForRead: true,
    requireFocusForRead: true,
    denyBackgroundRead: true,
    readMinIntervalMs: 1500,
    writeMinIntervalMs: 250,
    maxReadBytes: 1024 * 1024,
    maxWriteBytes: 1024 * 1024,
    confirmOnSensitive: true,
    stripDangerousHtmlOnWrite: true,
  };
}

function originKey(origin) {
  if (typeof origin !== 'string') return '';
  const idx = origin.indexOf('://');
  if (idx <= 0) return '';
  const scheme = origin.slice(0, idx).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') return '';
  const rest = origin.slice(idx + 3);
  if (rest === '' || rest.indexOf('/') >= 0 || rest.indexOf('?') >= 0) return '';
  return scheme + '://' + rest.toLowerCase();
}

function byteLen(s) {
  // 简单 UTF-8 长度估计（字符码 >= 0x80 计 2，代理对另计），用于上限判定足够。
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else n += 3;
  }
  return n;
}

function isAsciiDigit(c) {
  return c >= 48 && c <= 57;
}

function digitsOnly(s) {
  if (s.length < 12) return false;
  for (let i = 0; i < s.length; i++) {
    if (!isAsciiDigit(s.charCodeAt(i))) return false;
  }
  return true;
}

// luhnValid 对纯数字串做 Luhn 校验（信用卡号检测）。
function luhnValid(s) {
  let sum = 0;
  let dbl = false;
  for (let i = s.length - 1; i >= 0; i--) {
    let d = s.charCodeAt(i) - 48;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

function isHex(s) {
  if (s.length < 32) return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const ok = (c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70);
    if (!ok) return false;
  }
  return true;
}

function isLikelyOtp(token) {
  if (token.length < 4 || token.length > 8) return false;
  for (let i = 0; i < token.length; i++) {
    if (!isAsciiDigit(token.charCodeAt(i))) return false;
  }
  // 拒绝全相同数字（如 000000 仍可能是验证码，但单串无法区分；这里宽松放行给上层）
  return true;
}

function countWords(s) {
  let n = 0;
  let inWord = false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const word = (c >= 97 && c <= 122) || (c >= 65 && c <= 90);
    if (word && !inWord) { n++; inWord = true; }
    if (!word) inWord = false;
  }
  return n;
}

// classifySensitivity 对剪贴板文本做敏感分级，返回最确定的一类。
function classifySensitivity(rawText) {
  const text = typeof rawText === 'string' ? rawText.trim() : '';
  if (text === '') return SENS.NONE;

  const lower = text.toLowerCase();
  if (lower.indexOf('-----begin') >= 0 &&
    (lower.indexOf('private key') >= 0 || lower.indexOf('openssh') >= 0 || lower.indexOf('pgp') >= 0)) {
    return SENS.PRIVATE_KEY;
  }
  if (lower.indexOf('bearer ') === 0 || lower.indexOf('authorization: bearer') >= 0) {
    return SENS.BEARER_TOKEN;
  }

  // 信用卡：取文本中最长连续数字段做 Luhn。
  let run = '';
  for (let i = 0; i <= text.length; i++) {
    const c = i < text.length ? text.charCodeAt(i) : 0;
    if (isAsciiDigit(c)) {
      run += text[i];
    } else {
      if (digitsOnly(run) && luhnValid(run)) return SENS.CREDIT_CARD;
      run = '';
    }
  }

  // 助记词：小写英文单词数在 12/15/18/21/24。
  if (text.indexOf(' ') >= 0) {
    const wc = countWords(text);
    if ((wc === 12 || wc === 15 || wc === 18 || wc === 21 || wc === 24) && wc >= 12) {
      const allLowerAlphaSpaces = allWordsLowerAlpha(text);
      if (allLowerAlphaSpaces) return SENS.MNEMONIC;
    }
  }

  if (isHex(text)) return SENS.LONG_HEX_SECRET;

  // 孤立短数字串疑似验证码。
  if (text.length <= 8 && isLikelyOtp(text)) return SENS.OTP_CODE;

  // password=xxx / 密码：xxx 行。
  if (lower.indexOf('password=') === 0 || lower.indexOf('passwd=') === 0 ||
    text.indexOf('密码：') === 0 || text.indexOf('密码:') === 0) {
    return SENS.PASSWORD_LINE;
  }
  return SENS.NONE;
}

function allWordsLowerAlpha(text) {
  let hasLetter = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    const lower = c >= 97 && c <= 122;
    const space = c === 32;
    if (lower) hasLetter = true;
    if (!lower && !space) return false;
  }
  return hasLetter;
}

// containsDangerousHtmlScheme 检测要写入的富文本里是否含可执行 scheme。
function containsDangerousHtmlScheme(html) {
  if (typeof html !== 'string') return false;
  const lower = html.toLowerCase();
  const needles = ['javascript:', 'vbscript:', 'data:text/html', 'data:image/svg+xml'];
  for (const n of needles) {
    if (lower.indexOf(n) >= 0) return true;
  }
  return false;
}

class ClipboardGuard {
  constructor(policy) {
    this.policy = policy || defaultClipboardPolicy();
    this.lastRead = new Map();
    this.lastWrite = new Map();
  }

  _readBase(ctx) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { ok: false, reason: CB_REASON.BAD_ORIGIN };
    if (pol.requireSecureContext && ctx.isSecureContext !== true) {
      return { ok: false, reason: CB_REASON.INSECURE_CONTEXT };
    }
    const key = originKey(ctx.origin);
    if (!key) return { ok: false, reason: CB_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { ok: false, reason: CB_REASON.BLOCKED_ORIGIN };
    if (pol.denyBackgroundRead && ctx.isBackground === true) {
      return { ok: false, reason: CB_REASON.BACKGROUND_READ };
    }
    if (pol.requireFocusForRead && ctx.hasFocus !== true) {
      return { ok: false, reason: CB_REASON.NOT_FOCUSED };
    }
    if (pol.requireGestureForRead && ctx.hasUserGesture !== true) {
      return { ok: false, reason: CB_REASON.NO_GESTURE };
    }
    const now = ctx.now || 0;
    if (this.lastRead.has(key) && now - this.lastRead.get(key) < pol.readMinIntervalMs) {
      return { ok: false, reason: CB_REASON.READ_THROTTLED };
    }
    return { ok: true, key, now };
  }

  // decideRead 裁决一次读取；返回中带敏感分级，上层据此决定是否提示。
  decideRead(ctx, currentClipboardText) {
    const b = this._readBase(ctx);
    if (!b.ok) return { decision: CB_DENY, reason: b.reason };
    this.lastRead.set(b.key, b.now);
    const text = typeof currentClipboardText === 'string' ? currentClipboardText : '';
    if (text === '') return { decision: CB_ALLOW, reason: CB_REASON.EMPTY_CLIPBOARD, sensitivity: SENS.NONE };
    if (byteLen(text) > this.policy.maxReadBytes) {
      return { decision: CB_DENY, reason: CB_REASON.WRITE_TOO_LARGE };
    }
    const sensitivity = classifySensitivity(text);
    if (this.policy.confirmOnSensitive && sensitivity !== SENS.NONE) {
      return { decision: CB_CONFIRM, reason: '', sensitivity };
    }
    return { decision: CB_ALLOW, reason: '', sensitivity };
  }

  // decideWrite 裁决写入；html 给富文本，text 给纯文本。
  decideWrite(ctx, payload) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { decision: CB_DENY, reason: CB_REASON.BAD_ORIGIN };
    if (pol.requireSecureContext && ctx.isSecureContext !== true) {
      return { decision: CB_DENY, reason: CB_REASON.INSECURE_CONTEXT };
    }
    const key = originKey(ctx.origin);
    if (!key) return { decision: CB_DENY, reason: CB_REASON.BAD_ORIGIN };
    const now = ctx.now || 0;
    if (this.lastWrite.has(key) && now - this.lastWrite.get(key) < pol.writeMinIntervalMs) {
      return { decision: CB_DENY, reason: CB_REASON.WRITE_THROTTLED };
    }
    const html = payload && typeof payload.html === 'string' ? payload.html : '';
    const text = payload && typeof payload.text === 'string' ? payload.text : '';
    if (containsDangerousHtmlScheme(html)) {
      return { decision: CB_DENY, reason: CB_REASON.DANGEROUS_HTML };
    }
    if (byteLen(text) + byteLen(html) > pol.maxWriteBytes) {
      return { decision: CB_DENY, reason: CB_REASON.WRITE_TOO_LARGE };
    }
    this.lastWrite.set(key, now);
    return {
      decision: CB_ALLOW,
      reason: '',
      safeHtml: pol.stripDangerousHtmlOnWrite ? html : html,
    };
  }
}

module.exports = {
  CB_ALLOW, CB_DENY, CB_CONFIRM, CB_REASON, SENS,
  defaultClipboardPolicy, originKey, classifySensitivity, luhnValid,
  containsDangerousHtmlScheme, byteLen, ClipboardGuard,
};
