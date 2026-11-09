'use strict';


const REASON = Object.freeze({
  NOT_STRING: 'not-string',
  NOT_OBJECT: 'not-plain-object',
  NOT_ARRAY: 'not-array',
  NOT_BOOLEAN: 'not-boolean',
  NOT_INTEGER: 'not-integer',
  EMPTY: 'empty',
  TOO_LONG: 'too-long',
  TOO_MANY_ITEMS: 'too-many-items',
  CONTROL_CHAR: 'control-char',
  BAD_URL: 'bad-url',
  BAD_SCHEME: 'bad-scheme',
  TOO_DEEP: 'too-deep',
  TOO_MANY_KEYS: 'too-many-keys',
});

// 给得很宽的通用上限：单条字符串 1 MiB，单数组 10 万项，嵌套 32 层，
// 整包对象键总数 5 万、序列化体量 16 MiB。正常设置 / 下载清单远到不了这里。
const DEFAULT_MAX_STRING = 1 << 20;

const DEFAULT_MAX_ITEMS = 100000;

const DEFAULT_MAX_DEPTH = 32;

const DEFAULT_MAX_KEYS = 50000;

const DEFAULT_MAX_BYTES = 16 << 20;

function fail(reason) {
  return { ok: false, value: undefined, reason };
}

function pass(value) {
  return { ok: true, value, reason: '' };
}

function containsControlChar(s) {
  if (typeof s !== 'string') return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return true;
  }
  return false;
}

// asString：字符串裁决。opts:
//   max       最大长度（默认 1 MiB）
//   trim      是否去除首尾空白（默认 false，保留原值）
//   allowEmpty 是否允许空串（默认 true）
//   rejectControl 是否拒绝含 C0/DEL 控制字符的串（默认 true）
function asString(v, opts) {
  const o = opts || {};
  if (typeof v !== 'string') return fail(REASON.NOT_STRING);
  const max = typeof o.max === 'number' && o.max > 0 ? o.max : DEFAULT_MAX_STRING;
  if (v.length > max) return fail(REASON.TOO_LONG);
  if (o.rejectControl !== false && containsControlChar(v)) return fail(REASON.CONTROL_CHAR);
  let value = v;
  if (o.trim) value = value.trim();
  if (!o.allowEmpty && value.length === 0) return fail(REASON.EMPTY);
  return pass(value);
}

// asBoolean：只接受真正的布尔值。字符串 'false' 不会被当真，避免 truthy 绕过。
function asBoolean(v) {
  if (typeof v !== 'boolean') return fail(REASON.NOT_BOOLEAN);
  return pass(v);
}

// asInteger：只接受安全整数，可给 [min,max] 闭区间。
function asInteger(v, opts) {
  const o = opts || {};
  if (typeof v !== 'number' || !Number.isSafeInteger(v)) return fail(REASON.NOT_INTEGER);
  if (typeof o.min === 'number' && v < o.min) return fail(REASON.NOT_INTEGER);
  if (typeof o.max === 'number' && v > o.max) return fail(REASON.NOT_INTEGER);
  return pass(v);
}

// isPlainObject：仅接受普通对象（排除数组、null、类实例 / 带异常原型）。
function isPlainObject(v) {
  if (v === null || typeof v !== 'object') return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function asPlainObject(v) {
  if (!isPlainObject(v)) return fail(REASON.NOT_OBJECT);
  return pass(v);
}

// asArray：数组裁决，限定最大项数；不递归校验元素（元素校验交给调用方逐项做）。
function asArray(v, opts) {
  const o = opts || {};
  if (!Array.isArray(v)) return fail(REASON.NOT_ARRAY);
  const max = typeof o.maxItems === 'number' && o.maxItems > 0 ? o.maxItems : DEFAULT_MAX_ITEMS;
  if (v.length > max) return fail(REASON.TOO_MANY_ITEMS);
  return pass(v);
}

// asUrl：URL 裁决。opts.schemes 给允许协议（小写带冒号，默认 http/https）；
// opts.max 限 URL 长度。成功时 value 是规范化后的 URL 字符串。
function asUrl(v, opts) {
  const o = opts || {};
  const schemes = Array.isArray(o.schemes) && o.schemes.length > 0
    ? new Set(o.schemes.map(s => String(s).toLowerCase()))
    : new Set(['http:', 'https:']);
  const max = typeof o.max === 'number' && o.max > 0 ? o.max : 8192;
  if (typeof v !== 'string') return fail(REASON.BAD_URL);
  if (!v || v.length > max) return fail(REASON.BAD_URL);
  if (containsControlChar(v)) return fail(REASON.CONTROL_CHAR);
  let u;
  try {
    u = new URL(v);
  } catch {
    return fail(REASON.BAD_URL);
  }
  if (!schemes.has(u.protocol.toLowerCase())) return fail(REASON.BAD_SCHEME);
  // origin === 'null' 只在 http/https 下才视为异常（无法归属来源的网页地址）；
  // cosy: 等自定义协议的 origin 本就规范地序列化为 "null"，不能据此拒绝。
  if ((u.protocol === 'http:' || u.protocol === 'https:') && u.origin === 'null') {
    return fail(REASON.BAD_URL);
  }
  return pass(u.toString());
}

module.exports = {
  DEFAULT_MAX_BYTES,
  DEFAULT_MAX_DEPTH,
  DEFAULT_MAX_ITEMS,
  DEFAULT_MAX_KEYS,
  DEFAULT_MAX_STRING,
  REASON,
  asArray,
  asBoolean,
  asInteger,
  asPlainObject,
  asString,
  asUrl,
  containsControlChar,
  fail,
  isPlainObject,
  pass
};
