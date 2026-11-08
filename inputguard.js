'use strict';

// inputguard.js —— 渲染进程 IPC 入参的统一形状 / 长度 / 控制字符裁决内核。
//
// 威胁模型：
//   ipcMain 各通道收到的第一个实参完全由网页（渲染层）控制。历史代码对多数通道
//   只做了业务层的“能不能用”判断，缺少统一的“形状是否畸形 / 是否超大 / 是否藏
//   控制字符”裁决：
//     1) 期待 string 却收到 object / 超长串 / 含 NUL、CR/LF 的串，可能把脏数据写进
//        设置文件、拼进文件路径、送到搜索接口或本地命令；
//     2) 期待 array 却收到嵌套很深 / 元素成千上万的数组，放大后续处理开销；
//     3) save-settings 这类“整包落盘”通道若收到深层巨型对象，会把内存与磁盘打满；
//     4) 布尔 / 整数选项收到字符串 'false' 时 truthy，造成开关被意外打开。
//
//   本模块提供一组不抛异常的纯裁决器，统一返回 { ok, value, reason }。ok 为 true 时
//   value 是可直接使用的规整值；false 时 reason 是稳定错误码，main.js 据此拒绝并
//   记录安全事件。所有上限都刻意给得很宽（宁可放到接近“炸磁盘”的量级，也不误伤
//   正常使用），只挡明显畸形 / 滥用。

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

// measureObject：在不序列化的前提下，递归度量一个 JSON-like 值的嵌套深度、键总数
// 与粗略字符体量。opts.maxDepth / maxKeys / maxBytes 任一越界即返回 ok:false。
// 用于 save-settings 等“整包落盘”通道的有界性检查，防止深层巨型对象打爆磁盘。
function measureObject(root, opts) {
  const o = opts || {};
  const maxDepth = typeof o.maxDepth === 'number' ? o.maxDepth : DEFAULT_MAX_DEPTH;
  const maxKeys = typeof o.maxKeys === 'number' ? o.maxKeys : DEFAULT_MAX_KEYS;
  const maxBytes = typeof o.maxBytes === 'number' ? o.maxBytes : DEFAULT_MAX_BYTES;

  let keys = 0;
  let bytes = 0;
  let reason = '';
  const stack = [{ v: root, d: 0 }];
  while (stack.length > 0) {
    const { v, d } = stack.pop();
    if (d > maxDepth) { reason = REASON.TOO_DEEP; break; }
    const t = typeof v;
    if (t === 'string') {
      bytes += v.length;
    } else if (t === 'number' || t === 'boolean') {
      bytes += 8;
    } else if (v === null) {
      bytes += 4;
    } else if (Array.isArray(v)) {
      bytes += 2;
      for (let i = v.length - 1; i >= 0; i--) stack.push({ v: v[i], d: d + 1 });
    } else if (isPlainObject(v)) {
      const entries = Object.entries(v);
      keys += entries.length;
      bytes += 2;
      if (keys > maxKeys) { reason = REASON.TOO_MANY_KEYS; break; }
      for (let i = entries.length - 1; i >= 0; i--) {
        bytes += entries[i][0].length + 3;
        stack.push({ v: entries[i][1], d: d + 1 });
      }
    } else {
      // 函数 / undefined / Symbol / 类实例等不应出现在可落盘 JSON 里。
      reason = REASON.NOT_OBJECT;
      break;
    }
    if (bytes > maxBytes) { reason = REASON.TOO_LONG; break; }
  }
  if (reason) return { ok: false, keys, bytes, reason };
  return { ok: true, keys, bytes, reason: '' };
}

// assertShape：按字段规格批量校验一个普通对象。spec 为 { field: (v)=>{ok,value} }。
// 成功 value 是仅含 spec 字段的新对象（拒绝额外字段透传），失败给首个错误字段与原因。
function assertShape(input, spec) {
  const objRes = asPlainObject(input);
  if (!objRes.ok) return { ok: false, value: undefined, field: '', reason: objRes.reason };
  const out = {};
  for (const field of Object.keys(spec)) {
    const r = spec[field](input[field]);
    if (!r.ok) return { ok: false, value: undefined, field, reason: r.reason };
    out[field] = r.value;
  }
  return { ok: true, value: out, field: '', reason: '' };
}

module.exports = {
  REASON,
  DEFAULT_MAX_STRING,
  DEFAULT_MAX_ITEMS,
  DEFAULT_MAX_DEPTH,
  DEFAULT_MAX_KEYS,
  DEFAULT_MAX_BYTES,
  containsControlChar,
  asString,
  asBoolean,
  asInteger,
  isPlainObject,
  asPlainObject,
  asArray,
  asUrl,
  measureObject,
  assertShape,
};
