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

const {
  DEFAULT_MAX_BYTES,
  DEFAULT_MAX_DEPTH,
  DEFAULT_MAX_KEYS,
  REASON,
  asPlainObject,
  isPlainObject
} = require('./inputguard_rules');

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
