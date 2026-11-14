'use strict';

const MAX_ORDER_IDS = 500;  // 单窗口参与顺序编排的标签数硬上界，与标签栏实际容量对齐
const MAX_ORDER_ID_LEN = 128; // 单个标签 id 长度上界，与 pintabs / tabgroups 保持一致

const REJECT_NOT_ARRAY = 'not-array';
const REJECT_BAD_ID = 'bad-id';

// 与 tabgroups.sanitizeTabId 同一判定口径，但这里是批量、保序、去重、截断的版本，
// 独立实现以保持模块自包含（不反向依赖 tabgroups，便于单测与复用）。
function hasControlChar(s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    // 0x00-0x1F 与 0x7F 为 ASCII 控制字符（含 \t \n \r 等），标签 id 不允许出现。
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function isValidOrderId(value) {
  if (typeof value !== 'string') return false;
  if (value.length === 0 || value.length > MAX_ORDER_ID_LEN) return false;
  if (hasControlChar(value)) return false;
  return true;
}

/**
 * 把任意输入净化成“唯一、保序、有上界”的标签 id 数组。
 * 非法 / 重复条目静默丢弃（顺序编排对单个脏 id 的策略是跳过，而非整单拒绝）。
 * @param {*} raw
 * @param {number} [limit]
 * @returns {{ok:boolean,reason?:string,value:string[]}}
 */
function sanitizeOrderIds(raw, limit) {
  if (!Array.isArray(raw)) return { ok: false, reason: REJECT_NOT_ARRAY, value: [] };
  const max = Number.isInteger(limit) && limit > 0 ? limit : MAX_ORDER_IDS;
  const seen = new Set();
  const out = [];
  for (const item of raw) {
    if (!isValidOrderId(item)) continue;
    if (seen.has(item)) continue;
    seen.add(item);
    out.push(item);
    if (out.length >= max) break;
  }
  return { ok: true, value: out };
}

module.exports = {
  MAX_ORDER_IDS,
  MAX_ORDER_ID_LEN,
  REJECT_NOT_ARRAY,
  REJECT_BAD_ID,
  hasControlChar,
  isValidOrderId,
  sanitizeOrderIds,
};
