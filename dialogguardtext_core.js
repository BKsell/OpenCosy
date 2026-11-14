"use strict";

function classifyType(rawType) {
  const t = String(rawType || '').toLowerCase();
  if (JS_TYPES.has(t)) return t;
  if (t === DIALOG_BEFOREUNLOAD) return DIALOG_BEFOREUNLOAD;
  return DIALOG_OTHER;
}

// isBeforeUnload 供接线处分流：beforeunload 由 unloadguard 裁决，本内核不计数。
function isBeforeUnload(rawType) {
  return classifyType(rawType) === DIALOG_BEFOREUNLOAD;
}

// normalizeMessage 规整弹窗文案：非字符串按空处理，去除 C0/C1 控制字符（保留常规空白），
// 折叠连续空白并截断长度；changed/truncated 用于判定畸形输入。
function normalizeMessage(rawMessage) {
  let s = typeof rawMessage === 'string' ? rawMessage : '';
  const original = s;
  // 去掉除常见水平空白/tab/换行外的控制字符；再把所有连续空白压成一个空格。
  s = s.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, '');
  s = s.replace(/\s+/g, ' ').trim();
  const changed = s !== original.trim();
  let truncated = false;
  if (s.length > DIALOG_MESSAGE_MAX_LEN) {
    s = s.slice(0, DIALOG_MESSAGE_MAX_LEN);
    truncated = true;
  }
  return { message: s, changed, truncated, malformed: changed || truncated };
}

const DIALOG_REASON_TEXT = {
  [SUPPRESS_BURST]: '网页在短时间内连续弹出模态对话框（疑似弹窗轰炸），本次已拦截',
  [SUPPRESS_LONG]: '网页持续高频弹出对话框，本次已拦截并进入冷却',
  [SUPPRESS_COOLDOWN]: '对话框冷却期内的重复弹窗已拦截',
  [SUPPRESS_DUPLICATE]: '网页连续弹出相同文案的对话框，已合并拦截',
  [SUPPRESS_MALFORMED]: '对话框文案含异常控制字符或超长，已做净化展示',
};

function describeDialogReason(reason) {
  return describeReasonFrom(DIALOG_REASON_TEXT, reason, '对话框请求');
}

module.exports = { classifyType, isBeforeUnload, normalizeMessage, DIALOG_REASON_TEXT, describeDialogReason };
