'use strict';
const { DIALOG_SHOW, DIALOG_SUPPRESS, DIALOG_ALERT, DIALOG_CONFIRM, DIALOG_PROMPT, DIALOG_BEFOREUNLOAD, DIALOG_OTHER, SUPPRESS_BURST, SUPPRESS_LONG, SUPPRESS_COOLDOWN, SUPPRESS_DUPLICATE, SUPPRESS_MALFORMED, DIALOG_BURST_WINDOW_MS, DIALOG_BURST_LIMIT, DIALOG_LONG_WINDOW_MS, DIALOG_LONG_LIMIT, DIALOG_COOLDOWN_MS, DIALOG_DUP_MS, DIALOG_MESSAGE_MAX_LEN, JS_TYPES, createDialogState, decideDialog } = require('./dialogguardpolicy_core');
const { classifyType, isBeforeUnload, normalizeMessage, DIALOG_REASON_TEXT, describeDialogReason } = require('./dialogguardtext_core');
const { describeReasonFrom } = require('./reasontext');
const { pruneOlderThan, countSince, originFromUrl, resetCooldown, inCooldown } = require('./modutil_core');

// dialogguard.js —— 网页 JS 模态对话框（alert/confirm/prompt）的滥用/DoS 收口内核。
//
// 威胁模型：
//   alert()/confirm()/prompt() 会拉起应用级阻塞模态框，模态期间整个窗口停止响应输入。
//   恶意页可以：
//     1) 在定时器或前一个弹窗关闭回调里递归弹窗，形成“关不完”的轰炸（拒绝服务）；
//     2) 用完全相同的文案无限 confirm() 实施诈骗/疲劳点击（点错“是”即授权）；
//     3) 塞超长 / 含控制字符的消息撑爆布局、伪造系统语气。
//   Electron 的 webContents 'dialog' 事件可 preventDefault() 取消本次内置对话框，
//   因此与 printguard 同构，用“滑动窗口配额 + 冷却 + 同文案去抖”收敛：
//     - 短窗口（10s）突发上限 DIALOG_BURST_LIMIT；
//     - 长窗口（60s）总量上限 DIALOG_LONG_LIMIT；
//     - 同一 type+同一规范化文案在 DIALOG_DUP_MS 内重复，直接抑制（递归同文案弹窗）；
//     - 任一窗口越限进入冷却，冷却期内全部抑制。
//   beforeunload 类型不在此内核处理（由 unloadguard 统一裁决），这里显式放行/跳过，
//   避免两处对同一弹窗重复计数。
//   本模块只做纯判定，main.js 监听 'dialog'、按结果 preventDefault 并留痕。

module.exports = {
  DIALOG_SHOW,
  DIALOG_SUPPRESS,
  DIALOG_ALERT,
  DIALOG_CONFIRM,
  DIALOG_PROMPT,
  DIALOG_BEFOREUNLOAD,
  DIALOG_OTHER,
  SUPPRESS_BURST,
  SUPPRESS_LONG,
  SUPPRESS_COOLDOWN,
  SUPPRESS_DUPLICATE,
  SUPPRESS_MALFORMED,
  DIALOG_BURST_WINDOW_MS,
  DIALOG_BURST_LIMIT,
  DIALOG_LONG_WINDOW_MS,
  DIALOG_LONG_LIMIT,
  DIALOG_COOLDOWN_MS,
  DIALOG_DUP_MS,
  DIALOG_MESSAGE_MAX_LEN,
  classifyType,
  isBeforeUnload,
  normalizeMessage,
  originFromUrl,
  createDialogState,
  inCooldown,
  decideDialog,
  resetCooldown,
  describeDialogReason,
  DIALOG_REASON_TEXT,
  JS_TYPES,
};
