'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  DIALOG_SHOW,
  DIALOG_SUPPRESS,
  DIALOG_ALERT,
  DIALOG_CONFIRM,
  DIALOG_PROMPT,
  DIALOG_BEFOREUNLOAD,
  SUPPRESS_BURST,
  SUPPRESS_LONG,
  SUPPRESS_COOLDOWN,
  SUPPRESS_DUPLICATE,
  SUPPRESS_MALFORMED,
  DIALOG_BURST_LIMIT,
  DIALOG_DUP_MS,
  DIALOG_LONG_WINDOW_MS,
  DIALOG_MESSAGE_MAX_LEN,
  classifyType,
  isBeforeUnload,
  normalizeMessage,
  createDialogState,
  inCooldown,
  decideDialog,
  resetCooldown,
  describeDialogReason,
} = require('./dialogguard');

const T0 = 8_000_000;

test('类型归一与 beforeunload 分流', () => {
  assert.equal(classifyType('ALERT'), DIALOG_ALERT);
  assert.equal(classifyType('Confirm'), DIALOG_CONFIRM);
  assert.equal(classifyType('prompt'), DIALOG_PROMPT);
  assert.equal(classifyType('beforeunload'), DIALOG_BEFOREUNLOAD);
  assert.equal(classifyType('weird'), 'other');
  assert.equal(isBeforeUnload('beforeunload'), true);
  assert.equal(isBeforeUnload('alert'), false);
});

test('文案净化：剥离控制字符、折叠空白、截断超长', () => {
  const ctrl = normalizeMessage('a\x00\x07b');
  assert.equal(ctrl.message, 'ab');
  assert.equal(ctrl.malformed, true);

  const spaces = normalizeMessage('  hello   \n\tworld  ');
  assert.equal(spaces.message, 'hello world');
  assert.equal(spaces.changed, true);

  const normal = normalizeMessage('正常 文案');
  assert.equal(normal.message, '正常 文案');
  assert.equal(normal.malformed, false);

  const long = normalizeMessage('x'.repeat(DIALOG_MESSAGE_MAX_LEN + 50));
  assert.equal(long.message.length, DIALOG_MESSAGE_MAX_LEN);
  assert.equal(long.truncated, true);

  assert.equal(normalizeMessage(null).message, '');
  assert.equal(normalizeMessage(undefined).message, '');
  assert.equal(normalizeMessage(123).message, '');
});

test('少量弹窗正常放行', () => {
  const st = createDialogState(T0);
  const r1 = decideDialog(st, { type: 'alert', message: 'hi', originUrl: 'https://a.test/' }, T0 + 10);
  const r2 = decideDialog(st, { type: 'confirm', message: 'sure?' }, T0 + 20);
  assert.equal(r1.decision, DIALOG_SHOW);
  assert.equal(r2.decision, DIALOG_SHOW);
  assert.equal(st.shownCount, 2);
  assert.equal(st.origin, 'https://a.test');
});

test('短窗口超过突发上限即抑制并进入冷却', () => {
  const st = createDialogState(T0);
  const decisions = [];
  for (let i = 0;i < DIALOG_BURST_LIMIT + 1; i++) {
    decisions.push(decideDialog(st, { type: 'alert', message: `m${i}` }, T0 + 100 * (i + 1)).decision);
  }
  for (let i = 0;i < DIALOG_BURST_LIMIT;i++) assert.equal(decisions[i], DIALOG_SHOW);
  assert.equal(decisions[DIALOG_BURST_LIMIT], DIALOG_SUPPRESS);
  assert.equal(inCooldown(st, T0 + 300), true);

  const during = decideDialog(st, { type: 'prompt', message: 'x' }, T0 + 400);
  assert.equal(during.decision, DIALOG_SUPPRESS);
  assert.equal(during.reason, SUPPRESS_COOLDOWN);
});

test('冷却结束后配额随滑动窗口恢复', () => {
  const st = createDialogState(T0);
  for (let i = 0;i < DIALOG_BURST_LIMIT + 1; i++) {
    decideDialog(st, { type: 'alert', message: `m${i}` }, T0 + 100 * (i + 1));
  }
  resetCooldown(st);
  // 时间推进超过长窗口，窗口内无历史请求。
  const r = decideDialog(st, { type: 'alert', message: 'fresh' }, T0 + DIALOG_LONG_WINDOW_MS + 1000);
  assert.equal(r.decision, DIALOG_SHOW);
  assert.equal(r.longCount, 1);
});

test('相同文案在去抖窗口内重复被合并拦截', () => {
  const st = createDialogState(T0);
  const r1 = decideDialog(st, { type: 'confirm', message: '相同文案' }, T0 + 10);
  const r2 = decideDialog(st, { type: 'confirm', message: '相同文案' }, T0 + 10 + DIALOG_DUP_MS - 100);
  assert.equal(r1.decision, DIALOG_SHOW);
  assert.equal(r2.decision, DIALOG_SUPPRESS);
  assert.equal(r2.reason, SUPPRESS_DUPLICATE);

  // 超过去抖窗口后同文案不再按重复拦截。
  const r3 = decideDialog(st, { type: 'confirm', message: '相同文案' }, T0 + 10 + DIALOG_DUP_MS + 200);
  assert.notEqual(r3.reason, SUPPRESS_DUPLICATE);
});

test('不同类型的同文案不被误判为重复', () => {
  const st = createDialogState(T0);
  decideDialog(st, { type: 'alert', message: 'm' }, T0 + 10);
  const r = decideDialog(st, { type: 'confirm', message: 'm' }, T0 + 20);
  assert.notEqual(r.reason, SUPPRESS_DUPLICATE);
});

test('beforeunload 与未知类型不计数直接放行', () => {
  const st = createDialogState(T0);
  const r1 = decideDialog(st, { type: 'beforeunload', message: 'leave?' }, T0 + 10);
  const r2 = decideDialog(st, { type: 'something-else' }, T0 + 20);
  assert.equal(r1.decision, DIALOG_SHOW);
  assert.equal(r2.decision, DIALOG_SHOW);
  assert.equal(st.requestTimes.length, 0);
});

test('长窗口低频持续弹窗越限走长窗口原因', () => {
  const st = createDialogState(T0);
  let last;
  // 间隔 6s：始终在长窗口 60s 内累积，短窗口 10s 内每次只有 1~2 个，
  // 因此触发的是长窗口上限而不是突发上限。
  for (let i = 0;i < 12;i++) {
    last = decideDialog(st, { type: 'alert', message: `m${i}` }, T0 + 6_000 * (i + 1));
  }
  assert.equal(last.decision, DIALOG_SUPPRESS);
  assert.ok(last.reason === SUPPRESS_LONG || last.reason === SUPPRESS_COOLDOWN,
    `期望长窗口/冷却原因，得到 ${last.reason}`);
});

test('无状态对象调用安全拒绝', () => {
  const r = decideDialog(null, { type: 'alert' }, T0);
  assert.equal(r.decision, DIALOG_SUPPRESS);
});

test('原因描述均为可读中文', () => {
  for (const reason of [SUPPRESS_BURST, SUPPRESS_LONG, SUPPRESS_COOLDOWN, SUPPRESS_DUPLICATE, SUPPRESS_MALFORMED]) {
    assert.ok(describeDialogReason(reason).length > 0);
  }
});
