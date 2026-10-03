'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  KEYBOARD_ALLOW,
  KEYBOARD_DENY,
  DENY_NOT_FULLSCREEN,
  DENY_RATE_LIMITED,
  DENY_BAD_STATE,
  ABUSE_FLICKER,
  KEYBOARD_LOCK_WINDOW_MS,
  KEYBOARD_LOCK_LIMIT,
  FULLSCREEN_SWITCH_WINDOW_MS,
  FULLSCREEN_SWITCH_LIMIT,
  originFromUrl,
  createFullscreenState,
  noteEnter,
  noteLeave,
  currentSwitchRate,
  decideKeyboardLock,
  noteKeyboardUnlock,
  describeKeyboardReason,
  describeAbuse,
} = require('./fullscreenguard');

const T0 = 1_000_000;

test('originFromUrl 归一与畸形回退', () => {
  assert.equal(originFromUrl('https://a.test:8443/x'), 'https://a.test:8443');
  assert.equal(originFromUrl('http://a.test'), 'http://a.test');
  assert.equal(originFromUrl(''), '');
  assert.equal(originFromUrl('not a url'), '');
  assert.equal(originFromUrl(undefined), '');
});

test('窗口态请求键盘锁一律拒绝，全屏态放行', () => {
  const st = createFullscreenState(T0);
  // 初始窗口态。
  const w = decideKeyboardLock(st, { originUrl: 'https://evil.test/' }, T0 + 1);
  assert.equal(w.decision, KEYBOARD_DENY);
  assert.equal(w.reason, DENY_NOT_FULLSCREEN);
  assert.equal(w.origin, 'https://evil.test');
  assert.equal(st.deniedLockCount, 1);
  assert.equal(st.keyboardLocked, false);

  // 进入全屏后请求应放行。
  noteEnter(st, T0 + 10, 'https://ok.test/game');
  const f = decideKeyboardLock(st, { originUrl: 'https://ok.test/game' }, T0 + 20);
  assert.equal(f.decision, KEYBOARD_ALLOW);
  assert.equal(f.reason, '');
  assert.equal(st.keyboardLocked, true);
});

test('显式 fullscreen 入参覆盖状态（防御调用方传错）', () => {
  const st = createFullscreenState(T0);
  // 状态是窗口态，但显式声明全屏：以入参为准仍受限速；这里第一次放行。
  const r = decideKeyboardLock(st, { fullscreen: true }, T0 + 5);
  assert.equal(r.decision, KEYBOARD_ALLOW);
  // 状态里是全屏，但显式声明非全屏：拒绝。
  const st2 = createFullscreenState(T0);
  noteEnter(st2, T0, 'https://g.test');
  const r2 = decideKeyboardLock(st2, { fullscreen: false }, T0 + 5);
  assert.equal(r2.decision, KEYBOARD_DENY);
  assert.equal(r2.reason, DENY_NOT_FULLSCREEN);
});

test('键盘锁滑动窗口限速：窗口内超过上限即拒，窗口滑过后恢复', () => {
  const st = createFullscreenState(T0);
  noteEnter(st, T0, 'https://g.test');
  const decisions = [];
  for (let i = 0; i < KEYBOARD_LOCK_LIMIT + 2; i++) {
    decisions.push(decideKeyboardLock(st, {}, T0 + 100 * (i + 1)).decision);
  }
  // 前 LIMIT 次放行，之后拒绝。
  for (let i = 0; i < KEYBOARD_LOCK_LIMIT; i++) {
    assert.equal(decisions[i], KEYBOARD_ALLOW, `第 ${i + 1} 次应放行`);
  }
  assert.equal(decisions[KEYBOARD_LOCK_LIMIT], KEYBOARD_DENY);
  assert.equal(decisions[KEYBOARD_LOCK_LIMIT + 1], KEYBOARD_DENY);

  // 时间窗滑过后，计数被裁剪，可再次放行。
  const later = T0 + 100 * (KEYBOARD_LOCK_LIMIT + 2) + KEYBOARD_LOCK_WINDOW_MS + 1;
  const recovered = decideKeyboardLock(st, {}, later);
  assert.equal(recovered.decision, KEYBOARD_ALLOW);
  assert.equal(recovered.requestCount, 1);
});

test('被拒请求也计入限速，防止“拒绝后无限重试”绕过', () => {
  const st = createFullscreenState(T0);
  // 不进入全屏，连续狂请求：每次都因非全屏被拒，但时间戳仍累积。
  for (let i = 0; i < KEYBOARD_LOCK_LIMIT + 1; i++) {
    decideKeyboardLock(st, {}, T0 + i);
  }
  noteEnter(st, T0 + 1000, 'https://g.test');
  // 进入全屏后立刻请求：窗口内已累积 >LIMIT 次请求，应命中限速而非放行。
  const r = decideKeyboardLock(st, {}, T0 + 1001);
  assert.equal(r.decision, KEYBOARD_DENY);
  assert.equal(r.reason, DENY_RATE_LIMITED);
});

test('缺少状态对象时安全失败', () => {
  const r = decideKeyboardLock(null, {}, T0);
  assert.equal(r.decision, KEYBOARD_DENY);
  assert.equal(r.reason, DENY_BAD_STATE);
  assert.doesNotThrow(() => { noteEnter(null, T0); noteLeave(null, T0); });
});

test('退出全屏复位键盘锁标记', () => {
  const st = createFullscreenState(T0);
  noteEnter(st, T0, 'https://g.test');
  decideKeyboardLock(st, {}, T0 + 1);
  assert.equal(st.keyboardLocked, true);
  noteLeave(st, T0 + 2);
  assert.equal(st.keyboardLocked, false);
  assert.equal(st.fullscreen, false);
  noteKeyboardUnlock(st);
  assert.equal(st.keyboardLocked, false);
});

test('全屏高频进出触发抖动判定，且一个窗口只报一次', () => {
  const st = createFullscreenState(T0);
  let abuses = 0;
  let t = T0;
  // 交替 enter/leave，制造超过阈值的切换。
  for (let i = 0; i < FULLSCREEN_SWITCH_LIMIT + 2; i++) {
    t += 10;
    const r = i % 2 === 0 ? noteEnter(st, t, 'https://fx.test') : noteLeave(st, t);
    if (r.abusive) abuses += 1;
  }
  assert.ok(abuses >= 1, '应至少判定一次抖动');
  // 紧接着的更多切换不应在同一窗口重复上报。
  const before = abuses;
  for (let i = 0; i < 4; i++) {
    t += 10;
    const r = i % 2 === 0 ? noteEnter(st, t) : noteLeave(st, t);
    if (r.abusive) abuses += 1;
  }
  assert.equal(abuses, before, '同一时间窗不重复上报抖动');
  assert.ok(currentSwitchRate(st, t) <= FULLSCREEN_SWITCH_LIMIT + 6);
});

test('正常频率的全屏切换不触发抖动', () => {
  const st = createFullscreenState(T0);
  let t = T0;
  let abuses = 0;
  // 每次切换间隔超过窗口，窗口内永远只有 1 次。
  for (let i = 0; i < 20; i++) {
    t += FULLSCREEN_SWITCH_WINDOW_MS + 1;
    const r = i % 2 === 0 ? noteEnter(st, t) : noteLeave(st, t);
    if (r.abusive) abuses += 1;
  }
  assert.equal(abuses, 0);
  assert.equal(currentSwitchRate(st, t), 1);
});

test('currentSwitchRate 会裁剪过期时间戳', () => {
  const st = createFullscreenState(T0);
  noteEnter(st, T0, 'https://a.test');
  noteLeave(st, T0 + 5);
  assert.equal(currentSwitchRate(st, T0 + 5), 2);
  const later = T0 + FULLSCREEN_SWITCH_WINDOW_MS + 100;
  assert.equal(currentSwitchRate(st, later), 0);
});

test('进入全屏记录来源与计数', () => {
  const st = createFullscreenState(T0);
  noteEnter(st, T0 + 1, 'https://game.test/p');
  assert.equal(st.fullscreen, true);
  assert.equal(st.origin, 'https://game.test');
  assert.equal(st.enterCount, 1);
  noteLeave(st, T0 + 2);
  assert.equal(st.leaveCount, 1);
  // 第二次进入更新来源。
  noteEnter(st, T0 + 3, 'https://other.test/');
  assert.equal(st.origin, 'https://other.test');
  assert.equal(st.enterCount, 2);
});

test('拒绝原因与滥用类型都有中文说明', () => {
  for (const reason of [DENY_NOT_FULLSCREEN, DENY_RATE_LIMITED, DENY_BAD_STATE]) {
    assert.ok(describeKeyboardReason(reason).length > 0, `${reason} 缺说明`);
  }
  assert.ok(describeAbuse(ABUSE_FLICKER).includes('全屏'));
  assert.ok(describeKeyboardReason('whatever').length > 0);
  assert.ok(describeAbuse('unknown').length > 0);
});
