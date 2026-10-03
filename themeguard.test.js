'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  THEME_ACCEPT,
  THEME_HOLD,
  THEME_DROP,
  HOLD_NO_CHANGE,
  HOLD_TOO_SOON,
  DROP_BAD_COLOR,
  DROP_FLOOD,
  DROP_COOLDOWN,
  THEME_BURST_LIMIT,
  THEME_LONG_WINDOW_MS,
  normalizeThemeColor,
  createThemeState,
  resetForNavigation,
  decideThemeColor,
  describeThemeReason,
} = require('./themeguard');

const T0 = 10_000_000;

test('合法 hex 与 rgb()/rgba() 颜色通过，大小写归一', () => {
  for (const c of ['#fff', '#102030', '#102030ff', 'rgb(1,2,3)', 'rgba(0, 255, 128, 0.5)']) {
    assert.equal(normalizeThemeColor(c).ok, true, c);
  }
  assert.equal(normalizeThemeColor('#AABBCC').color, '#aabbcc');
});

test('非法颜色表达式被拒绝', () => {
  for (const bad of ['red', 'hsl(1,2%,3%)', 'calc(1px)', 'rgb(256,0,0)', 'rgba(0,0,0,2)', '#gggggg', '#12', '']) {
    if (bad === '') {
      assert.equal(normalizeThemeColor(bad).empty, true);
    } else {
      assert.equal(normalizeThemeColor(bad).ok, false, bad);
    }
  }
});

test('非字符串与超长颜色拒绝；控制字符被剥离后再判', () => {
  assert.equal(normalizeThemeColor(42).ok, false);
  assert.equal(normalizeThemeColor('#' + 'a'.repeat(100)).ok, false);
  assert.equal(normalizeThemeColor('#ab\x00cd').color, '#abcd');
});

test('同值与最小间隔内变更被软合并', () => {
  const st = createThemeState(T0);
  assert.equal(decideThemeColor(st, '#ff0000', T0).action, THEME_ACCEPT);
  assert.equal(decideThemeColor(st, '#ff0000', T0 + 50).reason, HOLD_NO_CHANGE);
  const soon = decideThemeColor(st, '#00ff00', T0 + 100);
  assert.equal(soon.action, THEME_HOLD);
  assert.equal(soon.reason, HOLD_TOO_SOON);
  assert.equal(decideThemeColor(st, '#00ff00', T0 + 500).action, THEME_ACCEPT);
});

test('空串恢复默认顶栏，重复空串合并', () => {
  const st = createThemeState(T0);
  assert.equal(decideThemeColor(st, '#fff', T0).color, '#fff');
  assert.equal(decideThemeColor(st, '', T0 + 300).action, THEME_ACCEPT);
  assert.equal(decideThemeColor(st, '', T0 + 400).action, THEME_HOLD);
});

test('高频闪烁越限后进入冷却，普通配色被丢弃', () => {
  const st = createThemeState(T0);
  let last;
  for (let i = 0; i < THEME_BURST_LIMIT + 1; i++) {
    last = decideThemeColor(st, '#' + ((1 << 20) + i).toString(16).padStart(6, '0'), T0 + 30 * i);
  }
  assert.equal(last.action, THEME_DROP);
  assert.ok(last.reason === DROP_FLOOD || last.reason === DROP_COOLDOWN);
  assert.ok(last.cooldownUntil > T0);
  const cooled = decideThemeColor(st, '#123456', T0 + 200);
  assert.equal(cooled.action, THEME_DROP);
  assert.equal(cooled.reason, DROP_COOLDOWN);
});

test('冷却期内空串仍放行，顶栏不被恶意配色粘住', () => {
  const st = createThemeState(T0);
  for (let i = 0; i < THEME_BURST_LIMIT + 1; i++) {
    decideThemeColor(st, '#' + ((1 << 20) + i).toString(16).padStart(6, '0'), T0 + 30 * i);
  }
  const clear = decideThemeColor(st, '', T0 + 200);
  assert.equal(clear.action, THEME_ACCEPT);
  assert.equal(clear.color, '');
});

test('长窗口外旧事件被修剪', () => {
  const st = createThemeState(T0);
  // 间隔 400ms 且每次颜色不同（超过 200ms 最小间隔），30 次跨 12s，
  // 期间滑窗会持续剔除 10s 外的旧事件，但任何时刻窗口内不超过 26 条 < 60 长上限。
  for (let i = 0; i < 30; i++) {
    const r = decideThemeColor(st, '#' + ((1 << 20) + i).toString(16).padStart(6, '0'), T0 + 400 * (i + 1));
    assert.notEqual(r.action, THEME_DROP);
  }
  assert.ok(st.times.length < 30);
  const r = decideThemeColor(st, '#abcdef', T0 + 400 * 30 + THEME_LONG_WINDOW_MS + 10);
  assert.equal(r.action, THEME_ACCEPT);
  assert.equal(r.longCount, 1);
});

test('主导航重置后恢复接受', () => {
  const st = createThemeState(T0);
  for (let i = 0; i < THEME_BURST_LIMIT + 1; i++) {
    decideThemeColor(st, '#' + ((1 << 20) + i).toString(16).padStart(6, '0'), T0 + 30 * i);
  }
  assert.equal(decideThemeColor(st, '#000', T0 + 500).action, THEME_DROP);
  resetForNavigation(st);
  assert.equal(decideThemeColor(st, '#000', T0 + 999_000).action, THEME_ACCEPT);
});

test('原因描述可读', () => {
  for (const reason of [HOLD_NO_CHANGE, HOLD_TOO_SOON, DROP_BAD_COLOR, DROP_FLOOD, DROP_COOLDOWN]) {
    assert.ok(describeThemeReason(reason).length > 0);
  }
});
