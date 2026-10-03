'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  CURSOR_APPLY,
  CURSOR_HOLD,
  CURSOR_DROP,
  HOLD_SAME,
  HOLD_TOO_SOON,
  DROP_BAD_TYPE,
  DROP_BAD_IMAGE,
  DROP_BAD_SCALE,
  DROP_FLOOD,
  DROP_COOLDOWN,
  FALLBACK_TYPE,
  CURSOR_MAX_EDGE_PX,
  CURSOR_MAX_IMAGE_BYTES,
  CURSOR_MIN_INTERVAL_MS,
  CURSOR_BURST_LIMIT,
  CURSOR_LONG_WINDOW_MS,
  isValidType,
  validateCustomImage,
  isValidScale,
  createCursorState,
  resetForNavigation,
  decideCursorChange,
  describeCursorReason,
} = require('./cursorguard');

const T0 = 40_000_000;
const goodImg = { width: 32, height: 32, bytes: 2048 };

test('内置类型合法，未知类型拒绝并回落 default', () => {
  assert.equal(isValidType('pointer'), true);
  assert.equal(isValidType('bogus'), false);
  const st = createCursorState(T0);
  const r = decideCursorChange(st, 'bogus', null, 1, T0);
  assert.equal(r.action, CURSOR_DROP);
  assert.equal(r.reason, DROP_BAD_TYPE);
  assert.equal(r.type, FALLBACK_TYPE);
});

test('custom 类型必须带合规位图', () => {
  assert.equal(validateCustomImage(goodImg), true);
  assert.equal(validateCustomImage({ width: 0, height: 32, bytes: 1 }), false);
  assert.equal(validateCustomImage({ width: CURSOR_MAX_EDGE_PX + 1, height: 32, bytes: 1 }), false);
  assert.equal(validateCustomImage({ width: 32, height: 32, bytes: CURSOR_MAX_IMAGE_BYTES + 1 }), false);
  assert.equal(validateCustomImage(null), false);
  const st = createCursorState(T0);
  assert.equal(decideCursorChange(st, 'custom', { width: 99999, height: 9, bytes: 1 }, 1, T0).reason, DROP_BAD_IMAGE);
});

test('scale 越界拒绝', () => {
  assert.equal(isValidScale(1), true);
  assert.equal(isValidScale(0.1), false);
  assert.equal(isValidScale(10), false);
  assert.equal(isValidScale(NaN), false);
  const st = createCursorState(T0);
  assert.equal(decideCursorChange(st, 'pointer', null, 99, T0).reason, DROP_BAD_SCALE);
});

test('同类型与最小间隔内变更被软合并', () => {
  const st = createCursorState(T0);
  assert.equal(decideCursorChange(st, 'pointer', null, 1, T0).action, CURSOR_APPLY);
  assert.equal(decideCursorChange(st, 'pointer', null, 1, T0 + 5).reason, HOLD_SAME);
  const soon = decideCursorChange(st, 'text', null, 1, T0 + CURSOR_MIN_INTERVAL_MS - 2);
  assert.equal(soon.action, CURSOR_HOLD);
  assert.equal(soon.reason, HOLD_TOO_SOON);
  assert.equal(decideCursorChange(st, 'text', null, 1, T0 + 50).action, CURSOR_APPLY);
});

test('scale 缺省按 1 处理，合法 custom 可应用', () => {
  const st = createCursorState(T0);
  const r = decideCursorChange(st, 'custom', goodImg, undefined, T0);
  assert.equal(r.action, CURSOR_APPLY);
  assert.equal(r.type, 'custom');
});

test('高频抖动越限进入冷却并回落 default', () => {
  const st = createCursorState(T0);
  const types = ['pointer', 'text', 'move', 'wait', 'crosshair'];
  let last;
  for (let i = 0; i < CURSOR_BURST_LIMIT + 1; i++) {
    last = decideCursorChange(st, types[i % types.length], null, 1, T0 + i);
  }
  assert.equal(last.action, CURSOR_DROP);
  assert.ok(last.reason === DROP_FLOOD || last.reason === DROP_COOLDOWN);
  assert.equal(last.type, FALLBACK_TYPE);
  const cooled = decideCursorChange(st, 'pointer', null, 1, T0 + 500);
  assert.equal(cooled.action, CURSOR_DROP);
  assert.equal(cooled.reason, DROP_COOLDOWN);
});

test('冷却结束后恢复应用', () => {
  const st = createCursorState(T0);
  const types = ['pointer', 'text', 'move'];
  for (let i = 0; i < CURSOR_BURST_LIMIT + 1; i++) {
    decideCursorChange(st, types[i % 3], null, 1, T0 + i);
  }
  const r = decideCursorChange(st, 'pointer', null, 1, T0 + 10_000);
  assert.equal(r.action, CURSOR_APPLY);
});

test('长窗口外旧事件被修剪', () => {
  const st = createCursorState(T0);
  for (let i = 0; i < 200; i++) {
    const r = decideCursorChange(st, i % 2 ? 'pointer' : 'text', null, 1, T0 + 20 * (i + 1));
    assert.notEqual(r.action, CURSOR_DROP);
  }
  const r = decideCursorChange(st, 'wait', null, 1, T0 + 20 * 200 + CURSOR_LONG_WINDOW_MS + 10);
  assert.equal(r.action, CURSOR_APPLY);
  assert.equal(r.longCount, 1);
});

test('主导航重置冷却与状态', () => {
  const st = createCursorState(T0);
  const types = ['pointer', 'text', 'move'];
  for (let i = 0; i < CURSOR_BURST_LIMIT + 1; i++) {
    decideCursorChange(st, types[i % 3], null, 1, T0 + i);
  }
  resetForNavigation(st);
  assert.equal(decideCursorChange(st, 'pointer', null, 1, T0 + 500_000).action, CURSOR_APPLY);
});

test('原因描述可读', () => {
  for (const reason of [HOLD_SAME, HOLD_TOO_SOON, DROP_BAD_TYPE, DROP_BAD_IMAGE, DROP_BAD_SCALE, DROP_FLOOD, DROP_COOLDOWN]) {
    assert.ok(describeCursorReason(reason).length > 0);
  }
});
