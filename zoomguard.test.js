'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  ZOOM_MIN_LEVEL,
  ZOOM_MAX_LEVEL,
  ZOOM_DEFAULT_LEVEL,
  ZOOM_BROADCAST_MIN_INTERVAL_MS,
  ZOOM_CHANGE_WINDOW_MS,
  ZOOM_CHANGE_LIMIT,
  ACTION_BROADCAST,
  ACTION_HOLD,
  HOLD_SAME_LEVEL,
  HOLD_TOO_FAST,
  HOLD_FLOODED,
  HOLD_BAD_STATE,
  clampZoomLevel,
  zoomLevelToPercent,
  createZoomState,
  applyZoomChange,
  flushPendingZoom,
  describeHoldReason,
} = require('./zoomguard');

const T0 = 7_000_000;

test('clampZoomLevel 钳制越界与非法输入，并量化到 0.5 级', () => {
  assert.equal(clampZoomLevel(100), ZOOM_MAX_LEVEL);
  assert.equal(clampZoomLevel(-100), ZOOM_MIN_LEVEL);
  assert.equal(clampZoomLevel(ZOOM_MIN_LEVEL), ZOOM_MIN_LEVEL);
  assert.equal(clampZoomLevel(ZOOM_MAX_LEVEL), ZOOM_MAX_LEVEL);
  assert.equal(clampZoomLevel(NaN), ZOOM_DEFAULT_LEVEL);
  assert.equal(clampZoomLevel(Infinity), ZOOM_DEFAULT_LEVEL);
  assert.equal(clampZoomLevel(-Infinity), ZOOM_DEFAULT_LEVEL);
  assert.equal(clampZoomLevel(undefined), ZOOM_DEFAULT_LEVEL);
  assert.equal(clampZoomLevel('3.2'), ZOOM_DEFAULT_LEVEL); // 非数值回退默认
  assert.equal(clampZoomLevel(3.3), 3.5);
  assert.equal(clampZoomLevel(3.8), 4);
});

test('zoomLevelToPercent 单调且 0 级为 100%', () => {
  assert.equal(zoomLevelToPercent(0), 100);
  assert.ok(zoomLevelToPercent(1) > 100);
  assert.ok(zoomLevelToPercent(-1) < 100);
  assert.ok(zoomLevelToPercent(ZOOM_MAX_LEVEL) > zoomLevelToPercent(ZOOM_MIN_LEVEL));
});

test('首次变化立即广播', () => {
  const st = createZoomState(T0);
  const r = applyZoomChange(st, { level: 2 }, T0 + 10);
  assert.equal(r.action, ACTION_BROADCAST);
  assert.equal(r.level, 2);
  assert.equal(r.percent, zoomLevelToPercent(2));
  assert.equal(st.lastBroadcastLevel, 2);
});

test('相同级别不重复广播', () => {
  const st = createZoomState(T0);
  applyZoomChange(st, { level: 1 }, T0 + 10);
  const r = applyZoomChange(st, { level: 1 }, T0 + 5000);
  assert.equal(r.action, ACTION_HOLD);
  assert.equal(r.reason, HOLD_SAME_LEVEL);
});

test('亚像素抖动量化后视为同级，不广播', () => {
  const st = createZoomState(T0);
  applyZoomChange(st, { level: 2 }, T0 + 10);
  const r = applyZoomChange(st, { level: 2.05 }, T0 + 5000);
  assert.equal(r.action, ACTION_HOLD);
  assert.equal(r.reason, HOLD_SAME_LEVEL);
  assert.equal(st.level, 2);
});

test('广播间隔过短先 hold，平息后 flush 补发最终级别', () => {
  const st = createZoomState(T0);
  applyZoomChange(st, { level: 1 }, T0);
  // 间隔小于最小广播间隔：hold（级别不同且未洪泛）。
  const fast = applyZoomChange(st, { level: 2 }, T0 + 10);
  assert.equal(fast.action, ACTION_HOLD);
  assert.equal(fast.reason, HOLD_TOO_FAST);
  assert.equal(st.level, 2);
  assert.equal(st.lastBroadcastLevel, 1); // 尚未广播 2
  // 间隔足够后 flush 应补发 2。
  const flush = flushPendingZoom(st, T0 + ZOOM_BROADCAST_MIN_INTERVAL_MS + 1);
  assert.equal(flush.action, ACTION_BROADCAST);
  assert.equal(flush.level, 2);
  assert.equal(st.lastBroadcastLevel, 2);
  // 再次 flush 无新变化。
  const again = flushPendingZoom(st, T0 + ZOOM_BROADCAST_MIN_INTERVAL_MS + 100);
  assert.equal(again.action, ACTION_HOLD);
});

test('滑动窗口内级别变化洪泛时暂停广播', () => {
  const st = createZoomState(T0);
  applyZoomChange(st, { level: -1 }, T0); // 首次广播，lastBroadcastAt=T0
  let sawFlood = false;
  let lastT = T0;
  // 在远小于最小广播间隔（60ms）的时间内，以 1ms 步长塞入超过窗口上限的原始变化。
  // 这些事件全部命中 TOO_FAST 而不更新 lastBroadcastLevel（故 3/4 始终 != -1），
 // 但时间戳照常计入窗口，第 41+ 个时应判定洪泛。
  for (let i = 0; i < ZOOM_CHANGE_LIMIT + 5; i++) {
    lastT = T0 + 1 + i;
    const level = (i % 2 === 0 ? 3 : 4);
    const r = applyZoomChange(st, { level }, lastT);
    if (r.flooded && r.reason === HOLD_FLOODED) sawFlood = true;
  }
  assert.ok(sawFlood, '应出现洪泛 hold');
  // 窗口滑过且超过广播间隔后 flush 可恢复广播最终级别。
  const later = lastT + ZOOM_CHANGE_WINDOW_MS + ZOOM_BROADCAST_MIN_INTERVAL_MS + 1;
  const flush = flushPendingZoom(st, later);
  assert.equal(flush.action, ACTION_BROADCAST);
});

test('缺少状态对象安全失败', () => {
  const r = applyZoomChange(null, { level: 5 }, T0);
  assert.equal(r.action, ACTION_HOLD);
  assert.equal(r.reason, HOLD_BAD_STATE);
  assert.equal(flushPendingZoom(null, T0).action, ACTION_HOLD);
});

test('hold 原因均有中文说明', () => {
  for (const reason of [HOLD_SAME_LEVEL, HOLD_TOO_FAST, HOLD_FLOODED, HOLD_BAD_STATE]) {
    assert.ok(describeHoldReason(reason).length > 0, `${reason} 缺说明`);
  }
  assert.ok(describeHoldReason('x').length > 0);
});
