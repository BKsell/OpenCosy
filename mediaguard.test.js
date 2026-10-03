'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  MEDIA_STARTED,
  MEDIA_PAUSED,
  MEDIA_ACCEPT,
  MEDIA_HOLD,
  MEDIA_DROP,
  HOLD_REDUNDANT,
  HOLD_TOO_SOON,
  DROP_BAD_EVENT,
  DROP_FLOOD,
  DROP_COOLDOWN,
  MEDIA_BURST_LIMIT,
  MEDIA_LONG_WINDOW_MS,
  createMediaState,
  resetForNavigation,
  decideMediaEvent,
  describeMediaReason,
} = require('./mediaguard');

const T0 = 20_000_000;

test('真实翻转被接受并维护播放态', () => {
  const st = createMediaState(T0);
  const a = decideMediaEvent(st, MEDIA_STARTED, T0);
  assert.equal(a.action, MEDIA_ACCEPT);
  assert.equal(a.playing, true);
  const b = decideMediaEvent(st, MEDIA_PAUSED, T0 + 500);
  assert.equal(b.action, MEDIA_ACCEPT);
  assert.equal(b.playing, false);
});

test('同态重复事件被软合并', () => {
  const st = createMediaState(T0);
  decideMediaEvent(st, MEDIA_STARTED, T0);
  const r = decideMediaEvent(st, MEDIA_STARTED, T0 + 1_000);
  assert.equal(r.action, MEDIA_HOLD);
  assert.equal(r.reason, HOLD_REDUNDANT);
  assert.equal(r.playing, true);
});

test('翻转间隔过短被软节流', () => {
  const st = createMediaState(T0);
  decideMediaEvent(st, MEDIA_STARTED, T0);
  const fast = decideMediaEvent(st, MEDIA_PAUSED, T0 + 40);
  assert.equal(fast.action, MEDIA_HOLD);
  assert.equal(fast.reason, HOLD_TOO_SOON);
});

test('未知事件类型被丢弃', () => {
  const st = createMediaState(T0);
  const r = decideMediaEvent(st, 'seeking', T0 + 10);
  assert.equal(r.action, MEDIA_DROP);
  assert.equal(r.reason, DROP_BAD_EVENT);
});

test('高频翻转越限进入冷却并丢弃，冷却原因可区分', () => {
  const st = createMediaState(T0);
  let last;
  for (let i = 0; i < MEDIA_BURST_LIMIT + 1; i++) {
    last = decideMediaEvent(st, i % 2 === 0 ? MEDIA_STARTED : MEDIA_PAUSED, T0 + 10 * i);
  }
  assert.equal(last.action, MEDIA_DROP);
  assert.ok(last.reason === DROP_FLOOD || last.reason === DROP_COOLDOWN);
  assert.ok(last.cooldownUntil > T0);
  const cooled = decideMediaEvent(st, MEDIA_STARTED, T0 + 500);
  assert.equal(cooled.action, MEDIA_DROP);
  assert.equal(cooled.reason, DROP_COOLDOWN);
});

test('冷却结束后恢复接受', () => {
  const st = createMediaState(T0);
  for (let i = 0; i < MEDIA_BURST_LIMIT + 1; i++) {
    decideMediaEvent(st, i % 2 === 0 ? MEDIA_STARTED : MEDIA_PAUSED, T0 + 10 * i);
  }
  // 洪泛期间翻转都被节流，内核停在“播放中”，恢复后用相反事件触发真实翻转。
  const recovered = decideMediaEvent(st, MEDIA_PAUSED, T0 + 100_000);
  assert.equal(recovered.action, MEDIA_ACCEPT);
  assert.equal(recovered.playing, false);
});

test('长窗口外旧事件被修剪', () => {
  const st = createMediaState(T0);
  // 500ms 交替翻转：始终合法，10s 窗口内不超过 20 条 < 200。
  for (let i = 0; i < 60; i++) {
    const r = decideMediaEvent(st, i % 2 === 0 ? MEDIA_STARTED : MEDIA_PAUSED, T0 + 500 * (i + 1));
    assert.notEqual(r.action, MEDIA_DROP);
  }
  assert.ok(st.times.length < 60);
  const r = decideMediaEvent(st, MEDIA_STARTED, T0 + 500 * 60 + MEDIA_LONG_WINDOW_MS + 10);
  assert.equal(r.action, MEDIA_ACCEPT);
  assert.equal(r.longCount, 1);
});

test('主导航重置媒体态与冷却', () => {
  const st = createMediaState(T0);
  for (let i = 0; i < MEDIA_BURST_LIMIT + 1; i++) {
    decideMediaEvent(st, i % 2 === 0 ? MEDIA_STARTED : MEDIA_PAUSED, T0 + 10 * i);
  }
  resetForNavigation(st);
  const r = decideMediaEvent(st, MEDIA_STARTED, T0 + 9_000_000);
  assert.equal(r.action, MEDIA_ACCEPT);
  assert.equal(r.playing, true);
});

test('原因描述可读', () => {
  for (const reason of [HOLD_REDUNDANT, HOLD_TOO_SOON, DROP_BAD_EVENT, DROP_FLOOD, DROP_COOLDOWN]) {
    assert.ok(describeMediaReason(reason).length > 0);
  }
});
