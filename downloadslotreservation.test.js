'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createSlotReservation, REASON } = require('./downloadslotreservation');

test('首次占用成功', () => {
  const slots = createSlotReservation();
  const result = slots.reserve({ id: 'a', path: '/downloads/a.zip' });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.reason, REASON.OK);
});

test('同一路径二次占用被拒', () => {
  const slots = createSlotReservation();
  slots.reserve({ id: 'a', path: '/downloads/a.zip' });
  const second = slots.reserve({ id: 'b', path: '/downloads/a.zip' });
  assert.strictEqual(second.ok, false);
  assert.strictEqual(second.reason, REASON.TAKEN);
  assert.strictEqual(second.conflictingId, 'a');
});

test('同一 id 重复占用同一路径幂等', () => {
  const slots = createSlotReservation();
  slots.reserve({ id: 'a', path: '/downloads/a.zip' });
  const again = slots.reserve({ id: 'a', path: '/downloads/a.zip' });
  assert.strictEqual(again.ok, true);
});

test('大小写不同视为同一路径', () => {
  const slots = createSlotReservation({ caseInsensitive: true });
  slots.reserve({ id: 'a', path: '/downloads/A.zip' });
  const second = slots.reserve({ id: 'b', path: '/downloads/a.zip' });
  assert.strictEqual(second.reason, REASON.TAKEN);
});

test('区分大小写模式允许共存', () => {
  const slots = createSlotReservation({ caseInsensitive: false });
  slots.reserve({ id: 'a', path: '/downloads/A.zip' });
  const second = slots.reserve({ id: 'b', path: '/downloads/a.zip' });
  assert.strictEqual(second.ok, true);
});

test('路径归一化后仍判冲突', () => {
  const slots = createSlotReservation();
  slots.reserve({ id: 'a', path: '/downloads/sub/../a.zip' });
  const second = slots.reserve({ id: 'b', path: '/downloads/a.zip' });
  assert.strictEqual(second.reason, REASON.TAKEN);
});

test('相对路径拒绝', () => {
  const slots = createSlotReservation();
  const result = slots.reserve({ id: 'a', path: 'a.zip' });
  assert.strictEqual(result.reason, REASON.INVALID_PATH);
});

test('空路径拒绝', () => {
  const slots = createSlotReservation();
  const result = slots.reserve({ id: 'a', path: '' });
  assert.strictEqual(result.reason, REASON.INVALID_PATH);
});

test('空 id 拒绝', () => {
  const slots = createSlotReservation();
  const result = slots.reserve({ id: '', path: '/downloads/a.zip' });
  assert.strictEqual(result.reason, REASON.INVALID_ID);
});

test('释放后路径可重新占用', () => {
  const slots = createSlotReservation();
  slots.reserve({ id: 'a', path: '/downloads/a.zip' });
  assert.strictEqual(slots.release('a'), 1);
  const second = slots.reserve({ id: 'b', path: '/downloads/a.zip' });
  assert.strictEqual(second.ok, true);
});

test('releasePath 返回占用者 id', () => {
  const slots = createSlotReservation();
  slots.reserve({ id: 'a', path: '/downloads/a.zip' });
  assert.strictEqual(slots.releasePath('/downloads/a.zip'), 'a');
  assert.strictEqual(slots.size(), 0);
});

test('过期自动回收', () => {
  let clock = 1000;
  const slots = createSlotReservation({ ttlMs: 100, now: () => clock });
  slots.reserve({ id: 'a', path: '/downloads/a.zip' });
  clock += 200;
  assert.strictEqual(slots.size(), 0);
  const second = slots.reserve({ id: 'b', path: '/downloads/a.zip' });
  assert.strictEqual(second.ok, true);
});

test('快照按创建时间排序', () => {
  let clock = 1000;
  const slots = createSlotReservation({ now: () => clock });
  slots.reserve({ id: 'a', path: '/downloads/a.zip' });
  clock += 1;
  slots.reserve({ id: 'b', path: '/downloads/b.zip' });
  const list = slots.snapshot();
  assert.deepStrictEqual(list.map((item) => item.id), ['a', 'b']);
});

test('has 反映占用状态', () => {
  const slots = createSlotReservation();
  assert.strictEqual(slots.has('/downloads/a.zip'), false);
  slots.reserve({ id: 'a', path: '/downloads/a.zip' });
  assert.strictEqual(slots.has('/downloads/a.zip'), true);
});
