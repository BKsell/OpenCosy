'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const ledgerModule = require('./permissiondenyledger');

test('首次记录放行写入', () => {
  const ledger = ledgerModule.createDenyLedger({ windowMs: 60000, maxPerKey: 3, now: () => 1000 });
  const result = ledger.record({ origin: 'https://a.test', permission: 'midi' });
  assert.equal(result.log, true);
  assert.equal(result.count, 1);
});

test('超过阈值后抑制重复日志', () => {
  const ledger = ledgerModule.createDenyLedger({ maxPerKey: 2, now: () => 500 });
  ledger.record({ origin: 'https://a.test', permission: 'midi' });
  ledger.record({ origin: 'https://a.test', permission: 'midi' });
  const third = ledger.record({ origin: 'https://a.test', permission: 'midi' });
  assert.equal(third.log, false);
  assert.equal(third.count, 3);
  assert.equal(third.suppressed, 1);
});

test('不同权限分别计数', () => {
  const ledger = ledgerModule.createDenyLedger({ maxPerKey: 1, now: () => 200 });
  assert.equal(ledger.record({ origin: 'https://a.test', permission: 'midi' }).log, true);
  assert.equal(ledger.record({ origin: 'https://a.test', permission: 'geolocation' }).log, true);
});

test('窗口过期后重新计数', () => {
  let clock = 0;
  const ledger = ledgerModule.createDenyLedger({ windowMs: 5000, maxPerKey: 1, now: () => clock });
  ledger.record({ origin: 'https://a.test', permission: 'midi' });
  clock = 6000;
  const fresh = ledger.record({ origin: 'https://a.test', permission: 'midi' });
  assert.equal(fresh.log, true);
  assert.equal(fresh.count, 1);
});

test('显式 now 覆盖时钟', () => {
  const ledger = ledgerModule.createDenyLedger({ windowMs: 1000, maxPerKey: 1, now: () => 0 });
  const result = ledger.record({ origin: 'https://a.test', permission: 'midi', now: 5000 });
  assert.equal(result.log, true);
});

test('摘要按次数排序并统计抑制量', () => {
  const ledger = ledgerModule.createDenyLedger({ maxPerKey: 2, now: () => 10 });
  for (let i = 0; i < 4; i += 1) ledger.record({ origin: 'https://a.test', permission: 'midi' });
  ledger.record({ origin: 'https://b.test', permission: 'usb' });
  const summary = ledger.summary();
  assert.equal(summary.total, 5);
  assert.equal(summary.suppressed, 2);
  assert.equal(summary.entries[0].key, 'https://a.test|midi');
});

test('超过键上限时淘汰最早条目', () => {
  const ledger = ledgerModule.createDenyLedger({ maxKeys: 2, now: () => 0 });
  ledger.record({ origin: 'https://a.test', permission: 'midi', now: 1 });
  ledger.record({ origin: 'https://b.test', permission: 'midi', now: 2 });
  ledger.record({ origin: 'https://c.test', permission: 'midi', now: 3 });
  const summary = ledger.summary();
  assert.equal(summary.keys, 2);
  assert.equal(summary.entries.some((entry) => entry.key === 'https://a.test|midi'), false);
});

test('reset 清空状态', () => {
  const ledger = ledgerModule.createDenyLedger({ now: () => 7 });
  ledger.record({ origin: 'https://a.test', permission: 'midi' });
  ledger.reset();
  const summary = ledger.summary();
  assert.equal(summary.total, 0);
  assert.equal(summary.keys, 0);
});

test('normalizeKey 统一大小写与空白', () => {
  assert.equal(ledgerModule.normalizeKey(' HTTPS://A.TEST ', ' MIDI '), 'https://a.test|midi');
  assert.equal(ledgerModule.normalizeKey('', ''), 'unknown-origin|unknown-permission');
});
