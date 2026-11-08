'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./attributionguard');

test('缺头不改动', () => {
  const r = guard.applyAttributionGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合规资格不改动', () => {
  const headers = { 'attribution-reporting-eligible': ['event-source, navigation'] };
  const r = guard.applyAttributionGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('未知资格被剔除', () => {
  const headers = { 'attribution-reporting-eligible': 'event-source, teleport' };
  const r = guard.applyAttributionGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_TOKEN);
  assert.strictEqual(headers['attribution-reporting-eligible'], 'event-source');
});

test('空资格删除', () => {
  const headers = { 'attribution-reporting-eligible': '' };
  const r = guard.applyAttributionGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
  assert.strictEqual(headers['attribution-reporting-eligible'], undefined);
});

test('非法注册键删除', () => {
  const headers = { 'attribution-reporting-registrable': 'bad key' };
  const r = guard.applyAttributionGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_TOKEN);
  assert.strictEqual(headers['attribution-reporting-registrable'], undefined);
});

test('注册键统一小写', () => {
  const headers = { 'attribution-reporting-registrable': 'Campaign_One' };
  const r = guard.applyAttributionGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['attribution-reporting-registrable'], 'campaign_one');
});
