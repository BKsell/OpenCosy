'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./secfetchsiteguard');

test('缺头不改动', () => {
  const r = guard.applySecFetchSiteGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合规取值不改动', () => {
  const headers = {
    'sec-fetch-site': 'cross-site',
    'sec-fetch-mode': 'cors',
    'sec-fetch-dest': 'script',
  };
  const r = guard.applySecFetchSiteGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('非法站点取值删除', () => {
  const headers = { 'sec-fetch-site': 'cross-origin' };
  const r = guard.applySecFetchSiteGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
  assert.strictEqual(headers['sec-fetch-site'], undefined);
});

test('非法模式删除', () => {
  const headers = { 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'prefetch' };
  const r = guard.applySecFetchSiteGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['sec-fetch-mode'], undefined);
});

test('none 与访问模式矛盾时删除站点', () => {
  const headers = { 'sec-fetch-site': 'none', 'sec-fetch-mode': 'cors' };
  const r = guard.applySecFetchSiteGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.INCONSISTENT);
  assert.strictEqual(headers['sec-fetch-site'], undefined);
});

test('法制目标类型非法删除', () => {
  const headers = { 'sec-fetch-site': 'same-site', 'sec-fetch-dest': 'hologram' };
  const r = guard.applySecFetchSiteGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['sec-fetch-dest'], undefined);
});
