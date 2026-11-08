'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./warningheaderguard');

const NOW = Date.UTC(2026, 10, 7, 8, 0, 0);

function h(value) {
  return { Warning: value };
}

test('合法警告条目不改动', () => {
  const stamp = new Date(NOW - 3600000).toUTCString();
  const headers = h(`110 proxy "response stale" "${stamp}"`);
  const r = guard.applyWarningHeaderGuard(headers, NOW);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(r.entries.length, 1);
});

test('缺少 Warning 返回 missing', () => {
  const r = guard.applyWarningHeaderGuard({}, NOW);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
  assert.strictEqual(r.changed, false);
});

test('无状态码被剥除', () => {
  const headers = h('proxy "stale"');
  const r = guard.applyWarningHeaderGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers.Warning, undefined);
});

test('未登记状态码被剥除', () => {
  const headers = h('199 proxy "misc"');
  const r = guard.applyWarningHeaderGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('未登记四位数状态码被剥除', () => {
  const headers = h('410 proxy "gone"');
  const r = guard.applyWarningHeaderGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('5xx 不在白名单被剥除', () => {
  const headers = h('500 proxy "boom"');
  const r = guard.applyWarningHeaderGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('200 不在白名单', () => {
  const headers = h('200 proxy "ok"');
  const r = guard.applyWarningHeaderGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('缺少引号被剥除', () => {
  const headers = h('110 proxy response');
  const r = guard.applyWarningHeaderGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('超长条目被剥除', () => {
  const headers = h(`110 proxy "${'x'.repeat(guard.MAX_ENTRY_LENGTH + 10)}"`);
  const r = guard.applyWarningHeaderGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});

test('条目过多被剥除', () => {
  const entry = '110 proxy "stale"';
  const headers = h(new Array(guard.MAX_ENTRIES + 2).fill(entry).join(', '));
  const r = guard.applyWarningHeaderGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers.Warning, undefined);
});

test('日期过旧被剥除', () => {
  const old = new Date(NOW - 5 * 86400000).toUTCString();
  const headers = h(`110 proxy "stale" "${old}"`);
  const r = guard.applyWarningHeaderGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.STALE_DATE);
});

test('日期在未来被剥除', () => {
  const future = new Date(NOW + 5 * 86400000).toUTCString();
  const headers = h(`110 proxy "stale" "${future}"`);
  const r = guard.applyWarningHeaderGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.STALE_DATE);
});

test('逗号包裹在引号内不拆分', () => {
  const headers = h('110 proxy "a, b"');
  const r = guard.applyWarningHeaderGuard(headers, NOW);
  assert.strictEqual(r.entries.length, 1);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('多个合法条目保留', () => {
  const headers = h('110 proxy "stale", 214 proxy "transformed"');
  const r = guard.applyWarningHeaderGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(r.entries.length, 2);
});

test('数组形式逐项合并', () => {
  const headers = { Warning: ['110 proxy "stale"', '214 proxy "transformed"'] };
  const r = guard.applyWarningHeaderGuard(headers, NOW);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(r.entries.length, 2);
});

test('小写键名命中并被剥除', () => {
  const headers = { warning: '500 proxy "boom"' };
  const r = guard.applyWarningHeaderGuard(headers, NOW);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers.warning, undefined);
});

test('describeReason 覆盖分支', () => {
  assert.match(guard.describeReason(guard.REASON.MALFORMED), /RFC 7234/);
  assert.match(guard.describeReason(guard.REASON.OVERLONG), /长度/);
  assert.match(guard.describeReason(guard.REASON.TOO_MANY), /数量/);
  assert.match(guard.describeReason(guard.REASON.PSEUDO_CODE), /伪状态码/);
  assert.match(guard.describeReason(guard.REASON.STALE_DATE), /日期/);
  assert.match(guard.describeReason(guard.REASON.OK), /通过/);
});
