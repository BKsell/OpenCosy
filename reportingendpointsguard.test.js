'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./reportingendpointsguard');

function h(value) {
  return { 'reporting-endpoints': [value] };
}

test('缺头不改动', () => {
  const r = guard.applyReportingEndpointsGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合规端点不改动', () => {
  const headers = h('default="https://reports.example.com/csp"');
  const r = guard.applyReportingEndpointsGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('明文端点被剔除', () => {
  const headers = h('default="http://reports.example.com/csp", backup="https://reports.example.com/b"');
  const r = guard.applyReportingEndpointsGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.INSECURE);
  assert.strictEqual(headers['reporting-endpoints'], 'backup="https://reports.example.com/b"');
});

test('畸形条目被剔除', () => {
  const headers = h('default=https://reports.example.com, bad entry');
  const r = guard.applyReportingEndpointsGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_ENTRY);
});

test('端点过多整体删除', () => {
  const headers = h(Array.from({ length: 10 }, (_, i) => 'e' + i + '="https://r.example.com"').join(','));
  const r = guard.applyReportingEndpointsGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers['reporting-endpoints'], undefined);
});

test('超长头删除', () => {
  const headers = h('default="https://r.example.com/' + 'a'.repeat(1200) + '"');
  const r = guard.applyReportingEndpointsGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});
