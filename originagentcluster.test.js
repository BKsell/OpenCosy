'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./originagentcluster');

function h(value) {
  return { 'Origin-Agent-Cluster': value };
}

test('严格取值不改动', () => {
  const headers = h('?1');
  const r = guard.applyOriginAgentClusterGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(headers['Origin-Agent-Cluster'], '?1');
});

test('缺少头时返回 missing', () => {
  const r = guard.applyOriginAgentClusterGuard({});
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('空对象不报错', () => {
  const r = guard.applyOriginAgentClusterGuard({});
  assert.strictEqual(r.strict, null);
});

test('放开取值被收紧为 ?1', () => {
  const headers = h('?0');
  const r = guard.applyOriginAgentClusterGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.TIGHTENED);
  assert.strictEqual(headers['Origin-Agent-Cluster'], '?1');
});

test('小写键名同样命中', () => {
  const headers = { 'origin-agent-cluster': '?0' };
  const r = guard.applyOriginAgentClusterGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['origin-agent-cluster'], '?1');
});

test('裸 1 视为非法并收紧', () => {
  const headers = h('1');
  const r = guard.applyOriginAgentClusterGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['Origin-Agent-Cluster'], '?1');
});

test('裸 0 视为非法并收紧', () => {
  const headers = h('0');
  const r = guard.applyOriginAgentClusterGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['Origin-Agent-Cluster'], '?1');
});

test('超长取值视为非法', () => {
  const headers = h('?1'.repeat(20));
  const r = guard.applyOriginAgentClusterGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('数组取值取首项', () => {
  const headers = { 'Origin-Agent-Cluster': ['?1', '?0'] };
  const r = guard.applyOriginAgentClusterGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('非法数组首项被收紧', () => {
  const headers = { 'Origin-Agent-Cluster': ['nonsense', '?1'] };
  const r = guard.applyOriginAgentClusterGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers['Origin-Agent-Cluster'], guard.STRICT);
});

test('parseOriginAgentCluster 直接判定', () => {
  assert.strictEqual(guard.parseOriginAgentCluster('?1').reason, guard.REASON.OK);
  assert.strictEqual(guard.parseOriginAgentCluster('?0').reason, guard.REASON.LENIENT);
  assert.strictEqual(guard.parseOriginAgentCluster('').reason, guard.REASON.MALFORMED);
});

test('describeReason 覆盖各分支', () => {
  assert.match(guard.describeReason(guard.REASON.MISSING), /缺少/);
  assert.match(guard.describeReason(guard.REASON.MALFORMED), /非法/);
  assert.match(guard.describeReason(guard.REASON.TIGHTENED), /放开/);
  assert.match(guard.describeReason(guard.REASON.OK), /同源隔离/);
});
