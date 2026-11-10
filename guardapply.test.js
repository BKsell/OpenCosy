'use strict';
const test = require('node:test');
const assert = require('node:assert');
const {
  applyDeprecatedHeaderGuard,
  applyFindingsGuard,
  applyMemberListGuard,
  applyPinHeaderGuard,
  applySingleHeaderGuard,
} = require('./guardapply');

function headersOf(entries) {
  return entries;
}

test('single 内核命中即删对应键并保留 inspect 结果', () => {
  const headers = { 'x-frame-options': ['DENY'] };
  const inspect = () => ({ changed: true, reason: 'frame-options', verdict: 'deny' });
  const result = applySingleHeaderGuard(headers, 'x-frame-options', inspect);
  assert.strictEqual(result.verdict, 'deny');
  assert.deepStrictEqual(headers, {});
});

test('single 内核未变更时原样返回且不动头', () => {
  const headers = { 'x-frame-options': ['SAMEORIGIN'] };
  const inspect = () => ({ changed: false, reason: 'strict' });
  const result = applySingleHeaderGuard(headers, 'x-frame-options', inspect);
  assert.strictEqual(result.changed, false);
  assert.deepStrictEqual(headers, { 'x-frame-options': ['SAMEORIGIN'] });
});

test('single 内核先由 inspect 判定，未变更时不动头', () => {
  const headers = {};
  let called = 0;
  const inspect = () => { called += 1; return { changed: false, reason: 'missing' }; };
  const result = applySingleHeaderGuard(headers, 'x-frame-options', inspect);
  assert.strictEqual(called, 1);
  assert.strictEqual(result.changed, false);
  assert.strictEqual(result.reason, 'missing');
  assert.deepStrictEqual(headers, {});
});

test('pin 内核把命中键钉回固定值', () => {
  const headers = { 'origin-agent-cluster': ['?1'] };
  const inspect = () => ({ changed: true, reason: 'tightened', strict: true });
  applyPinHeaderGuard(headers, 'origin-agent-cluster', inspect, '?1');
  assert.deepStrictEqual(headers, { 'origin-agent-cluster': '?1' });
});

test('deprecated 内核删头并透传字段', () => {
  const headers = { 'x-expect-ct': ['max-age=0'] };
  const inspect = () => ({ changed: false, reason: 'deprecated', directives: ['max-age=0'] });
  const result = applyDeprecatedHeaderGuard(headers, 'x-expect-ct', inspect, {
    reason: 'deprecated',
    missingReason: 'missing',
    field: 'directives',
  });
  assert.deepStrictEqual(result, { changed: true, reason: 'deprecated', directives: ['max-age=0'] });
  assert.deepStrictEqual(headers, {});
});

test('deprecated 内核缺值时回空字段', () => {
  const headers = {};
  const result = applyDeprecatedHeaderGuard(headers, 'x-expect-ct', () => ({ changed: false }), {
    reason: 'deprecated',
    missingReason: 'missing',
    field: 'directives',
  });
  assert.deepStrictEqual(result, { changed: false, reason: 'missing', directives: [] });
});

test('member-list 内核按逗号重写命中头', () => {
  const headers = { 'accept-patch': ['application/foo', 'text/bar'] };
  const inspect = () => ({ reason: 'tightened', types: ['application/foo', 'text/bar'] });
  const result = applyMemberListGuard(headers, 'accept-patch', inspect, {
    okReason: 'ok',
    missingReason: 'missing',
    field: 'types',
    wrap: false,
  });
  assert.deepStrictEqual(result, { changed: true, reason: 'tightened', types: ['application/foo', 'text/bar'] });
  assert.deepStrictEqual(headers, { 'accept-patch': ['application/foo, text/bar'] });
});

test('member-list 内核空列表删头', () => {
  const headers = { 'accept-patch': ['bogus'] };
  const result = applyMemberListGuard(headers, 'accept-patch', () => ({ reason: 'malformed', types: [] }), {
    okReason: 'ok',
    missingReason: 'missing',
    field: 'types',
    wrap: false,
  });
  assert.strictEqual(result.changed, true);
  assert.deepStrictEqual(headers, {});
});

test('member-list 内核 okReason 早返回不改头', () => {
  const headers = { 'accept-patch': ['application/foo'] };
  const inspect = () => ({ reason: 'ok', types: ['application/foo'] });
  const result = applyMemberListGuard(headers, 'accept-patch', inspect, {
    okReason: 'ok',
    missingReason: 'missing',
    field: 'types',
    wrap: false,
  });
  assert.strictEqual(result.changed, false);
  assert.deepStrictEqual(headers, { 'accept-patch': ['application/foo'] });
});

test('member-list wrap 形态把判定收进 findings', () => {
  const headers = { 'cache-status': ['hit'] };
  const inspect = () => ({ reason: 'tightened', members: ['hit'] });
  const result = applyMemberListGuard(headers, 'cache-status', inspect, {
    okReason: 'ok',
    missingReason: 'missing',
    field: 'members',
    wrap: true,
  });
  assert.deepStrictEqual(result, {
    changed: true,
    reason: 'tightened',
    findings: [{ reason: 'tightened', members: ['hit'] }],
  });
  assert.deepStrictEqual(headers, { 'cache-status': ['hit'] });
});

test('findings 内核只带 reason 且始终删头', () => {
  const headers = { 'sec-websocket-accept': ['bad'] };
  const result = applyFindingsGuard(headers, 'sec-websocket-accept', () => ({ reason: 'malformed' }), {
    okReason: 'ok',
    missingReason: 'missing',
  });
  assert.deepStrictEqual(result, { changed: true, reason: 'malformed', findings: [{ reason: 'malformed' }] });
  assert.deepStrictEqual(headers, {});
});

test('findings 内核 okReason 保留头', () => {
  const headers = { 'sec-websocket-accept': ['good'] };
  const result = applyFindingsGuard(headers, 'sec-websocket-accept', () => ({ reason: 'ok' }), {
    okReason: 'ok',
    missingReason: 'missing',
  });
  assert.strictEqual(result.changed, false);
  assert.deepStrictEqual(result.findings, [{ reason: 'ok' }]);
  assert.deepStrictEqual(headers, { 'sec-websocket-accept': ['good'] });
});

test('头名大小写不敏感命中', () => {
  const headers = { 'X-Frame-Options': ['DENY'] };
  const result = applySingleHeaderGuard(headers, 'x-frame-options', () => ({ changed: true, reason: 'x' }));
  assert.strictEqual(result.changed, true);
  assert.deepStrictEqual(headers, {});
});
