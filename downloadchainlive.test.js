'use strict';

const test = require('node:test');
const assert = require('node:assert');
const live = require('./downloadchainlive');

test('no chain means continue', () => {
  for (const input of [null, undefined, []]) {
    const res = live.auditLiveChain(input);
    assert.strictEqual(res.verdict, live.VERDICT.CONTINUE);
    assert.strictEqual(res.reason, live.REASON.NO_CHAIN);
    assert.strictEqual(res.hopCount, 0);
  }
});

test('https chain continues and reports final hop', () => {
  const chain = [
    'https://example.com/a',
    'https://cdn.example.com/a',
  ];
  const res = live.auditLiveChain(chain);
  assert.strictEqual(res.verdict, live.VERDICT.CONTINUE);
  assert.strictEqual(res.reason, live.REASON.OK);
  assert.strictEqual(res.hopCount, 2);
  assert.strictEqual(res.finalHost, 'cdn.example.com');
  assert.strictEqual(res.finalUrl, 'https://cdn.example.com/a');
});

test('http first hop is allowed when chain never started from https', () => {
  const res = live.auditLiveChain(['http://example.com/a', 'http://example.com/b']);
  assert.strictEqual(res.verdict, live.VERDICT.CONTINUE);
  assert.strictEqual(res.reason, live.REASON.OK);
});

test('late https downgrade aborts', () => {
  const res = live.auditLiveChain([
    'https://example.com/a',
    'https://example.com/b',
    'http://example.com/c',
  ]);
  assert.strictEqual(res.verdict, live.VERDICT.ABORT);
  assert.strictEqual(res.reason, live.REASON.DOWNGRADE);
  assert.strictEqual(res.badIndex, 2);
});

test('non array chain aborts', () => {
  const res = live.auditLiveChain('https://example.com');
  assert.strictEqual(res.verdict, live.VERDICT.ABORT);
  assert.strictEqual(res.reason, live.REASON.BAD_SHAPE);
});

test('too many hops aborts', () => {
  const chain = [];
  for (let i = 0; i <= live.MAX_LIVE_HOPS; i += 1) {
    chain.push(`https://example.com/${i}`);
  }
  const res = live.auditLiveChain(chain);
  assert.strictEqual(res.verdict, live.VERDICT.ABORT);
  assert.strictEqual(res.reason, live.REASON.TOO_MANY_HOPS);
});

test('bad hop payloads abort with index', () => {
  const cases = [
    [['https://example.com/a', 42], live.REASON.BAD_URL],
    [['https://example.com/a', 'https://example.com/b c'], live.REASON.BAD_URL],
    [['https://example.com/a', 'ftp://example.com/b'], live.REASON.BAD_SCHEME],
    [['https://example.com/a', 'file:///C:/x'], live.REASON.BAD_SCHEME],
    [['https://example.com/a', 'https://user:pass@example.com/b'], live.REASON.USERINFO],
    [['https://example.com/a', `https://example.com/${'a'.repeat(live.MAX_LIVE_URL_CHARS)}`], live.REASON.BAD_URL],
  ];
  for (const [chain, reason] of cases) {
    const res = live.auditLiveChain(chain);
    assert.strictEqual(res.verdict, live.VERDICT.ABORT);
    assert.strictEqual(res.reason, reason);
    assert.strictEqual(res.badIndex, 1);
  }
});

test('control characters abort', () => {
  const res = live.auditLiveChain(['https://example.com/a\u0000']);
  assert.strictEqual(res.verdict, live.VERDICT.ABORT);
  assert.strictEqual(res.reason, live.REASON.BAD_URL);
});

test('descriptions are stable and non empty', () => {
  const results = [
    { reason: live.REASON.OK, hopCount: 3 },
    { reason: live.REASON.NO_CHAIN },
    { reason: live.REASON.BAD_SHAPE },
    { reason: live.REASON.TOO_MANY_HOPS },
    { reason: live.REASON.BAD_URL, badIndex: 1 },
    { reason: live.REASON.BAD_SCHEME, badIndex: 2 },
    { reason: live.REASON.USERINFO, badIndex: 0 },
    { reason: live.REASON.EMPTY_HOST, badIndex: 3 },
    { reason: live.REASON.DOWNGRADE, badIndex: 1 },
  ];
  const seen = new Set();
  for (const res of results) {
    const msg = live.describeLiveChain(res);
    assert.ok(msg.length > 0);
    assert.ok(!seen.has(msg), `duplicate message ${msg}`);
    seen.add(msg);
  }
  assert.ok(live.describeLiveChain(null).length > 0);
  assert.ok(live.describeLiveChain({ reason: 'unknown' }).length > 0);
});
