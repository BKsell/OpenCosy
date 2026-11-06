'use strict';

const nodeTest = require('node:test');
const assert = require('node:assert');
const budget = require('./externalprotocolbudget');

const { REASON, scrubTarget, createExternalBudget, describeReason } = budget;

nodeTest.test('scrubTarget accepts https and keeps href', () => {
  const result = scrubTarget('https://example.com/path?q=1');
  assert.equal(result.ok, true);
  assert.equal(result.reason, REASON.OK);
  assert.match(result.target, /^https:\/\/example\.com\/path\?q=1$/);
});

nodeTest.test('scrubTarget rejects empty and non-string targets', () => {
  assert.equal(scrubTarget('').reason, REASON.EMPTY_TARGET);
  assert.equal(scrubTarget('   ').reason, REASON.EMPTY_TARGET);
  assert.equal(scrubTarget(null).reason, REASON.EMPTY_TARGET);
});

nodeTest.test('scrubTarget rejects control characters', () => {
  assert.equal(scrubTarget('https://example.com/\u0001').reason, REASON.CONTROL_CHAR);
});

nodeTest.test('scrubTarget rejects oversized targets', () => {
  const long = 'https://example.com/' + 'a'.repeat(3000);
  assert.equal(scrubTarget(long).reason, REASON.TOO_LONG);
});

nodeTest.test('scrubTarget rejects embedded credentials', () => {
  assert.equal(scrubTarget('https://user:pass@example.com/x').reason, REASON.USERINFO);
});

nodeTest.test('scrubTarget rejects unparsable protocol handler strings', () => {
  assert.equal(scrubTarget('not a url').reason, REASON.BLOCKED_SCHEME);
});

nodeTest.test('judge blocks always-blocked schemes even when confirmable', () => {
  const guard = createExternalBudget();
  for (const scheme of ['javascript', 'data', 'file', 'blob']) {
    const verdict = guard.judge({ url: `${scheme}:payload`, origin: 'https://site.test', now: 1000 });
    assert.equal(verdict.allowed, false, scheme);
    assert.equal(verdict.reason, REASON.BLOCKED_SCHEME, scheme);
  }
});

nodeTest.test('judge allows mailto within budget', () => {
  const guard = createExternalBudget();
  const verdict = guard.judge({ url: 'mailto:a@b.test', origin: 'https://site.test', now: 1000 });
  assert.equal(verdict.allowed, true);
  assert.equal(verdict.scheme, 'mailto');
});

nodeTest.test('judge throttles per origin and reports retry delay', () => {
  const guard = createExternalBudget({ windowMs: 60000, maxPerOrigin: 3 });
  for (let i = 0; i < 3; i += 1) {
    assert.equal(guard.judge({ url: `tel:+1000${i}`, origin: 'https://a.test', now: 1000 + i }).allowed, true);
  }
  const blocked = guard.judge({ url: 'tel:+10004', origin: 'https://a.test', now: 2000 });
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.reason, REASON.FLOOD);
  assert.equal(blocked.retryAfterMs, 59000);
  const otherOrigin = guard.judge({ url: 'tel:+10005', origin: 'https://b.test', now: 2000 });
  assert.equal(otherOrigin.allowed, true);
});

nodeTest.test('judge throttles globally per scheme', () => {
  const guard = createExternalBudget({ windowMs: 60000, maxPerOrigin: 10, maxPerScheme: 2 });
  assert.equal(guard.judge({ url: 'mailto:x@a.test', origin: 'https://a.test', now: 1000 }).allowed, true);
  assert.equal(guard.judge({ url: 'mailto:y@b.test', origin: 'https://b.test', now: 1100 }).allowed, true);
  const third = guard.judge({ url: 'mailto:z@c.test', origin: 'https://c.test', now: 1200 });
  assert.equal(third.allowed, false);
  assert.equal(third.reason, REASON.SCHEME_FLOOD);
});

nodeTest.test('window expires and budget recovers', () => {
  const guard = createExternalBudget({ windowMs: 5000, maxPerOrigin: 2 });
  assert.equal(guard.judge({ url: 'tel:1', origin: 'https://a.test', now: 1000 }).allowed, true);
  assert.equal(guard.judge({ url: 'tel:2', origin: 'https://a.test', now: 2000 }).allowed, true);
  assert.equal(guard.judge({ url: 'tel:3', origin: 'https://a.test', now: 3000 }).allowed, false);
  assert.equal(guard.judge({ url: 'tel:4', origin: 'https://a.test', now: 7000 }).allowed, true);
});

nodeTest.test('judge rejects origins that normalize to empty', () => {
  const guard = createExternalBudget();
  const verdict = guard.judge({ url: 'mailto:a@b.test', origin: '   ', now: 1000 });
  assert.equal(verdict.allowed, false);
  assert.equal(verdict.reason, REASON.EMPTY_TARGET);
});

nodeTest.test('snapshot reports fresh counters only', () => {
  const guard = createExternalBudget({ windowMs: 10000, maxPerOrigin: 5 });
  guard.judge({ url: 'tel:1', origin: 'https://a.test', now: 1000 });
  guard.judge({ url: 'mailto:a@b.test', origin: 'https://a.test', now: 2000 });
  const snap = guard.snapshot(3000);
  assert.equal(snap.origins.length, 2);
  assert.equal(snap.policy.maxPerOrigin, 5);
  const stale = guard.snapshot(15000);
  assert.equal(stale.origins.length, 0);
});

nodeTest.test('reset clears counters', () => {
  const guard = createExternalBudget({ maxPerOrigin: 1 });
  guard.judge({ url: 'tel:1', origin: 'https://a.test', now: 1000 });
  assert.equal(guard.judge({ url: 'tel:2', origin: 'https://a.test', now: 1001 }).allowed, false);
  guard.reset();
  assert.equal(guard.judge({ url: 'tel:3', origin: 'https://a.test', now: 1002 }).allowed, true);
});

nodeTest.test('describeReason covers every reason code', () => {
  for (const reason of Object.values(REASON)) {
    assert.equal(typeof describeReason(reason), 'string');
    assert.ok(describeReason(reason).length > 0);
  }
  assert.equal(describeReason('nope'), '未知原因');
});
