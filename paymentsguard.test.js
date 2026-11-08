'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./paymentsguard.js');

const PROBES = [
  undefined,
  null,
  '',
  'x',
  0,
  1,
  true,
  {},
  [],
  { url: 'https://probe.example/path' },
  [['content-type', 'text/plain']],
  [['vary', 'accept-encoding']],
];

function callEntries(fn, probe) {
  try {
    return { thrown: false, value: fn(probe, probe) };
  } catch (err) {
    return { thrown: true, value: err };
  }
}

test('paymentsguard exports a populated reason table', () => {
  assert.strictEqual(typeof mod.REASON, 'object');
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.strictEqual(typeof mod.REASON[key], 'string');
    assert.ok(mod.REASON[key].length > 0);
  }
});

test('paymentsguard exports callable entries', () => {
  const names = Object.keys(mod);
  const fns = names.filter((key) => typeof mod[key] === 'function');
  assert.ok(names.length > 0);
  const reasonValues = new Set(Object.values(mod.REASON));
  for (const fn of fns) {
    for (const probe of PROBES) {
      const outcome = callEntries(mod[fn], probe);
      if (outcome.thrown) {
        assert.ok(outcome.value instanceof Error);
        continue;
      }
      const value = outcome.value;
      if (value && typeof value === 'object' && 'ok' in value) {
        if (value.ok !== undefined) assert.strictEqual(typeof value.ok, 'boolean');
        if (value.blocked !== undefined) assert.strictEqual(typeof value.blocked, 'boolean');
        if (value.blocked === true) {
          assert.ok(reasonValues.has(value.reason), 'unknown reason ' + String(value.reason));
        }
      }
    }
  }
});

test('paymentsguard keeps decision shape under repeated calls', () => {
  const fns = Object.keys(mod).filter((key) => typeof mod[key] === 'function');
  for (const fn of fns) {
    const first = callEntries(mod[fn], { url: 'https://probe.example/path' });
    const second = callEntries(mod[fn], { url: 'https://probe.example/path' });
    assert.strictEqual(first.thrown, second.thrown);
    if (!first.thrown && first.value && typeof first.value === 'object') {
      assert.deepStrictEqual(Object.keys(first.value).length, Object.keys(second.value).length);
    }
  }
});

test('paymentsguard classifies known inputs', () => {
  const a0 = mod.evaluatePaymentRequest({ origin: 'https://a.example', methods: ['https://google.com/pay'] });
  assert.strictEqual(a0.ok, true, "mod.evaluatePaymentRequest({ origin: 'https://a.example', methods: ['https://google.com/pay'] })");
  assert.strictEqual(a0.reason, mod.REASON.OK);
  const a1 = mod.evaluatePaymentRequest({ origin: 'http://a.example', methods: ['https://google.com/pay'] });
  assert.strictEqual(a1.reason, mod.REASON.INSECURE_ORIGIN, "mod.evaluatePaymentRequest({ origin: 'http://a.example', methods: ['https://google.com/pay'] })");
  const a2 = mod.evaluatePaymentRequest({ origin: 'https://a.example', methods: ['https://evil.example/pay'] });
  assert.strictEqual(a2.reason, mod.REASON.UNKNOWN_METHOD, "mod.evaluatePaymentRequest({ origin: 'https://a.example', methods: ['https://evil.example/pay'] })");
  const a3 = mod.evaluatePaymentRequest({ origin: 'https://a.example', methods: ['https://google.com/pay'], userGesture: false }, { requireGesture: true });
  assert.strictEqual(a3.reason, mod.REASON.NO_USER_GESTURE, "mod.evaluatePaymentRequest({ origin: 'https://a.example', methods: ['https://google.com/pay'], userGesture: false }, { requireGesture: true })");
});
