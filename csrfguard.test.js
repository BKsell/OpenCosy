'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./csrfguard.js');

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

test('csrfguard exports a populated reason table', () => {
  assert.strictEqual(typeof mod.REASON, 'object');
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.strictEqual(typeof mod.REASON[key], 'string');
    assert.ok(mod.REASON[key].length > 0);
  }
});

test('csrfguard exports callable entries', () => {
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

test('csrfguard keeps decision shape under repeated calls', () => {
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

test('csrfguard classifies known inputs', () => {
  const a0 = mod.evaluateCsrf({ method: 'GET' });
  assert.strictEqual(a0.reason, mod.REASON.SAFE_METHOD, "mod.evaluateCsrf({ method: 'GET' })");
  const a1 = mod.evaluateCsrf({ method: 'POST' });
  assert.strictEqual(a1.reason, mod.REASON.NO_ORIGIN, "mod.evaluateCsrf({ method: 'POST' })");
  const a2 = mod.evaluateCsrf({ method: 'POST', headers: [['origin', 'null']] });
  assert.strictEqual(a2.reason, mod.REASON.NULL_ORIGIN, "mod.evaluateCsrf({ method: 'POST', headers: [['origin', 'null']] })");
  const a3 = mod.evaluateCsrf({ method: 'POST', headers: [['origin', 'https://evil.example']], expectedOrigin: 'https://a.example' });
  assert.strictEqual(a3.reason, mod.REASON.CROSS_ORIGIN, "mod.evaluateCsrf({ method: 'POST', headers: [['origin', 'https://evil.example']], expectedOrigin: 'https://a.example' })");
  const a4 = mod.evaluateCsrf({ method: 'POST', headers: [['origin', 'https://a.example']], expectedOrigin: 'https://a.example' });
  assert.strictEqual(a4.ok, true, "mod.evaluateCsrf({ method: 'POST', headers: [['origin', 'https://a.example']], expectedOrigin: 'https://a.example' })");
  assert.strictEqual(a4.reason, mod.REASON.OK);
});
