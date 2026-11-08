'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./webhidguard.js');

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

test('webhidguard exports a populated reason table', () => {
  assert.strictEqual(typeof mod.REASON, 'object');
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.strictEqual(typeof mod.REASON[key], 'string');
    assert.ok(mod.REASON[key].length > 0);
  }
});

test('webhidguard exports callable entries', () => {
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

test('webhidguard keeps decision shape under repeated calls', () => {
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

test('webhidguard classifies known inputs', () => {
  const a0 = mod.evaluateHid({ origin: 'https://a.example', options: { filters: [{ usagePage: 1, usage: 6 }] } });
  assert.strictEqual(a0.ok, true, "mod.evaluateHid({ origin: 'https://a.example', options: { filters: [{ usagePage: 1, usage: 6 }] } })");
  assert.strictEqual(a0.reason, mod.REASON.OK);
  const a1 = mod.evaluateHid({ origin: 'https://a.example', options: { filters: [] } });
  assert.strictEqual(a1.reason, mod.REASON.NO_FILTER, "mod.evaluateHid({ origin: 'https://a.example', options: { filters: [] } })");
  const a2 = mod.evaluateHid({ origin: 'https://a.example', options: { filters: [{ usagePage: -1 }] } });
  assert.strictEqual(a2.reason, mod.REASON.WILDCARD_USAGE, "mod.evaluateHid({ origin: 'https://a.example', options: { filters: [{ usagePage: -1 }] } })");
  const a3 = mod.evaluateHid({ origin: 'http://a.example', options: { filters: [{ usagePage: 1 }] } });
  assert.strictEqual(a3.reason, mod.REASON.INSECURE, "mod.evaluateHid({ origin: 'http://a.example', options: { filters: [{ usagePage: 1 }] } })");
});
