'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./bloburlguard.js');

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

test('bloburlguard exports a populated reason table', () => {
  assert.strictEqual(typeof mod.REASON, 'object');
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.strictEqual(typeof mod.REASON[key], 'string');
    assert.ok(mod.REASON[key].length > 0);
  }
});

test('bloburlguard exports callable entries', () => {
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

test('bloburlguard keeps decision shape under repeated calls', () => {
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

test('bloburlguard classifies known inputs', () => {
  const a0 = mod.evaluateBlobUrl('blob:https://a.example/uuid');
  assert.strictEqual(a0.ok, true, "mod.evaluateBlobUrl('blob:https://a.example/uuid')");
  assert.strictEqual(a0.reason, mod.REASON.OK);
  const a1 = mod.evaluateBlobUrl('https://a.example/uuid');
  assert.strictEqual(a1.reason, mod.REASON.NOT_BLOB, "mod.evaluateBlobUrl('https://a.example/uuid')");
  const a2 = mod.evaluateBlobUrl('blob:null/uuid');
  assert.strictEqual(a2.reason, mod.REASON.OPAQUE_ORIGIN, "mod.evaluateBlobUrl('blob:null/uuid')");
  const a3 = mod.evaluateBlobUrl('');
  assert.strictEqual(a3.reason, mod.REASON.EMPTY, "mod.evaluateBlobUrl('')");
});
