'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./cspobjectsrcguard.js');

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

test('cspobjectsrcguard exports a populated reason table', () => {
  assert.strictEqual(typeof mod.REASON, 'object');
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.strictEqual(typeof mod.REASON[key], 'string');
    assert.ok(mod.REASON[key].length > 0);
  }
});

test('cspobjectsrcguard exports callable entries', () => {
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

test('cspobjectsrcguard keeps decision shape under repeated calls', () => {
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

test('cspobjectsrcguard classifies known inputs', () => {
  const a0 = mod.evaluateObjectSrc("object-src 'none'");
  assert.strictEqual(a0.ok, true, "mod.evaluateObjectSrc(\"object-src 'none'\")");
  assert.strictEqual(a0.reason, mod.REASON.OK);
  const a1 = mod.evaluateObjectSrc('object-src *');
  assert.strictEqual(a1.reason, mod.REASON.WILDCARD, "mod.evaluateObjectSrc('object-src *')");
  const a2 = mod.evaluateObjectSrc('object-src https:');
  assert.strictEqual(a2.reason, mod.REASON.PLUGIN_TYPES, "mod.evaluateObjectSrc('object-src https:')");
  const a3 = mod.evaluateObjectSrc("default-src 'self'");
  assert.strictEqual(a3.reason, mod.REASON.MISSING, "mod.evaluateObjectSrc(\"default-src 'self'\")");
});
