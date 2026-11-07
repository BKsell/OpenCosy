'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./spellchecklanguageguard.js');

const evaluate = mod.evaluateSpellcheckLanguageGuard;
const describe = mod.describeSpellcheckLanguageGuard;

test('spellchecklanguageguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('spellchecklanguageguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('spellchecklanguageguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('spellchecklanguageguard clean snapshot produces no findings', () => {
  const clean = {
  "languages": [
    "en-US"
  ],
  "remoteDictionary": false,
  "dictionaryUrl": "https://example.com/en.dic",
  "maxLanguages": 6
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('spellchecklanguageguard flags SPELL_LANG_EMPTY', () => {
  const snapshot = {
  "languages": []
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SPELL_LANG_EMPTY);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('spellchecklanguageguard flags SPELL_LANG_INVALID', () => {
  const snapshot = {
  "languages": [
    "*"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SPELL_LANG_INVALID);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('spellchecklanguageguard flags SPELL_LANG_LIMIT', () => {
  const snapshot = {
  "languages": [
    "ok0",
    "ok1",
    "ok2",
    "ok3",
    "ok4",
    "ok5",
    "ok6"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SPELL_LANG_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('spellchecklanguageguard flags SPELL_DICT_NOT_HTTPS', () => {
  const snapshot = {
  "dictionaryUrl": "http://insecure.test/x"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SPELL_DICT_NOT_HTTPS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('spellchecklanguageguard flags SPELL_REMOTE_RISK', () => {
  const snapshot = {
  "remoteDictionary": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SPELL_REMOTE_RISK);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('spellchecklanguageguard describe renders findings in order', () => {
  const snapshot = {"languages": []};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('spellchecklanguageguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
