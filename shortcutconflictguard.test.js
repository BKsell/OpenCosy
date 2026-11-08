'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./shortcutconflictguard.js');

const evaluate = mod.evaluateShortcutConflictGuard;
const describe = mod.describeShortcutConflictGuard;

test('shortcutconflictguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('shortcutconflictguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('shortcutconflictguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('shortcutconflictguard clean snapshot produces no findings', () => {
  const clean = {
  "shortcuts": [
    {
      "key": "Ctrl+T",
      "action": "newtab"
    }
  ],
  "reserved": [
    "Ctrl+W"
  ],
  "maxShortcuts": 30
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('shortcutconflictguard flags SHORTCUT_DUPLICATE_KEY', () => {
  const snapshot = {
  "shortcuts": [
    {
      "key": "dup"
    },
    {
      "key": "dup"
    }
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SHORTCUT_DUPLICATE_KEY);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('shortcutconflictguard flags SHORTCUT_RESERVED_KEY', () => {
  const snapshot = {
  "shortcuts": [
    {
      "key": "Ctrl+W"
    }
  ],
  "reserved": [
    "Ctrl+W"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SHORTCUT_RESERVED_KEY);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('shortcutconflictguard flags SHORTCUT_ACTION_EMPTY', () => {
  const snapshot = {
  "shortcuts": [
    {}
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SHORTCUT_ACTION_EMPTY);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('shortcutconflictguard flags SHORTCUT_LIMIT', () => {
  const snapshot = {
  "shortcuts": [
    "ok0",
    "ok1",
    "ok2",
    "ok3",
    "ok4",
    "ok5",
    "ok6",
    "ok7",
    "ok8",
    "ok9",
    "ok10",
    "ok11",
    "ok12",
    "ok13",
    "ok14",
    "ok15",
    "ok16",
    "ok17",
    "ok18",
    "ok19",
    "ok20",
    "ok21",
    "ok22",
    "ok23",
    "ok24",
    "ok25",
    "ok26",
    "ok27",
    "ok28",
    "ok29",
    "ok30"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SHORTCUT_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('shortcutconflictguard flags SHORTCUT_KEY_EMPTY', () => {
  const snapshot = {
  "shortcuts": [
    {}
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SHORTCUT_KEY_EMPTY);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('shortcutconflictguard describe renders findings in order', () => {
  const snapshot = {"shortcuts": [{"key": "dup"}, {"key": "dup"}]};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('shortcutconflictguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
