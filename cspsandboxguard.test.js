'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./cspsandboxguard.js');

const REASONS = ["CSPSBX_FLAG_OFF", "CSPSBX_REPORT_ONLY", "CSPSBX_MODE_INVALID", "CSPSBX_COUNT_OUT_OF_RANGE", "CSPSBX_ENDPOINT_INSECURE", "CSPSBX_ENDPOINT_TOO_LONG", "CSPSBX_NOTE_CONTROL", "CSPSBX_PATH_TRAVERSAL", "CSPSBX_ITEM_UNKNOWN", "CSPSBX_ITEM_DUPLICATE", "CSPSBX_ITEM_COUNT", "CSPSBX_BASELINE_EMPTY"];
const CLEAN = {
  "cspSandbox": {
    "enabled": true,
    "reportOnly": false,
    "mode": "strict",
    "lifetime": 1800,
    "endpoint": "https://sandbox.example.com/run",
    "note": "sandbox-note",
    "storagePath": "policies/sandbox",
    "items": [
      "allow-forms"
    ],
    "baseline": [
      "sandbox"
    ]
  }
};

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function withValue(path, value) {
  const snapshot = clone(CLEAN);
  const parts = path.split('.');
  let cursor = snapshot;
  for (const part of parts.slice(0, -1)) {
    if (typeof cursor[part] !== 'object' || cursor[part] === null) {
      cursor[part] = {};
    }
    cursor = cursor[part];
  }
  cursor[parts[parts.length - 1]] = value;
  return snapshot;
}

function hasKey(result, key) {
  return result.findings.some((finding) => finding.key === key);
}

test('reason table covers every rule', () => {
  assert.deepStrictEqual(guard.RULES.map((rule) => rule.key), REASONS);
});

test('exported evaluator is callable', () => {
  assert.strictEqual(typeof guard.evaluateCspsandboxGuard, 'function');
  assert.strictEqual(typeof guard.describeCspsandboxGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateCspsandboxGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateCspsandboxGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule CSPSBX_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateCspsandboxGuard(withValue('cspSandbox.enabled', false));
  assert.ok(hasKey(result, 'CSPSBX_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'CSPSBX_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPSBX_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateCspsandboxGuard(withValue('cspSandbox.reportOnly', true));
  assert.ok(hasKey(result, 'CSPSBX_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'CSPSBX_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPSBX_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateCspsandboxGuard(withValue('cspSandbox.mode', "bogus-value"));
  assert.ok(hasKey(result, 'CSPSBX_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'CSPSBX_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPSBX_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateCspsandboxGuard(withValue('cspSandbox.lifetime', 599));
  assert.ok(hasKey(result, 'CSPSBX_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'CSPSBX_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPSBX_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateCspsandboxGuard(withValue('cspSandbox.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'CSPSBX_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'CSPSBX_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPSBX_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateCspsandboxGuard(withValue('cspSandbox.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'CSPSBX_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'CSPSBX_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPSBX_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateCspsandboxGuard(withValue('cspSandbox.note', "a\u0007b"));
  assert.ok(hasKey(result, 'CSPSBX_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'CSPSBX_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPSBX_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateCspsandboxGuard(withValue('cspSandbox.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'CSPSBX_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'CSPSBX_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPSBX_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateCspsandboxGuard(withValue('cspSandbox.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'CSPSBX_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'CSPSBX_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPSBX_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateCspsandboxGuard(withValue('cspSandbox.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'CSPSBX_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'CSPSBX_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPSBX_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateCspsandboxGuard(withValue('cspSandbox.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'CSPSBX_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'CSPSBX_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPSBX_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateCspsandboxGuard(withValue('cspSandbox.baseline', []));
  assert.ok(hasKey(result, 'CSPSBX_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'CSPSBX_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateCspsandboxGuard(withValue('cspSandbox.enabled', false));
  const text = guard.describeCspsandboxGuard(result);
  assert.ok(text.includes('CSPSBX_FLAG_OFF'));
  assert.ok(text.length > 'cspsandboxguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeCspsandboxGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateCspsandboxGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
