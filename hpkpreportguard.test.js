'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./hpkpreportguard.js');

const CLEAN = { enabled: true, reportOnly: false, mode: 'enforce', maxItems: 8, endpoint: 'https://example.com/report', note: 'ok', fallbackPath: 'fallback.html', items: ['default-src', 'script-src'], baseline: ['default-src'], origins: ['self'] };

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function withValue(target, path, value) {
  const parts = path.split('.');
  let cursor = target;
  for (let i = 0; i < parts.length - 1; i += 1) {
    if (typeof cursor[parts[i]] !== 'object' || cursor[parts[i]] === null) {
      cursor[parts[i]] = {};
    }
    cursor = cursor[parts[i]];
  }
  cursor[parts[parts.length - 1]] = value;
}

function badValueFor(kind) {
  switch (kind) {
    case 'boolean-true':
      return false;
    case 'boolean-false':
      return true;
    case 'value-range':
      return 0;
    case 'text-enum':
      return 'bogus-mode';
    case 'text-pattern':
      return 'http://example.com/report';
    case 'text-too-long':
      return 'x'.repeat(600);
    case 'text-control':
      return 'a\u0007b';
    case 'text-traversal':
      return '../etc/passwd';
    case 'list-empty':
      return [];
    case 'list-count':
      return new Array(40).fill('default-src');
    case 'list-duplicate':
      return ['default-src', 'default-src'];
    case 'list-item-equals':
      return ['bogus-item'];
    default:
      return undefined;
  }
}

test('clean config passes every rule', () => {
  const result = guard.evaluateHpkpreportGuard(clone(CLEAN));
  assert.equal(result.ok, true);
  assert.equal(result.findings.length, 0);
});

test('null config is rejected', () => {
  const result = guard.evaluateHpkpreportGuard(null);
  assert.equal(result.ok, false);
  assert.equal(result.findings[0].key, 'HPKPREPOR_CONFIG_INVALID');
});

test('array config is rejected', () => {
  const result = guard.evaluateHpkpreportGuard([]);
  assert.equal(result.ok, false);
  assert.equal(result.findings[0].blocking, true);
});

test('describe renders the first findings', () => {
  const config = clone(CLEAN);
  withValue(config, 'enabled', false);
  const text = guard.describeHpkpreportGuard(config);
  assert.equal(typeof text, 'string');
  assert.ok(text.indexOf('HPKPREPOR_FLAG_OFF') >= 0);
});

test('describe caps the finding list', () => {
  const config = clone(CLEAN);
  withValue(config, 'enabled', false);
  withValue(config, 'reportOnly', true);
  withValue(config, 'mode', 'bogus-mode');
  withValue(config, 'maxItems', 0);
  withValue(config, 'endpoint', 'http://example.com/report');
  withValue(config, 'note', 'a\u0007b');
  withValue(config, 'fallbackPath', '../etc/passwd');
  withValue(config, 'items', ['bogus-item']);
  withValue(config, 'baseline', []);
  withValue(config, 'origins', ['bogus-item']);
  const text = guard.describeHpkpreportGuard(config);
  assert.ok(text.length > 0);
});

test('summary counts blocking and advisory', () => {
  const config = clone(CLEAN);
  withValue(config, 'enabled', false);
  withValue(config, 'note', 'a\u0007b');
  const summary = guard.summarizeHpkpreportGuard(config);
  assert.equal(summary.ok, false);
  assert.equal(summary.total, 2);
  assert.equal(summary.blocking, 1);
  assert.equal(summary.advisory, 1);
  assert.deepEqual(summary.keys, ['HPKPREPOR_FLAG_OFF', 'HPKPREPOR_NOTE_CONTROL']);
});

test('unsupported rule kind degrades to CONFIG_INVALID', () => {
  const rules = guard.RULES;
  const copy = rules.map((rule) => Object.assign({}, rule));
  copy[0].kind = 'not-a-kind';
  const original = rules[0].kind;
  rules[0].kind = 'not-a-kind';
  const result = guard.evaluateHpkpreportGuard(clone(CLEAN));
  rules[0].kind = original;
  assert.equal(result.ok, false);
  assert.equal(result.findings[0].key, 'HPKPREPOR_CONFIG_INVALID');
  assert.equal(copy[0].kind, 'not-a-kind');
});

test('evaluate is deterministic', () => {
  const config = clone(CLEAN);
  withValue(config, 'enabled', false);
  const first = guard.evaluateHpkpreportGuard(config);
  const second = guard.evaluateHpkpreportGuard(config);
  assert.deepEqual(first, second);
});

test('rule FLAG_OFF reacts to boolean-true', () => {
  const config = clone(CLEAN);
  withValue(config, 'enabled', false);
  const result = guard.evaluateHpkpreportGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'HPKPREPOR_FLAG_OFF');
  assert.ok(hit, 'missing HPKPREPOR_FLAG_OFF');
  assert.equal(hit.blocking, true);
});

test('rule REPORT_ONLY reacts to boolean-false', () => {
  const config = clone(CLEAN);
  withValue(config, 'reportOnly', true);
  const result = guard.evaluateHpkpreportGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'HPKPREPOR_REPORT_ONLY');
  assert.ok(hit, 'missing HPKPREPOR_REPORT_ONLY');
  assert.equal(hit.blocking, false);
});

test('rule MODE_INVALID reacts to text-enum', () => {
  const config = clone(CLEAN);
  withValue(config, 'mode', 'bogus-mode');
  const result = guard.evaluateHpkpreportGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'HPKPREPOR_MODE_INVALID');
  assert.ok(hit, 'missing HPKPREPOR_MODE_INVALID');
  assert.equal(hit.blocking, true);
});

test('rule COUNT_OUT_OF_RANGE reacts to value-range', () => {
  const config = clone(CLEAN);
  withValue(config, 'maxItems', 0);
  const result = guard.evaluateHpkpreportGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'HPKPREPOR_COUNT_OUT_OF_RANGE');
  assert.ok(hit, 'missing HPKPREPOR_COUNT_OUT_OF_RANGE');
  assert.equal(hit.blocking, true);
});

test('rule ENDPOINT_INSECURE reacts to text-pattern', () => {
  const config = clone(CLEAN);
  withValue(config, 'endpoint', 'http://example.com/report');
  const result = guard.evaluateHpkpreportGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'HPKPREPOR_ENDPOINT_INSECURE');
  assert.ok(hit, 'missing HPKPREPOR_ENDPOINT_INSECURE');
  assert.equal(hit.blocking, true);
});

test('rule ENDPOINT_TOO_LONG reacts to text-too-long', () => {
  const config = clone(CLEAN);
  withValue(config, 'endpoint', 'x'.repeat(600));
  const result = guard.evaluateHpkpreportGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'HPKPREPOR_ENDPOINT_TOO_LONG');
  assert.ok(hit, 'missing HPKPREPOR_ENDPOINT_TOO_LONG');
  assert.equal(hit.blocking, false);
});

test('rule NOTE_CONTROL reacts to text-control', () => {
  const config = clone(CLEAN);
  withValue(config, 'note', 'a\u0007b');
  const result = guard.evaluateHpkpreportGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'HPKPREPOR_NOTE_CONTROL');
  assert.ok(hit, 'missing HPKPREPOR_NOTE_CONTROL');
  assert.equal(hit.blocking, false);
});

test('rule PATH_TRAVERSAL reacts to text-traversal', () => {
  const config = clone(CLEAN);
  withValue(config, 'fallbackPath', '../etc/passwd');
  const result = guard.evaluateHpkpreportGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'HPKPREPOR_PATH_TRAVERSAL');
  assert.ok(hit, 'missing HPKPREPOR_PATH_TRAVERSAL');
  assert.equal(hit.blocking, true);
});

test('rule ITEM_UNKNOWN reacts to list-item-equals', () => {
  const config = clone(CLEAN);
  withValue(config, 'items', ['bogus-item']);
  const result = guard.evaluateHpkpreportGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'HPKPREPOR_ITEM_UNKNOWN');
  assert.ok(hit, 'missing HPKPREPOR_ITEM_UNKNOWN');
  assert.equal(hit.blocking, true);
});

test('rule ITEM_DUPLICATE reacts to list-duplicate', () => {
  const config = clone(CLEAN);
  withValue(config, 'items', ['default-src', 'default-src']);
  const result = guard.evaluateHpkpreportGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'HPKPREPOR_ITEM_DUPLICATE');
  assert.ok(hit, 'missing HPKPREPOR_ITEM_DUPLICATE');
  assert.equal(hit.blocking, false);
});

test('rule ITEM_COUNT reacts to list-count', () => {
  const config = clone(CLEAN);
  withValue(config, 'items', new Array(40).fill('default-src'));
  const result = guard.evaluateHpkpreportGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'HPKPREPOR_ITEM_COUNT');
  assert.ok(hit, 'missing HPKPREPOR_ITEM_COUNT');
  assert.equal(hit.blocking, false);
});

test('rule BASELINE_EMPTY reacts to list-empty', () => {
  const config = clone(CLEAN);
  withValue(config, 'baseline', []);
  const result = guard.evaluateHpkpreportGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'HPKPREPOR_BASELINE_EMPTY');
  assert.ok(hit, 'missing HPKPREPOR_BASELINE_EMPTY');
  assert.equal(hit.blocking, true);
});

test('rule ORIGIN_UNKNOWN reacts to list-item-equals', () => {
  const config = clone(CLEAN);
  withValue(config, 'origins', ['bogus-item']);
  const result = guard.evaluateHpkpreportGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'HPKPREPOR_ORIGIN_UNKNOWN');
  assert.ok(hit, 'missing HPKPREPOR_ORIGIN_UNKNOWN');
  assert.equal(hit.blocking, true);
});
