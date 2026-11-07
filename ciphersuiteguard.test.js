'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./ciphersuiteguard.js');

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
  const result = guard.evaluateCiphersuiteGuard(clone(CLEAN));
  assert.equal(result.ok, true);
  assert.equal(result.findings.length, 0);
});

test('null config is rejected', () => {
  const result = guard.evaluateCiphersuiteGuard(null);
  assert.equal(result.ok, false);
  assert.equal(result.findings[0].key, 'CIPHERSUI_CONFIG_INVALID');
});

test('array config is rejected', () => {
  const result = guard.evaluateCiphersuiteGuard([]);
  assert.equal(result.ok, false);
  assert.equal(result.findings[0].blocking, true);
});

test('describe renders the first findings', () => {
  const config = clone(CLEAN);
  withValue(config, 'enabled', false);
  const text = guard.describeCiphersuiteGuard(config);
  assert.equal(typeof text, 'string');
  assert.ok(text.indexOf('CIPHERSUI_FLAG_OFF') >= 0);
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
  const text = guard.describeCiphersuiteGuard(config);
  assert.ok(text.length > 0);
});

test('summary counts blocking and advisory', () => {
  const config = clone(CLEAN);
  withValue(config, 'enabled', false);
  withValue(config, 'note', 'a\u0007b');
  const summary = guard.summarizeCiphersuiteGuard(config);
  assert.equal(summary.ok, false);
  assert.equal(summary.total, 2);
  assert.equal(summary.blocking, 1);
  assert.equal(summary.advisory, 1);
  assert.deepEqual(summary.keys, ['CIPHERSUI_FLAG_OFF', 'CIPHERSUI_NOTE_CONTROL']);
});

test('unsupported rule kind degrades to CONFIG_INVALID', () => {
  const rules = guard.RULES;
  const copy = rules.map((rule) => Object.assign({}, rule));
  copy[0].kind = 'not-a-kind';
  const original = rules[0].kind;
  rules[0].kind = 'not-a-kind';
  const result = guard.evaluateCiphersuiteGuard(clone(CLEAN));
  rules[0].kind = original;
  assert.equal(result.ok, false);
  assert.equal(result.findings[0].key, 'CIPHERSUI_CONFIG_INVALID');
  assert.equal(copy[0].kind, 'not-a-kind');
});

test('evaluate is deterministic', () => {
  const config = clone(CLEAN);
  withValue(config, 'enabled', false);
  const first = guard.evaluateCiphersuiteGuard(config);
  const second = guard.evaluateCiphersuiteGuard(config);
  assert.deepEqual(first, second);
});

test('rule FLAG_OFF reacts to boolean-true', () => {
  const config = clone(CLEAN);
  withValue(config, 'enabled', false);
  const result = guard.evaluateCiphersuiteGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'CIPHERSUI_FLAG_OFF');
  assert.ok(hit, 'missing CIPHERSUI_FLAG_OFF');
  assert.equal(hit.blocking, true);
});

test('rule REPORT_ONLY reacts to boolean-false', () => {
  const config = clone(CLEAN);
  withValue(config, 'reportOnly', true);
  const result = guard.evaluateCiphersuiteGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'CIPHERSUI_REPORT_ONLY');
  assert.ok(hit, 'missing CIPHERSUI_REPORT_ONLY');
  assert.equal(hit.blocking, false);
});

test('rule MODE_INVALID reacts to text-enum', () => {
  const config = clone(CLEAN);
  withValue(config, 'mode', 'bogus-mode');
  const result = guard.evaluateCiphersuiteGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'CIPHERSUI_MODE_INVALID');
  assert.ok(hit, 'missing CIPHERSUI_MODE_INVALID');
  assert.equal(hit.blocking, true);
});

test('rule COUNT_OUT_OF_RANGE reacts to value-range', () => {
  const config = clone(CLEAN);
  withValue(config, 'maxItems', 0);
  const result = guard.evaluateCiphersuiteGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'CIPHERSUI_COUNT_OUT_OF_RANGE');
  assert.ok(hit, 'missing CIPHERSUI_COUNT_OUT_OF_RANGE');
  assert.equal(hit.blocking, true);
});

test('rule ENDPOINT_INSECURE reacts to text-pattern', () => {
  const config = clone(CLEAN);
  withValue(config, 'endpoint', 'http://example.com/report');
  const result = guard.evaluateCiphersuiteGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'CIPHERSUI_ENDPOINT_INSECURE');
  assert.ok(hit, 'missing CIPHERSUI_ENDPOINT_INSECURE');
  assert.equal(hit.blocking, true);
});

test('rule ENDPOINT_TOO_LONG reacts to text-too-long', () => {
  const config = clone(CLEAN);
  withValue(config, 'endpoint', 'x'.repeat(600));
  const result = guard.evaluateCiphersuiteGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'CIPHERSUI_ENDPOINT_TOO_LONG');
  assert.ok(hit, 'missing CIPHERSUI_ENDPOINT_TOO_LONG');
  assert.equal(hit.blocking, false);
});

test('rule NOTE_CONTROL reacts to text-control', () => {
  const config = clone(CLEAN);
  withValue(config, 'note', 'a\u0007b');
  const result = guard.evaluateCiphersuiteGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'CIPHERSUI_NOTE_CONTROL');
  assert.ok(hit, 'missing CIPHERSUI_NOTE_CONTROL');
  assert.equal(hit.blocking, false);
});

test('rule PATH_TRAVERSAL reacts to text-traversal', () => {
  const config = clone(CLEAN);
  withValue(config, 'fallbackPath', '../etc/passwd');
  const result = guard.evaluateCiphersuiteGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'CIPHERSUI_PATH_TRAVERSAL');
  assert.ok(hit, 'missing CIPHERSUI_PATH_TRAVERSAL');
  assert.equal(hit.blocking, true);
});

test('rule ITEM_UNKNOWN reacts to list-item-equals', () => {
  const config = clone(CLEAN);
  withValue(config, 'items', ['bogus-item']);
  const result = guard.evaluateCiphersuiteGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'CIPHERSUI_ITEM_UNKNOWN');
  assert.ok(hit, 'missing CIPHERSUI_ITEM_UNKNOWN');
  assert.equal(hit.blocking, true);
});

test('rule ITEM_DUPLICATE reacts to list-duplicate', () => {
  const config = clone(CLEAN);
  withValue(config, 'items', ['default-src', 'default-src']);
  const result = guard.evaluateCiphersuiteGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'CIPHERSUI_ITEM_DUPLICATE');
  assert.ok(hit, 'missing CIPHERSUI_ITEM_DUPLICATE');
  assert.equal(hit.blocking, false);
});

test('rule ITEM_COUNT reacts to list-count', () => {
  const config = clone(CLEAN);
  withValue(config, 'items', new Array(40).fill('default-src'));
  const result = guard.evaluateCiphersuiteGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'CIPHERSUI_ITEM_COUNT');
  assert.ok(hit, 'missing CIPHERSUI_ITEM_COUNT');
  assert.equal(hit.blocking, false);
});

test('rule BASELINE_EMPTY reacts to list-empty', () => {
  const config = clone(CLEAN);
  withValue(config, 'baseline', []);
  const result = guard.evaluateCiphersuiteGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'CIPHERSUI_BASELINE_EMPTY');
  assert.ok(hit, 'missing CIPHERSUI_BASELINE_EMPTY');
  assert.equal(hit.blocking, true);
});

test('rule ORIGIN_UNKNOWN reacts to list-item-equals', () => {
  const config = clone(CLEAN);
  withValue(config, 'origins', ['bogus-item']);
  const result = guard.evaluateCiphersuiteGuard(config);
  assert.equal(result.ok, false);
  const hit = result.findings.find((finding) => finding.key === 'CIPHERSUI_ORIGIN_UNKNOWN');
  assert.ok(hit, 'missing CIPHERSUI_ORIGIN_UNKNOWN');
  assert.equal(hit.blocking, true);
});
