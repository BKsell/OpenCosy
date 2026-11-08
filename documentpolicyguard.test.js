'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./documentpolicyguard');

function h(value) {
  return { 'document-policy': [value] };
}

test('缺头返回 missing 且不改动', () => {
  const headers = {};
  const r = guard.applyDocumentPolicyGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合规指令不改动', () => {
  const headers = h('sync-xhr=none, document-domain=none');
  const r = guard.applyDocumentPolicyGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.ok(Array.isArray(headers['document-policy']));
});

test('布尔指令无取值合法', () => {
  const headers = h('cross-origin-isolated, oversized-images=none');
  const r = guard.applyDocumentPolicyGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('未知指令被剔除后保留其余', () => {
  const headers = h('made-up-feature=none, fonts=none');
  const r = guard.applyDocumentPolicyGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.UNKNOWN_DIRECTIVE);
  assert.strictEqual(headers['document-policy'][0], 'fonts=none');
});

test('document.domain 放行被剔除', () => {
  const headers = h('document-domain=*, sync-xhr=none');
  const r = guard.applyDocumentPolicyGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.DOCUMENT_DOMAIN_ALLOWED);
  assert.strictEqual(headers['document-policy'][0], 'sync-xhr=none');
});

test('同步 XHR 放行被剔除', () => {
  const headers = h('sync-xhr=*');
  const r = guard.applyDocumentPolicyGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.SYNC_XHR_ALLOWED);
  assert.strictEqual(headers['document-policy'], undefined);
});

test('非法取值整头剥除', () => {
  const headers = h('fonts=yes');
  const r = guard.applyDocumentPolicyGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.UNKNOWN_DIRECTIVE);
  assert.strictEqual(headers['document-policy'], undefined);
});

test('重复指令去重', () => {
  const headers = h('fonts=none, fonts=none');
  const r = guard.applyDocumentPolicyGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.DUPLICATE_DIRECTIVE);
  assert.strictEqual(headers['document-policy'][0], 'fonts=none');
});

test('超长取值整头剥除', () => {
  const headers = h(`fonts=none, ${'x'.repeat(3000)}`);
  const r = guard.applyDocumentPolicyGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
  assert.strictEqual(headers['document-policy'], undefined);
});

test('空取值视为非法', () => {
  const headers = h('   ');
  const r = guard.applyDocumentPolicyGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
  assert.strictEqual(headers['document-policy'], undefined);
});

test('大小写头名可识别', () => {
  const headers = { 'Document-Policy': ['sync-xhr=none'] };
  const r = guard.applyDocumentPolicyGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('describeReason 覆盖主要状态', () => {
  assert.strictEqual(typeof guard.describeReason(guard.REASON.OK), 'string');
  assert.strictEqual(typeof guard.describeReason('unknown'), 'string');
});
