'use strict';

const test = require('node:test');
const assert = require('node:assert');

const guard = require('./crossoriginpolicyguard');

test('三个头都缺失时不改动', () => {
  const headers = {};
  const result = guard.applyCrossOriginPolicyGuard(headers);
  assert.strictEqual(result.changed, false);
  assert.strictEqual(result.findings.length, 0);
});

test('合规的 CORP/COOP/COEP 保持原样', () => {
  const headers = {
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Embedder-Policy': 'require-corp',
  };
  const result = guard.applyCrossOriginPolicyGuard(headers);
  assert.strictEqual(result.changed, false);
  assert.strictEqual(headers['Cross-Origin-Resource-Policy'], 'same-origin');
});

test('CORP 非法取值被移除', () => {
  const headers = { 'Cross-Origin-Resource-Policy': 'everyone' };
  guard.applyCrossOriginPolicyGuard(headers);
  assert.strictEqual('Cross-Origin-Resource-Policy' in headers, false);
});

test('CORP 空白值被移除', () => {
  const headers = { 'Cross-Origin-Resource-Policy': '   ' };
  guard.applyCrossOriginPolicyGuard(headers);
  assert.strictEqual('Cross-Origin-Resource-Policy' in headers, false);
});

test('CORP cross-origin 单独出现只记为宽松', () => {
  const headers = { 'Cross-Origin-Resource-Policy': 'cross-origin' };
  const result = guard.applyCrossOriginPolicyGuard(headers);
  assert.strictEqual(headers['Cross-Origin-Resource-Policy'], 'cross-origin');
  assert.strictEqual(result.findings[0].reason, guard.REASON.PERMISSIVE);
});

test('CORP cross-origin 搭配 ACAO 通配被收紧', () => {
  const headers = {
    'Cross-Origin-Resource-Policy': 'cross-origin',
    'Access-Control-Allow-Origin': '*',
  };
  const result = guard.applyCrossOriginPolicyGuard(headers);
  assert.strictEqual(headers['Cross-Origin-Resource-Policy'], 'same-origin');
  assert.strictEqual(result.findings[0].reason, guard.REASON.DOWNGRADED);
});

test('CORP 重复头合并为单一值', () => {
  const headers = { 'Cross-Origin-Resource-Policy': ['same-site', 'same-origin'] };
  const result = guard.applyCrossOriginPolicyGuard(headers);
  assert.strictEqual(Array.isArray(headers['Cross-Origin-Resource-Policy']), false);
  assert.strictEqual(headers['Cross-Origin-Resource-Policy'], 'same-site');
  assert.strictEqual(result.findings[0].reason, guard.REASON.DUPLICATE);
});

test('COOP unsafe-none 只记为宽松', () => {
  const headers = { 'Cross-Origin-Opener-Policy': 'unsafe-none' };
  const result = guard.applyCrossOriginPolicyGuard(headers);
  assert.strictEqual(headers['Cross-Origin-Opener-Policy'], 'unsafe-none');
  assert.strictEqual(result.findings[0].reason, guard.REASON.PERMISSIVE);
});

test('COOP 非法取值被移除', () => {
  const headers = { 'Cross-Origin-Opener-Policy': 'same-site' };
  guard.applyCrossOriginPolicyGuard(headers);
  assert.strictEqual('Cross-Origin-Opener-Policy' in headers, false);
});

test('COOP 大小写归一后合法', () => {
  const headers = { 'Cross-Origin-Opener-Policy': 'SAME-ORIGIN-ALLOW-POPUPS' };
  const result = guard.applyCrossOriginPolicyGuard(headers);
  assert.strictEqual(result.changed, false);
});

test('COEP unsafe-none 搭配 COOP same-origin 收紧为 credentialless', () => {
  const headers = {
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Embedder-Policy': 'unsafe-none',
  };
  const result = guard.applyCrossOriginPolicyGuard(headers);
  assert.strictEqual(headers['Cross-Origin-Embedder-Policy'], 'credentialless');
  assert.strictEqual(result.findings[0].reason, guard.REASON.DOWNGRADED);
});

test('COEP unsafe-none 单独出现保持原样', () => {
  const headers = { 'Cross-Origin-Embedder-Policy': 'unsafe-none' };
  guard.applyCrossOriginPolicyGuard(headers);
  assert.strictEqual(headers['Cross-Origin-Embedder-Policy'], 'unsafe-none');
});

test('COEP 非法取值被移除', () => {
  const headers = { 'Cross-Origin-Embedder-Policy': 'require-cors' };
  guard.applyCrossOriginPolicyGuard(headers);
  assert.strictEqual('Cross-Origin-Embedder-Policy' in headers, false);
});

test('超长取值按非法处理', () => {
  const headers = { 'Cross-Origin-Resource-Policy': 'x'.repeat(guard.MAX_VALUE_LENGTH + 1) };
  guard.applyCrossOriginPolicyGuard(headers);
  assert.strictEqual('Cross-Origin-Resource-Policy' in headers, false);
});

test('ACAO 通配大小写不敏感', () => {
  const headers = {
    'cross-origin-resource-policy': 'cross-origin',
    'access-control-allow-origin': ['*'],
  };
  const result = guard.applyCrossOriginPolicyGuard(headers);
  assert.strictEqual(result.wildcard, true);
  assert.strictEqual(headers['cross-origin-resource-policy'], 'same-origin');
});

test('describeReason 覆盖全部原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
