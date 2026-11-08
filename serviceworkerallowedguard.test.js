'use strict';

const test = require('node:test');
const assert = require('node:assert');

const guard = require('./serviceworkerallowedguard');

test('missing header is untouched', () => {
  const headers = {};
  const result = guard.applyServiceWorkerAllowedGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.MISSING);
});

test('absolute scope is accepted', () => {
  const headers = { 'service-worker-allowed': '/' };
  const result = guard.applyServiceWorkerAllowedGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(headers['service-worker-allowed'], '/');
});

test('nested scope is accepted', () => {
  const headers = { 'Service-Worker-Allowed': '/app/' };
  const result = guard.applyServiceWorkerAllowedGuard(headers);
  assert.equal(result.changed, false);
});

test('traversal scope is removed', () => {
  const headers = { 'service-worker-allowed': '/app/../secret/' };
  const result = guard.applyServiceWorkerAllowedGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(result.reason, guard.REASON.TRAVERSAL);
  assert.equal(headers['service-worker-allowed'], undefined);
});

test('relative scope is removed', () => {
  const headers = { 'service-worker-allowed': 'app/' };
  const result = guard.applyServiceWorkerAllowedGuard(headers);
  assert.equal(result.reason, guard.REASON.OUTSIDE_ORIGIN);
  assert.equal(headers['service-worker-allowed'], undefined);
});

test('absolute url is removed', () => {
  const headers = { 'service-worker-allowed': 'https://evil.example/' };
  const result = guard.applyServiceWorkerAllowedGuard(headers);
  assert.equal(result.reason, guard.REASON.OUTSIDE_ORIGIN);
  assert.equal(headers['service-worker-allowed'], undefined);
});

test('empty value is removed', () => {
  const headers = { 'service-worker-allowed': '   ' };
  const result = guard.applyServiceWorkerAllowedGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
  assert.equal(headers['service-worker-allowed'], undefined);
});

test('overlong value is removed', () => {
  const headers = { 'service-worker-allowed': '/' + 'a'.repeat(guard.MAX_VALUE_LENGTH) };
  const result = guard.applyServiceWorkerAllowedGuard(headers);
  assert.equal(result.reason, guard.REASON.TOO_LONG);
  assert.equal(headers['service-worker-allowed'], undefined);
});

test('control character is rejected', () => {
  assert.equal(guard.scopePath('/a\u0000b'), '');
});

test('scopeCovers matches exact and prefix', () => {
  assert.equal(guard.scopeCovers('/', '/sw.js'), true);
  assert.equal(guard.scopeCovers('/app/', '/app/sw.js'), true);
  assert.equal(guard.scopeCovers('/app', '/app/sw.js'), true);
  assert.equal(guard.scopeCovers('/app', '/other/sw.js'), false);
  assert.equal(guard.scopeCovers('', '/sw.js'), false);
});

test('describeReason covers branches', () => {
  assert.equal(guard.describeReason(guard.REASON.MISSING), '响应未声明服务工作线程作用域');
  assert.equal(guard.describeReason('other'), '服务工作线程作用域合法');
});
