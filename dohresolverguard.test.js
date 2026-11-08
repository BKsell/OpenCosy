'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');

const guard = require('./dohresolverguard.js');

const root = path.join(os.tmpdir(), 'cosy-guard-root');

test('allows allowlisted doh endpoint', () => {
  const result = guard.evaluateDohEndpoint('https://dns.example.com/dns-query', { allowHosts: ['*.example.com'] });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.blocked, false);
  assert.strictEqual(result.reason, guard.REASON.OK);
});

test('blocks plaintext doh', () => {
  const result = guard.evaluateDohEndpoint('http://dns.example.com/dns-query', { allowHosts: ['*.example.com'] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.PLAINTEXT);
});

test('blocks loopback doh', () => {
  const result = guard.evaluateDohEndpoint('https://127.0.0.1/dns-query', { allowHosts: ['*.example.com'] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.LOOPBACK);
});

test('blocks host outside allowlist', () => {
  const result = guard.evaluateDohEndpoint('https://evil.com/dns-query', { allowHosts: ['*.example.com'] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.HOST_NOT_ALLOWED);
});

test('blocks endpoint without dns-query path', () => {
  const result = guard.evaluateDohEndpoint('https://dns.example.com/resolve', { allowHosts: ['*.example.com'] });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.reason, guard.REASON.TEMPLATE_INVALID);
});

