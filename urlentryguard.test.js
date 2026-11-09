'use strict';

const test = require('node:test');
const assert = require('node:assert');

const guard = require('./urlentryguard');

const reasons = {
  empty: 'empty',
  tooLong: 'too-long',
  badUrl: 'bad-url',
  badProtocol: 'bad-protocol',
  credentials: 'credentials',
};

test('sanitizeWebUrl rejects empty and non-string input', () => {
  assert.strictEqual(guard.sanitizeWebUrl('', reasons, guard.MAX_URL_CHARS).reason, 'empty');
  assert.strictEqual(guard.sanitizeWebUrl(null, reasons, guard.MAX_URL_CHARS).reason, 'empty');
});

test('sanitizeWebUrl rejects over-long input before parsing', () => {
  const long = 'https://example.com/' + 'a'.repeat(guard.MAX_URL_CHARS);
  assert.strictEqual(guard.sanitizeWebUrl(long, reasons, guard.MAX_URL_CHARS).reason, 'too-long');
});

test('sanitizeWebUrl rejects malformed and empty-host URLs', () => {
  assert.strictEqual(guard.sanitizeWebUrl('not a url', reasons, guard.MAX_URL_CHARS).reason, 'bad-url');
  assert.strictEqual(guard.sanitizeWebUrl('https://', reasons, guard.MAX_URL_CHARS).reason, 'bad-url');
});

test('sanitizeWebUrl rejects non-http schemes', () => {
  for (const u of ['javascript:alert(1)', 'file:///c:/x', 'data:text/html,<b>x']) {
    assert.strictEqual(guard.sanitizeWebUrl(u, reasons, guard.MAX_URL_CHARS).reason, 'bad-protocol');
  }
});

test('sanitizeWebUrl rejects URLs carrying embedded credentials', () => {
  const r = guard.sanitizeWebUrl('https://user:pass@example.com/x', reasons, guard.MAX_URL_CHARS);
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.reason, 'credentials');
});

test('sanitizeWebUrl falls back to bad-url when no credentials reason is supplied', () => {
  const r = guard.sanitizeWebUrl('https://user:pass@example.com/x', { badUrl: 'bad-url' }, guard.MAX_URL_CHARS);
  assert.strictEqual(r.reason, 'bad-url');
});

test('sanitizeWebUrl returns normalized href for http and https', () => {
  const r = guard.sanitizeWebUrl('HTTPS://Example.COM/a', reasons, guard.MAX_URL_CHARS);
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.url, 'https://example.com/a');
  assert.deepStrictEqual([...guard.ALLOWED_PROTOCOLS], ['http:', 'https:']);
});
