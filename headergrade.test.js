'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  getResponseHeader,
  letterForScore,
  parseHstsMaxAge,
  gradeSecurityHeaders,
} = require('./headergrade');

test('getResponseHeader is case-insensitive and handles arrays/strings', () => {
  const h = { 'Content-Type': ['text/html; charset=utf-8'], 'X-Test': 'abc' };
  assert.equal(getResponseHeader(h, 'content-type'), 'text/html; charset=utf-8');
  assert.equal(getResponseHeader(h, 'X-TEST'), 'abc');
  assert.equal(getResponseHeader(h, 'missing'), '');
  assert.equal(getResponseHeader(null, 'x'), '');
});

test('letterForScore maps percent bands', () => {
  assert.equal(letterForScore(100), 'A');
  assert.equal(letterForScore(90), 'A');
  assert.equal(letterForScore(75), 'B');
  assert.equal(letterForScore(60), 'C');
  assert.equal(letterForScore(40), 'D');
  assert.equal(letterForScore(39), 'F');
});

test('parseHstsMaxAge reads numeric max-age', () => {
  assert.equal(parseHstsMaxAge('max-age=31536000; includeSubDomains'), 31536000);
  assert.equal(parseHstsMaxAge('max-age=0'), 0);
  assert.equal(parseHstsMaxAge(''), -1);
  assert.equal(parseHstsMaxAge('no-store'), -1);
});

test('site with no security headers scores F', () => {
  const g = gradeSecurityHeaders('https://example.com/', { 'Content-Type': ['text/html'] });
  assert.equal(g.scheme, 'https');
  assert.equal(g.host, 'example.com');
  assert.equal(g.grade, 'F');
  assert.ok(g.percent < 40);
  for (const c of g.checks) assert.notEqual(c.status, 'pass');
});

test('hardened https site scores A', () => {
  const g = gradeSecurityHeaders('https://hardened.test/', {
    'Strict-Transport-Security': ['max-age=31536000; includeSubDomains'],
    'Content-Security-Policy': ["default-src 'self'; object-src 'none'; frame-ancestors 'none'"],
    'X-Content-Type-Options': ['nosniff'],
    'X-Frame-Options': ['DENY'],
    'Referrer-Policy': ['strict-origin-when-cross-origin'],
    'Permissions-Policy': ['geolocation=(), camera=()'],
    'Cross-Origin-Opener-Policy': ['same-origin'],
    'Cross-Origin-Resource-Policy': ['same-origin'],
    'Cross-Origin-Embedder-Policy': ['require-corp'],
  });
  assert.equal(g.grade, 'A');
  assert.ok(g.percent >= 90, `expected >=90 got ${g.percent}`);
  for (const c of g.checks) assert.equal(c.status, 'pass', `${c.id} should pass`);
});

test('CSP with unsafe-inline is only partial', () => {
  const g = gradeSecurityHeaders('https://x.test/', {
    'Content-Security-Policy': ["default-src 'self'; script-src 'self' 'unsafe-inline'"],
  });
  const csp = g.checks.find(c => c.id === 'csp');
  assert.equal(csp.status, 'partial');
});

test('plaintext HTTP is capped regardless of headers', () => {
  const g = gradeSecurityHeaders('http://legacy.test/', {
    'X-Content-Type-Options': ['nosniff'],
  });
  assert.equal(g.insecureTransport, true);
  assert.ok(g.percent <= 59);
  assert.notEqual(g.grade, 'A');
  assert.notEqual(g.grade, 'B');
});

test('information-leaking headers are surfaced as warnings', () => {
  const g = gradeSecurityHeaders('https://leaky.test/', {
    'X-Powered-By': ['PHP/5.4.0'],
    'Server': ['Apache/2.4.41'],
    'Strict-Transport-Security': ['max-age=31536000'],
  });
  assert.ok(g.warnings.some(w => w.includes('X-Powered-By')));
  assert.ok(g.warnings.some(w => w.includes('Server')));
  assert.ok(g.warnings.some(w => w.includes('includeSubDomains')));
});

test('bad url does not throw', () => {
  const g = gradeSecurityHeaders('not a url', {});
  assert.equal(typeof g.grade, 'string');
  assert.equal(g.scheme, '');
});
