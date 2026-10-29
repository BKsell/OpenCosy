'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const c = require('./credentialbreachcheck');

test('常见弱口令拦', () => {
  const r = c.evaluatePassword('password');
  assert.equal(r.ok, false);
  assert.ok(r.reasons.includes('common-weak'));
});

test('过短拦', () => {
  const r = c.evaluatePassword('Ab1!');
  assert.equal(r.ok, false);
  assert.ok(r.reasons.includes('too-short'));
});

test('纯重复字符拦', () => {
  const r = c.evaluatePassword('aaaaaaaaaaaa');
  assert.equal(r.ok, false);
  assert.ok(r.reasons.includes('repeated-char'));
});

test('纯序列拦', () => {
  const r = c.evaluatePassword('Abcdefgh1!');
  assert.equal(r.ok, false);
  assert.ok(r.reasons.includes('sequential'));
});

test('强口令放行', () => {
  const r = c.evaluatePassword('Xk9#vL2!qZ$mW3&p');
  assert.equal(r.ok, true);
  assert.equal(r.score >= 3, true);
});

test('shouldWarnBeforeSave', () => {
  assert.equal(c.shouldWarnBeforeSave('123456'), true);
  assert.equal(c.shouldWarnBeforeSave('Xk9#vL2!qZ$mW3&p'), false);
});

test('isSequence', () => {
  assert.equal(c.isSequence('abcd'), true);
  assert.equal(c.isSequence('ab1d'), false);
});
