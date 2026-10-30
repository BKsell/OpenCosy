'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const d = require('./dnttransmit');

test('enabled + https 发 DNT:1', () => {
  const r = d.decideDntHeader({ userPreference: 'enabled', requestUrl: 'https://a.com' });
  assert.equal(r.value, '1');
});

test('disabled 不发', () => {
  const r = d.decideDntHeader({ userPreference: 'disabled', requestUrl: 'https://a.com' });
  assert.equal(r.value, null);
});

test('unspecified 不发', () => {
  const r = d.decideDntHeader({ userPreference: 'unspecified', requestUrl: 'https://a.com' });
  assert.equal(r.value, null);
});

test('非 http(s) 不发', () => {
  const r = d.decideDntHeader({ userPreference: 'enabled', requestUrl: 'file:///etc/passwd' });
  assert.equal(r.value, null);
});

test('Sec-GPC 跟随 enabled', () => {
  assert.equal(d.shouldSendSecGpcHeader('enabled'), true);
  assert.equal(d.shouldSendSecGpcHeader('disabled'), false);
});
