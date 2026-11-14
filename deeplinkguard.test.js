'use strict';

const test = require('node:test');
const assert = require('node:assert');
const schemes = require('./deeplinkguard_schemes_core');
const { pickDeepLinkFromArgv } = require('./deeplinkguard_core');

test('reviewStartupArg rejects web deeplinks carrying credentials', () => {
  assert.deepEqual(schemes.reviewStartupArg('https://user:pw@evil.example/x'), {
    ok: false, kind: 'web', reason: 'userinfo',
  });
  assert.deepEqual(schemes.reviewStartupArg('http://user@evil.example/x'), {
    ok: false, kind: 'web', reason: 'userinfo',
  });
});

test('reviewStartupArg keeps plain web deeplinks', () => {
  assert.equal(schemes.reviewStartupArg('https://example.com/a?b=1').ok, true);
  assert.equal(schemes.reviewStartupArg('http://example.com/').kind, 'web');
});

test('reviewStartupArg restricts cosy hosts to the whitelist', () => {
  assert.equal(schemes.reviewStartupArg('cosy://setting/tab').host, 'setting');
  assert.deepEqual(schemes.reviewStartupArg('cosy://evil/x'), {
    ok: false, kind: 'internal', reason: 'host',
  });
});

test('reviewStartupArg rejects traversal, switches and unknown schemes', () => {
  assert.equal(schemes.reviewStartupArg('C:\\tmp\\..\\evil.html').reason, 'traversal');
  assert.equal(schemes.reviewStartupArg('--disable-sandbox').reason, 'switch-like');
  assert.equal(schemes.reviewStartupArg('javascript:alert(1)').reason, 'scheme');
});

test('pickDeepLinkFromArgv skips switches and picks the first valid link', () => {
  const link = pickDeepLinkFromArgv(
    ['cosy.exe', '--flag', 'https://example.com/', 'cosy://setting/x'],
    new Set(['setting']),
  );
  assert.equal(link.kind, 'web');
  assert.equal(link.value, 'https://example.com/');
});
