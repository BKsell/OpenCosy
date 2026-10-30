'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const d = require('./dnsthemebypass');

test('页面只支持 light 但 shell 是 dark，拒绝覆盖', () => {
  const r = d.decideColorSchemeOverride({
    shellTheme: 'dark',
    pageMetaScheme: ['light'],
  });
  assert.equal(r.effective, 'dark');
  assert.equal(r.allowPageOverride, false);
});

test('页面同时支持 light/dark，允许', () => {
  const r = d.decideColorSchemeOverride({
    shellTheme: 'dark',
    pageMetaScheme: ['light', 'dark'],
  });
  assert.equal(r.allowPageOverride, true);
});

test('用户信任源可强制覆盖', () => {
  const r = d.decideColorSchemeOverride({
    shellTheme: 'dark',
    pageMetaScheme: ['light'],
    userTrustOrigin: true,
  });
  assert.equal(r.allowPageOverride, true);
});

test('空 meta 默认跟随 shell', () => {
  const r = d.decideColorSchemeOverride({ shellTheme: 'light' });
  assert.equal(r.effective, 'light');
});

test('isRiskyInversionCss 识别 filter:invert', () => {
  assert.equal(d.isRiskyInversionCss('body { filter: invert(1) }'), true);
  assert.equal(d.isRiskyInversionCss('body { color: red }'), false);
  assert.equal(d.isRiskyInversionCss(''), false);
});
