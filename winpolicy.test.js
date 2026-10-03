'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const wp = require('./winpolicy');

const APP_ROOT = path.resolve('/opt/opencosy');

test('正确安全配置原样保留并补全', () => {
  const { prefs, findings } = wp.harden({
    nodeIntegration: false,
    contextIsolation: true,
    sandbox: true,
    webSecurity: true,
    allowRunningInsecureContent: false,
    spellcheck: true,
    preload: path.join(APP_ROOT, 'preload.js'),
  }, { preloadRoots: APP_ROOT });

  assert.equal(prefs.nodeIntegration, false);
  assert.equal(prefs.contextIsolation, true);
  assert.equal(prefs.sandbox, true);
  assert.equal(prefs.webSecurity, true);
  assert.equal(prefs.spellcheck, true);
  assert.equal(prefs.preload, path.join(APP_ROOT, 'preload.js'));
  assert.equal(wp.hasCritical(findings), false);
});

test('不安全配置被强制覆盖并记 critical', () => {
  const { prefs, findings } = wp.harden({
    nodeIntegration: true,
    contextIsolation: false,
    sandbox: false,
    webSecurity: false,
    allowRunningInsecureContent: true,
    enableRemoteModule: true,
    webviewTag: true,
    preload: path.join(APP_ROOT, 'preload.js'),
  }, { preloadRoots: APP_ROOT });

  assert.equal(prefs.nodeIntegration, false);
  assert.equal(prefs.contextIsolation, true);
  assert.equal(prefs.sandbox, true);
  assert.equal(prefs.webSecurity, true);
  assert.equal(prefs.allowRunningInsecureContent, false);
  assert.equal(prefs.enableRemoteModule, false);
  assert.equal(prefs.webviewTag, false);
  assert.equal(wp.hasCritical(findings), true);
});

test('额外 Blink / 实验特性被丢弃', () => {
  const { prefs, findings } = wp.harden({
    enableBlinkFeatures: 'IdleDetection,WebGL',
    experimentalFeatures: true,
    plugins: true,
    preload: path.join(APP_ROOT, 'preload.js'),
  }, { preloadRoots: APP_ROOT });
  assert.equal(prefs.enableBlinkFeatures, undefined);
  assert.equal(prefs.experimentalFeatures, false);
  assert.equal(prefs.plugins, false);
  assert.ok(findings.some((f) => f.key === 'enableBlinkFeatures'));
});

test('preload 路径穿越 / 外部 preload 被拒', () => {
  const traversal = wp.harden({
    preload: path.join(APP_ROOT, '..', '..', 'evil', 'preload.js'),
  }, { preloadRoots: APP_ROOT });
  assert.equal(traversal.prefs.preload, undefined);
  assert.ok(traversal.findings.some((f) => f.key === 'preload' && f.severity === 'critical'));

  const outside = wp.harden({ preload: '/tmp/evil.js' }, { preloadRoots: APP_ROOT });
  assert.equal(outside.prefs.preload, undefined);
  assert.equal(wp.hasCritical(outside.findings), true);
});

test('缺少必须 preload 记 critical', () => {
  const r = wp.harden({}, { preloadRoots: APP_ROOT, requirePreload: true });
  assert.ok(r.findings.some((f) => f.key === 'preload'));
  assert.equal(wp.hasCritical(r.findings), true);

  const ok = wp.harden({ preload: path.join(APP_ROOT, 'preload.js') },
    { preloadRoots: APP_ROOT, requirePreload: true });
  assert.equal(wp.hasCritical(ok.findings), false);
});

test('isInsideRoot 边界', () => {
  assert.equal(wp.isInsideRoot(path.join(APP_ROOT, 'preload.js'), APP_ROOT), true);
  assert.equal(wp.isInsideRoot(APP_ROOT, APP_ROOT), true);
  assert.equal(wp.isInsideRoot(path.join(APP_ROOT, '..', 'x.js'), APP_ROOT), false);
  assert.equal(wp.isInsideRoot('', APP_ROOT), false);
  assert.equal(wp.isInsideRoot('/etc/passwd', APP_ROOT), false);
});

test('未登记的 webPreferences 选项不透传并告警', () => {
  const r = wp.harden({
    someFutureDangerousOption: true,
    preload: path.join(APP_ROOT, 'preload.js'),
  }, { preloadRoots: APP_ROOT });
  assert.equal(r.prefs.someFutureDangerousOption, undefined);
  assert.ok(r.findings.some((f) => f.key === 'someFutureDangerousOption' && f.severity === 'warn'));
});

test('空输入不抛错', () => {
  assert.doesNotThrow(() => wp.harden(null, {}));
  assert.doesNotThrow(() => wp.harden(undefined, undefined));
});
