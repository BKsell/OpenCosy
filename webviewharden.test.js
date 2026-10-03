'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const wv = require('./webviewharden');

test('合法 https guest 通过并拿到安全基线', () => {
  const r = wv.review({}, { src: 'https://example.com/app' });
  assert.equal(r.blocked, false);
  assert.equal(r.prefs.nodeIntegration, false);
  assert.equal(r.prefs.contextIsolation, true);
  assert.equal(r.prefs.sandbox, true);
  assert.equal(r.prefs.webSecurity, true);
  assert.equal(r.prefs.webviewTag, false);
  assert.equal(r.prefs.preload, undefined);
});

test('危险 src 全部阻断', () => {
  const srcs = [
    '',
    'not-a-url',
    'file:///C:/Windows/win.ini',
    'cosy://security',
    'data:text/html,<script>1</script>',
    'blob:https://example.com/u',
    'javascript:alert(1)',
    'about:blank',
    'https://user:pass@example.com/',
  ];
  for (const src of srcs) {
    const r = wv.review({}, { src });
    assert.equal(r.blocked, true, `src=${src} 应阻断`);
  }
});

test('http src 放行（仅协议层，mixed content 另有模块管）', () => {
  const r = wv.review({}, { src: 'http://localhost:3000/' });
  assert.equal(r.blocked, false);
});

test('提权配置被记录并被安全基线覆盖', () => {
  const r = wv.review({
    nodeIntegration: true,
    nodeIntegrationInSubFrames: true,
    contextIsolation: false,
    sandbox: false,
    webSecurity: false,
    allowRunningInsecureContent: true,
    enableRemoteModule: true,
    webviewTag: true,
    plugins: true,
    experimentalFeatures: true,
    enableBlinkFeatures: 'IdleDetection',
    allowPopups: true,
    preload: 'C:\\attacker\\preload.js',
    additionalPreferencesBlob: 'something',
  }, { src: 'https://example.com/' });

  assert.equal(r.blocked, false); // src 合法不阻断，但配置被强制收口
  for (const reason of [
    'node-integration', 'context-isolation-off', 'sandbox-off', 'web-security-off',
    'insecure-content', 'remote-module', 'nested-webview-tag', 'guest-preload',
  ]) {
    assert.ok(r.reasons.includes(reason), `应记录 ${reason}`);
  }
  assert.equal(r.prefs.nodeIntegration, false);
  assert.equal(r.prefs.enableBlinkFeatures, '');
  assert.equal(r.prefs.preload, undefined);
});

test('主会话分区被拦，独立分区保留', () => {
  const bad = ['', 'default', 'persist:default'];
  for (const p of bad) {
    const r = wv.review({ partition: p }, { src: 'https://example.com/' });
    assert.ok(r.reasons.includes('shared-default-partition'));
    assert.equal(r.prefs.partition, undefined);
  }
  const ok = wv.review({ partition: 'persist:guest-123' }, { src: 'https://example.com/' });
  assert.equal(ok.prefs.partition, 'persist:guest-123');
});

test('附加参数默认全拒，白名单内保留，数量有界', () => {
  const r1 = wv.review({ additionalArguments: ['--evil=x', 7] }, { src: 'https://e.com' });
  assert.deepEqual(r1.prefs.additionalArguments, []);
  assert.ok(r1.reasons.includes('additional-args-stripped'));

  const r2 = wv.review(
    { additionalArguments: ['SAFE_TOKEN', 'evil'] },
    { src: 'https://e.com' },
    { allowedArgs: ['SAFE_TOKEN'] },
  );
  assert.deepEqual(r2.prefs.additionalArguments, ['SAFE_TOKEN']);

  const many = Array.from({ length: wv.MAX_ADDITIONAL_ARGS + 5 }, (_, i) => `K${i}`);
  const r3 = wv.review({ additionalArguments: many }, { src: 'https://e.com' },
    { allowedArgs: new Set(many) });
  assert.equal(r3.prefs.additionalArguments.length, wv.MAX_ADDITIONAL_ARGS);
});

test('空 / 异常入参不抛错', () => {
  assert.doesNotThrow(() => wv.review(null, null));
  assert.equal(wv.review(undefined, undefined).blocked, true);
});

test('审计说明稳定且不回显输入', () => {
  const r = wv.review({ preload: '/secret/path.js' }, { src: 'file:///secret' });
  for (const reason of r.reasons) {
    assert.equal(wv.describeReason(reason).includes('/secret'), false);
  }
});
