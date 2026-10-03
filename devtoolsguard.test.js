'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  ACTION_OPEN_TAB,
  ACTION_BLOCK,
  REASON_ALLOW_HTTP,
  REASON_ALLOW_COSY,
  REASON_MALFORMED,
  REASON_EMPTY,
  REASON_DANGEROUS_SCHEME,
  REASON_UNSUPPORTED_SCHEME,
  decideDevToolsUrl,
  describeDevToolsReason,
} = require('./devtoolsguard');

test('http/https 链接转入受控标签页', () => {
  const http = decideDevToolsUrl('http://example.test/a');
  assert.equal(http.action, ACTION_OPEN_TAB);
  assert.equal(http.reason, REASON_ALLOW_HTTP);
  assert.equal(http.scheme, 'http:');
  assert.equal(http.origin, 'http://example.test');

  const https = decideDevToolsUrl('  https://example.test/b?x=1  ');
  assert.equal(https.action, ACTION_OPEN_TAB);
  assert.equal(https.url, 'https://example.test/b?x=1');
  assert.equal(https.origin, 'https://example.test');
});

test('内部 cosy: 链接允许应用内打开', () => {
  const r = decideDevToolsUrl('cosy://setting');
  assert.equal(r.action, ACTION_OPEN_TAB);
  assert.equal(r.reason, REASON_ALLOW_COSY);
  assert.equal(r.scheme, 'cosy:');
});

test('危险协议一律拦截', () => {
  const danger = [
    'file:///C:/Windows/System32/calc.exe',
    'file:///etc/passwd',
    'javascript:alert(1)',
    'vbscript:msgbox(1)',
    'data:text/html,<script>1</script>',
    'blob:https://a.test/uuid',
    'filesystem:https://a.test/t/x',
    'about:blank',
  ];
  for (const u of danger) {
    const r = decideDevToolsUrl(u);
    assert.equal(r.action, ACTION_BLOCK, `${u} 应被拦截`);
    assert.equal(r.reason, REASON_DANGEROUS_SCHEME, `${u} 应为危险协议`);
  }
});

test('外部应用协议默认拒绝', () => {
  const ext = [
    'mailto:x@y.test',
    'tel:12345',
    'msteams:/l/...',
    'custom-app://do/something',
    'steam://run/123',
  ];
  for (const u of ext) {
    const r = decideDevToolsUrl(u);
    assert.equal(r.action, ACTION_BLOCK, `${u} 应被拒绝`);
    assert.equal(r.reason, REASON_UNSUPPORTED_SCHEME, `${u} 应为不支持协议`);
  }
});

test('大小写混合的危险协议仍被识别（协议大小写不敏感）', () => {
  const r = decideDevToolsUrl('JaVaScRiPt:alert(1)');
  assert.equal(r.action, ACTION_BLOCK);
  assert.equal(r.reason, REASON_DANGEROUS_SCHEME);
});

test('空与畸形 URL 被拦截', () => {
  assert.equal(decideDevToolsUrl('').action, ACTION_BLOCK);
  assert.equal(decideDevToolsUrl('   ').reason, REASON_EMPTY);
  assert.equal(decideDevToolsUrl(null).reason, REASON_EMPTY);
  assert.equal(decideDevToolsUrl(undefined).reason, REASON_EMPTY);
  assert.equal(decideDevToolsUrl(123).reason, REASON_EMPTY);
  assert.equal(decideDevToolsUrl('not a url at all').reason, REASON_MALFORMED);
});

test('放行时返回规范化绝对 URL', () => {
  const r = decideDevToolsUrl('https://a.test/x/../y');
  assert.equal(r.action, ACTION_OPEN_TAB);
  assert.equal(r.url, 'https://a.test/y');
});

test('所有原因码都有中文说明', () => {
  for (const reason of [
    REASON_ALLOW_HTTP, REASON_ALLOW_COSY, REASON_MALFORMED, REASON_EMPTY,
    REASON_DANGEROUS_SCHEME, REASON_UNSUPPORTED_SCHEME,
  ]) {
    assert.ok(describeDevToolsReason(reason).length > 0, `${reason} 缺说明`);
  }
  assert.ok(describeDevToolsReason('nope').length > 0);
});
