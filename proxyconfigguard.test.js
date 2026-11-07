'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./proxyconfigguard');

test('直连模式通过', () => {
  const r = guard.applyProxyConfigGuard({ mode: 'direct' });
  assert.strictEqual(r.changed, false);
  assert.deepStrictEqual(r.sanitized, { mode: 'direct' });
});

test('HTTPS PAC 通过并强制 mandatory', () => {
  const r = guard.applyProxyConfigGuard({ mode: 'pac_script', pacScript: { url: 'https://example.com/proxy.pac' } });
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.sanitized.pacScript.mandatory, true);
});

test('HTTP PAC 被拒', () => {
  const r = guard.inspectProxyConfig({ mode: 'pac_script', pacScript: { url: 'http://example.com/proxy.pac' } });
  assert.strictEqual(r.reason, guard.REASON.INSECURE_PAC);
});

test('file PAC 被拒', () => {
  const r = guard.inspectProxyConfig({ mode: 'pac_script', pacScript: { url: 'file:///tmp/proxy.pac' } });
  assert.strictEqual(r.reason, guard.REASON.PAC_FILE);
});

test('内嵌账号密码被拒', () => {
  const r = guard.inspectProxyConfig({ mode: 'pac_script', pacScript: { url: 'https://user:pass@example.com/proxy.pac' } });
  assert.strictEqual(r.reason, guard.REASON.USERINFO);
});

test('固定代理通过', () => {
  const r = guard.applyProxyConfigGuard({ mode: 'fixed_servers', rules: { scheme: 'https', host: 'proxy.example.com', port: 8443, bypassList: ['localhost', '<local>', '*.example.com'] } });
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.sanitized.rules.port, 8443);
});

test('非法端口被拒', () => {
  const r = guard.inspectProxyConfig({ mode: 'fixed_servers', rules: { host: 'proxy.example.com', port: 70000 } });
  assert.strictEqual(r.reason, guard.REASON.BAD_HOST);
});

test('非法协议被拒', () => {
  const r = guard.inspectProxyConfig({ mode: 'fixed_servers', rules: { scheme: 'ftp', host: 'proxy.example.com', port: 21 } });
  assert.strictEqual(r.reason, guard.REASON.BAD_SCHEME);
});

test('绕过列表含协议被拒', () => {
  const r = guard.inspectProxyConfig({ mode: 'fixed_servers', rules: { host: 'proxy.example.com', port: 8080, bypassList: ['https://evil.example.com'] } });
  assert.strictEqual(r.reason, guard.REASON.BAD_BYPASS);
});

test('非法模式被拒', () => {
  const r = guard.inspectProxyConfig({ mode: 'auto' });
  assert.strictEqual(r.reason, guard.REASON.INVALID_MODE);
});

test('空配置被拒', () => {
  const r = guard.inspectProxyConfig(null);
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
});

test('描述文本覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
