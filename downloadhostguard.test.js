'use strict';

const test = require('node:test');
const assert = require('node:assert');
const hostGuard = require('./downloadhostguard');

function check(url, options) {
  return hostGuard.evaluateDownloadUrl(url, options);
}

test('https 公网地址放行', () => {
  const result = check('https://example.com/files/mod.jar');
  assert.strictEqual(result.action, hostGuard.ACTION.ALLOW);
  assert.strictEqual(result.reason, hostGuard.REASON.OK);
  assert.strictEqual(result.host, 'example.com');
  assert.strictEqual(result.port, 443);
});

test('http 明文降级为告警', () => {
  const result = check('http://example.com/a.zip');
  assert.strictEqual(result.action, hostGuard.ACTION.WARN);
  assert.strictEqual(result.reason, hostGuard.REASON.INSECURE_SCHEME);
});

test('HTTPS-only 拒绝 http', () => {
  const result = check('http://example.com/a.zip', { requireHttps: true });
  assert.strictEqual(result.action, hostGuard.ACTION.BLOCK);
  assert.strictEqual(result.reason, hostGuard.REASON.INSECURE_SCHEME);
});

test('非 http 协议拒绝', () => {
  const result = check('ftp://example.com/a.zip');
  assert.strictEqual(result.action, hostGuard.ACTION.BLOCK);
  assert.strictEqual(result.reason, hostGuard.REASON.BAD_SCHEME);
});

test('file 协议拒绝', () => {
  const result = check('file:///C:/Windows/win.ini');
  assert.strictEqual(result.action, hostGuard.ACTION.BLOCK);
  assert.strictEqual(result.reason, hostGuard.REASON.BAD_SCHEME);
});

test('URL 内嵌账号密码拒绝', () => {
  const result = check('https://user:pass@example.com/a.zip');
  assert.strictEqual(result.action, hostGuard.ACTION.BLOCK);
  assert.strictEqual(result.reason, hostGuard.REASON.USERINFO);
});

test('回环地址拒绝', () => {
  const result = check('http://127.0.0.1:8080/admin');
  assert.strictEqual(result.action, hostGuard.ACTION.BLOCK);
  assert.strictEqual(result.reason, hostGuard.REASON.PRIVATE_ADDRESS);
});

test('内网 192.168 拒绝', () => {
  const result = check('http://192.168.1.1/router.cfg');
  assert.strictEqual(result.reason, hostGuard.REASON.PRIVATE_ADDRESS);
  assert.strictEqual(result.action, hostGuard.ACTION.BLOCK);
});

test('内网 10.x 拒绝', () => {
  const result = check('https://10.1.2.3/internal.zip');
  assert.strictEqual(result.reason, hostGuard.REASON.PRIVATE_ADDRESS);
});

test('链路本地 169.254 拒绝', () => {
  const result = check('http://169.254.169.254/latest/meta-data/');
  assert.strictEqual(result.reason, hostGuard.REASON.PRIVATE_ADDRESS);
});

test('IPv6 回环拒绝', () => {
  const result = check('http://[::1]:9000/a.zip');
  assert.strictEqual(result.reason, hostGuard.REASON.PRIVATE_ADDRESS);
});

test('IPv6 唯一本地地址拒绝', () => {
  const result = check('http://[fd00::1]/a.zip');
  assert.strictEqual(result.reason, hostGuard.REASON.PRIVATE_ADDRESS);
});

test('localhost 拒绝', () => {
  const result = check('https://localhost/a.zip');
  assert.strictEqual(result.reason, hostGuard.REASON.LOCAL_HOST);
});

test('.local 域名拒绝', () => {
  const result = check('https://printer.local/status');
  assert.strictEqual(result.reason, hostGuard.REASON.LOCAL_HOST);
});

test('受限端口 445 拒绝', () => {
  const result = check('https://example.com:445/share.zip');
  assert.strictEqual(result.action, hostGuard.ACTION.BLOCK);
  assert.strictEqual(result.reason, hostGuard.REASON.RESTRICTED_PORT);
});

test('非常规高位端口放行', () => {
  const result = check('https://example.com:8443/a.zip');
  assert.strictEqual(result.action, hostGuard.ACTION.ALLOW);
});

test('punycode 主机告警', () => {
  const result = check('https://xn--80ak6aa92e.com/a.zip');
  assert.strictEqual(result.action, hostGuard.ACTION.WARN);
  assert.strictEqual(result.reason, hostGuard.REASON.PUNYCODE_HOST);
});

test('超长 URL 拒绝', () => {
  const result = check(`https://example.com/${'a'.repeat(hostGuard.MAX_URL_BYTES)}`);
  assert.strictEqual(result.reason, hostGuard.REASON.TOO_LONG);
});

test('控制字符拒绝', () => {
  const result = check('https://example.com/a\u0000.zip');
  assert.strictEqual(result.reason, hostGuard.REASON.CONTROL_CHAR);
});

test('非法 URL 拒绝', () => {
  const result = check('ht!tp://example.com/a.zip');
  assert.strictEqual(result.reason, hostGuard.REASON.INVALID_URL);
});

test('残缺 URL 拒绝', () => {
  const result = check('https://');
  assert.strictEqual(result.reason, hostGuard.REASON.INVALID_URL);
});

test('描述函数输出原因', () => {
  const result = check('http://127.0.0.1/a.zip');
  assert.ok(hostGuard.describeDownloadUrl(result).includes(hostGuard.REASON.PRIVATE_ADDRESS));
});
