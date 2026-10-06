'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { safeOrigin, safeHostname, safeHost, safeProtocol } = require('./urlresolve');

test('safeOrigin 正常解析与端口保留', () => {
  assert.strictEqual(safeOrigin('https://example.com/a?b=1'), 'https://example.com');
  assert.strictEqual(safeOrigin('http://127.0.0.1:8080/x'), 'http://127.0.0.1:8080');
  assert.strictEqual(safeOrigin('https://a.example.com:443/'), 'https://a.example.com');
});

test('safeOrigin 非法/空输入回落到 fallback', () => {
  assert.strictEqual(safeOrigin('not a url'), '');
  assert.strictEqual(safeOrigin(''), '');
  assert.strictEqual(safeOrigin(null), '');
  assert.strictEqual(safeOrigin(undefined), '');
  assert.strictEqual(safeOrigin(123), '');
  // 需要区分"无法解析"的调用方可自定义回落（对齐历史 originOf 返回 null）。
  assert.strictEqual(safeOrigin('@@@', null), null);
  assert.strictEqual(safeOrigin('', null), null);
});

test('safeOrigin 对不透明源保留 URL 的原始结果（"null" 串），不擅自改写', () => {
  // 与直接 new URL(raw).origin 一致，避免权限归属判断出现口径偏差。
  assert.strictEqual(safeOrigin('about:blank'), new URL('about:blank').origin);
  assert.strictEqual(safeOrigin('file:///tmp/a'), new URL('file:///tmp/a').origin);
});

test('safeHostname 不含端口/IPv6 不带方括号', () => {
  assert.strictEqual(safeHostname('https://Example.COM:8443/'), 'example.com');
  // WHATWG URL 的 hostname 对 IPv6 保留方括号，内核直接透传，不私自去括号。
  assert.strictEqual(safeHostname('http://[::1]:8080/'), '[::1]');
  assert.strictEqual(safeHostname('not-url', 'fb'), 'fb');
  assert.strictEqual(safeHostname('', 'fb'), 'fb');
  // file: URL 无主机名，回落。
  assert.strictEqual(safeHostname('file:///a', 'none'), 'none');
});

test('safeHost 含端口', () => {
  assert.strictEqual(safeHost('https://example.com:9000/'), 'example.com:9000');
  assert.strictEqual(safeHost('bad', 'x'), 'x');
});

test('safeProtocol 默认失败回 null，成功带冒号', () => {
  assert.strictEqual(safeProtocol('https://example.com'), 'https:');
  assert.strictEqual(safeProtocol('cosy://settings'), 'cosy:');
  assert.strictEqual(safeProtocol('garbage'), null);
  assert.strictEqual(safeProtocol('', ''), '');
});

test('内核不抛异常（事件回调安全前提）', () => {
  const weird = ['', null, undefined, 123, {}, '://', 'http://', 'a\nb', String.fromCharCode(0)];
  for (const w of weird) {
    assert.doesNotThrow(() => { safeOrigin(w); safeHostname(w); safeHost(w); safeProtocol(w); });
  }
});
