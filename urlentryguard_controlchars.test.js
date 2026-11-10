'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { sanitizeWebUrl } = require('./urlentryguard');

const REASONS = Object.freeze({
  empty: 'empty',
  tooLong: 'too-long',
  badUrl: 'bad-url',
  badProtocol: 'bad-protocol',
});

function decide(raw) {
  return sanitizeWebUrl(raw, REASONS, 8192);
}

test('URL 正文里的 C0 控制字符被拒绝，不再被解析器静默吞掉', () => {
  const cases = [
    'http://exa\tmple.com/',
    'https://example.com/x\n',
    'https://example.com/\r',
    'http://example.com\u0000path',
    'https://example.com\u0007',
    'http://example.com\u001f',
  ];
  for (const raw of cases) {
    const r = decide(raw);
    assert.strictEqual(r.ok, false, raw);
    assert.strictEqual(r.reason, 'bad-url', raw);
    assert.strictEqual(r.url, '', raw);
  }
});

test('DEL 与 C1 控制字符同样被拒绝', () => {
  for (const raw of ['http://example.com\u007f', 'https://example.com/\u0085', 'https://a.com\u009f']) {
    const r = decide(raw);
    assert.strictEqual(r.ok, false, raw);
    assert.strictEqual(r.reason, 'bad-url', raw);
  }
});

test('正常多字节路径不受影响，仍按 URL 规范化', () => {
  const r = decide('https://example.com/\u00e9/\u4e2d');
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.url, 'https://example.com/%C3%A9/%E4%B8%AD');
});

test('控制字符 reason 可由调用方覆写', () => {
  const r = sanitizeWebUrl('http://a.com\tb', { badUrl: 'bad-url', control: 'control-char' }, 8192);
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.reason, 'control-char');
});
