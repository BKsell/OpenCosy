'use strict';

const test = require('node:test');
const assert = require('node:assert');

// jsonimportguard 是浏览器端 UMD（挂 window/globalThis），node 下 require 后
// 从 globalThis 取同一实例验证，确保与页面运行的是同一份代码。
require('./src/jsonimportguard.js');
const guard = globalThis.OpenCosyJsonImport;

test('parseTiles：正常磁贴备份', () => {
  const r = guard.parseTiles(JSON.stringify({
    version: 1,
    customs: [{ name: 'A', url: 'https://a.example/', color: '#123456', letter: 'A' }],
    order: ['https://a.example/'],
  }));
  assert.equal(r.ok, true);
  assert.equal(r.items.length, 1);
  assert.equal(r.items[0].url, 'https://a.example/');
  assert.equal(r.order.length, 1);
});

test('parseTiles：顶层数组兼容', () => {
  const r = guard.parseTiles('[{"name":"B","url":"https://b.example/"}]');
  assert.equal(r.ok, true);
  assert.equal(r.items[0].name, 'B');
});

test('parseTiles：拒绝超深嵌套（栈溢出炸弹）', () => {
  const deep = '['.repeat(500) + '0' + ']'.repeat(500);
  const r = guard.parseTiles(deep);
  assert.equal(r.ok, false);
  assert.match(r.error, /深度/);
});

test('parseTiles：拒绝超大元素数量（内存炸弹）', () => {
  const wide = '[' + Array(200000).fill('1').join(',') + ']';
  const r = guard.parseTiles(wide);
  assert.equal(r.ok, false);
  assert.match(r.error, /元素数量/);
});

test('parseTiles：拒绝超大文件', () => {
  const big = '[' + '0,'.repeat(200000) + '0]';
  const r = guard.parseTiles(big);
  assert.equal(r.ok, false);
});

test('parseTiles：危险协议与字段注入被净化', () => {
  const r = guard.parseTiles(JSON.stringify([
    { name: '<img src=x onerror=alert(1)>', url: 'javascript:alert(1)' },
    { name: 'D', url: 'data:text/html,x', color: 'red;background:url(javascript:1)' },
    { name: 'OK', url: 'https://ok.example/', color: '#0f0f0f', letter: 'O' },
  ]));
  assert.equal(r.ok, true);
  assert.equal(r.items.length, 1);
  assert.equal(r.items[0].name, 'OK');
  assert.equal(r.items[0].color, '#0f0f0f');
});

test('parseTiles：非法 JSON 返回错误', () => {
  assert.equal(guard.parseTiles('{oops').ok, false);
  assert.equal(guard.parseTiles('').ok, false);
  assert.equal(guard.parseTiles('[] x').ok, false);
});

test('parseTiles：无 customs 的对象被拒', () => {
  const r = guard.parseTiles('{"foo":1}');
  assert.equal(r.ok, false);
  assert.match(r.error, /没有磁贴列表/);
});

test('sanitizeTile：字段收口', () => {
  assert.equal(guard.sanitizeTile(null), null);
  assert.equal(guard.sanitizeTile({ url: 'ftp://x' }), null);
  const t = guard.sanitizeTile({ name: '  E  ', url: 'https://e.example/', color: '#abc', letter: 'X' });
  assert.equal(t.name, 'E');
  assert.equal(t.letter, 'X');
});

test('stripControlChars / truncateRunes', () => {
  assert.equal(guard.stripControlChars('a\u0001b\u009fc'), 'abc');
  assert.equal(guard.truncateRunes('abcdef', 3), 'abc');
});
