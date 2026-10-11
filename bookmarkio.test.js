'use strict';

const test = require('node:test');
const assert = require('node:assert');
const bmio = require('./bookmarkio');

test('有界 JSON：正常数组解析', () => {
  const data = bmio.parseBoundedJSON('[{"url":"https://a.example/","title":"A"},{"url":"https://b.example/"}]');
  assert.equal(data.length, 2);
  assert.equal(data[1].url, 'https://b.example/');
});

test('有界 JSON：bookmarks 包装对象', () => {
  const data = bmio.parseBoundedJSON('{"bookmarks":[{"url":"https://c.example/"}]}');
  assert.equal(data.bookmarks.length, 1);
});

test('有界 JSON：拒绝超深嵌套（栈溢出炸弹）', () => {
  const deep = '['.repeat(500) + '0' + ']'.repeat(500);
  assert.throws(() => bmio.parseBoundedJSON(deep), /嵌套深度/);
});

test('有界 JSON：拒绝超大元素数量（内存炸弹）', () => {
  const wide = '[' + Array(500000).fill('1').join(',') + ']';
  assert.throws(() => bmio.parseBoundedJSON(wide), /元素数量/);
});

test('有界 JSON：拒绝非法尾部内容', () => {
  assert.throws(() => bmio.parseBoundedJSON('[] x'), /尾部/);
  assert.throws(() => bmio.parseBoundedJSON('[1,]'), /期望|无法识别/);
});

test('有界 JSON：字符串转义与 unicode 正常', () => {
  const data = bmio.parseBoundedJSON('{"t":"a\\n\\u4e2d"}');
  assert.equal(data.t, 'a\n中');
});

test('有界 JSON：拒绝字符串内未转义控制字符', () => {
  assert.throws(() => bmio.parseBoundedJSON('{"t":"a\u0001b"}'), /控制字符/);
});

test('parseBookmarkFile：JSON 书签全链路', () => {
  const buf = Buffer.from('[{"url":"https://x.example/","title":"X"}]', 'utf8');
  const r = bmio.parseBookmarkFile(buf);
  assert.equal(r.format, 'json');
  assert.equal(r.bookmarks.length, 1);
  assert.equal(r.bookmarks[0].title, 'X');
});

test('parseBookmarkFile：恶意 JSON 抛出中文错误', () => {
  const deep = Buffer.from('['.repeat(500) + '0' + ']'.repeat(500), 'utf8');
  assert.throws(() => bmio.parseBookmarkFile(deep), /JSON 解析失败/);
});

test('parseBookmarkFile：空文件被拒', () => {
  assert.throws(() => bmio.parseBookmarkFile(Buffer.alloc(0)), /为空/);
});

test('safeBookmarkURL：仅 http/https 且拒凭据', () => {
  assert.equal(bmio.safeBookmarkURL('javascript:alert(1)'), null);
  assert.equal(bmio.safeBookmarkURL('data:text/html,x'), null);
  assert.equal(bmio.safeBookmarkURL('https://user:pass@h.example/'), null);
  assert.ok(bmio.safeBookmarkURL('https://h.example/a').startsWith('https://'));
});
