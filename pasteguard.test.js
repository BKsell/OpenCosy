'use strict';

// pasteguard.test.js —— 覆盖隐形剥离、双向覆盖拦截、主机同形字、富文本假链接
// 与危险 href 协议。

const test = require('node:test');
const assert = require('node:assert/strict');
const pg = require('./pasteguard');
const {
  stripInvisible,
  hostOf,
  scanHostConfusables,
  sanitizePastedUrl,
  readAttr,
  stripSimpleTags,
  analyzeAnchorHTML,
  decideClipboardPaste,
} = pg;

test('剥离零宽空格与 BOM、软连字符', () => {
  const r = stripInvisible('exa\u200Bmple\uFEFF.\u00ADcom');
  assert.equal(r.text, 'example.com');
  assert.equal(r.removed, 3);
  assert.equal(r.hadBidi, false);
});

test('RLO 双向覆盖标记为 hard bidi', () => {
  const r = stripInvisible('a\u202Eb');
  assert.equal(r.hadBidi, true);
  const v = sanitizePastedUrl('https://a\u202Eb.com');
  assert.equal(v.status, 'blocked');
  assert.ok(v.reasons.includes('bidi-override'));
});

test('hostOf 提取 http/https 主机并在端口/路径处截断', () => {
  assert.equal(hostOf('https://example.com:8443/x'), 'example.com');
  assert.equal(hostOf('http://evil.test/a?b=1#c'), 'evil.test');
  assert.equal(hostOf('example.com'), null);
});

test('同形字：纯拉丁主机不报，混西里尔主机报', () => {
  assert.equal(scanHostConfusables('example.com').count, 0);
  // 用西里尔 а(U+0430) 与 е(U+0435) 冒充拉丁 a/e。
  const mixed = scanHostConfusables('ex\u0430mpl\u0435.com');
  assert.ok(mixed.count >= 2);
  assert.ok(mixed.scripts.includes('cyrillic'));
  const v = sanitizePastedUrl('https://ex\u0430mpl\u0435.com/x');
  assert.equal(v.status, 'suspicious');
  assert.ok(v.reasons.includes('homograph-host'));
});

test('正常 URL 判 ok', () => {
  const v = sanitizePastedUrl('https://example.com/path?id=1');
  assert.equal(v.status, 'ok');
  assert.deepEqual(v.reasons, []);
});

test('隐形字符被清洗后判 cleaned', () => {
  const v = sanitizePastedUrl('https://example.com/\u200Bx');
  assert.equal(v.status, 'cleaned');
  assert.ok(v.reasons.includes('invisible-stripped'));
  assert.equal(v.text, 'https://example.com/x');
});

test('前导空白/噪声标记，内嵌换行判 suspicious', () => {
  const v1 = sanitizePastedUrl('   https://example.com');
  assert.ok(v1.reasons.includes('leading-noise'));
  const v2 = sanitizePastedUrl('https://example.com\nhttps://evil.com');
  assert.equal(v2.status, 'suspicious');
  assert.ok(v2.reasons.includes('embedded-newline'));
});

test('非字符串输入 blocked', () => {
  assert.equal(sanitizePastedUrl(undefined).status, 'blocked');
});

test('readAttr 读取单双引号属性', () => {
  assert.equal(readAttr('<a href="https://x.com">', 'href'), 'https://x.com');
  assert.equal(readAttr("<a HREF='https://y.com'>", 'href'), 'https://y.com');
  assert.equal(readAttr('<a href=https://z.com>', 'href'), 'https://z.com');
  assert.equal(readAttr('<a data-x="1">', 'href'), null);
});

test('不把 <article> 误判为 <a>', () => {
  const r = analyzeAnchorHTML('<article>hi</article>');
  assert.equal(r.anchorCount, 0);
});

test('stripSimpleTags 去标签留文本（实体解码由 decodeBasicEntities 负责）', () => {
  assert.equal(stripSimpleTags('<b>Pay</b> &amp; Co'), 'Pay &amp; Co');
});

test('危险 href 协议整批 blocked', () => {
  for (const sc of ['javascript:', 'data:text/html,x', 'vbscript:x', 'file:///C:/x']) {
    const r = analyzeAnchorHTML('<a href="' + sc + '">x</a>');
    assert.equal(r.verdict, 'blocked', sc);
    assert.ok(r.links[0].reasons.some(x => x.startsWith('dangerous-href')), sc);
  }
});

test('显示文字与真实地址不一致的假链接判 suspicious', () => {
  const html = '<a href="https://evil-login.example/">https://accounts.google.com</a>';
  const r = analyzeAnchorHTML(html);
  assert.equal(r.verdict, 'suspicious');
  assert.ok(r.links[0].reasons.includes('label-href-mismatch'));
});

test('显示与真实一致的安全链接判 ok 并给出 href', () => {
  const html = '<a href="https://github.com/">https://github.com/</a>';
  const r = analyzeAnchorHTML(html);
  assert.equal(r.verdict, 'ok');
  assert.equal(r.links[0].reasons.length, 0);
});

test('同形字 href 判 suspicious 并给建议主机', () => {
  const html = '<a href="https://g\u043Eogle.com/">g\u043Eogle.com</a>';
  const r = analyzeAnchorHTML(html);
  assert.equal(r.verdict, 'suspicious');
  assert.ok(r.links[0].reasons.includes('homograph-host'));
});

test('decideClipboardPaste 富文本安全链接时建议用 href', () => {
  const d = decideClipboardPaste({
    text: 'https://github.com/',
    html: '<a href="https://github.com/">GitHub</a>',
  });
  assert.equal(d.status, 'ok');
  assert.equal(d.text, 'https://github.com/');
});

test('decideClipboardPaste 文本 RLO 优先级 blocked', () => {
  const d = decideClipboardPaste({ text: 'https://a\u202Eb.com', html: '' });
  assert.equal(d.status, 'blocked');
});

test('decideClipboardPaste 空载荷不抛错', () => {
  const d = decideClipboardPaste(null);
  assert.equal(d.status, 'ok');
});
