'use strict';

const test = require('node:test');
const assert = require('node:assert');
const readerCore = require('./reader_core');
const bridge = require('./readerbridge_core');

bridge.bindDeps({ readerCore });

test('keepReaderUrl 只放行 http/https 并把相对链接解析到页面基址', () => {
  assert.equal(bridge.keepReaderUrl('https://a.test/x', 'https://a.test/p', 2048), 'https://a.test/x');
  assert.equal(bridge.keepReaderUrl('/rel', 'https://a.test/p', 2048), 'https://a.test/rel');
  for (const bad of ['javascript:alert(1)', 'JaVaScRiPt:alert(1)', 'data:text/html,x',
    'vbscript:x', 'file:///etc/passwd']) {
    assert.equal(bridge.keepReaderUrl(bad, 'https://a.test/p', 2048), '', `应拒绝: ${bad}`);
  }
  assert.equal(bridge.keepReaderUrl('https://a.test/' + 'a'.repeat(3000), 'https://a.test/p', 2048), '');
});

test('scrubReaderUrls 递归剔除危险链接与图片源', () => {
  const nodes = [
    { tag: 'p', text: '正文', children: [{ tag: 'a', text: '点我', href: 'javascript:alert(1)' }] },
    { tag: 'img', text: '', src: 'data:image/png;base64,AA' },
  ];
  const out = bridge.scrubReaderUrls(nodes, 'https://a.test/p');
  assert.equal(out[0].children[0].href, undefined);
  assert.equal(out[1].src, undefined);
});

test('sanitizeReaderArticle 会丢弃页面返回的危险 href/src', () => {
  const raw = {
    ok: true, title: 't', wordCount: 100, minutes: 1,
    contentNodes: [{ tag: 'a', text: 'x', href: 'javascript:alert(1)',
      children: [{ tag: 'img', text: '', src: 'javascript:x' }] }],
  };
  const article = bridge.sanitizeReaderArticle(raw, 'https://a.test/p', 't');
  assert.equal(article.ok, true);
  assert.equal(article.contentNodes[0].href, undefined);
  assert.equal(article.contentNodes[0].children[0].src, undefined);
});
