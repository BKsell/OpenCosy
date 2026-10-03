'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const g = require('./menuguard');

test('safeMenuUrl 仅放行 http/https', () => {
  assert.equal(g.safeMenuUrl('https://a.com/x').ok, true);
  assert.equal(g.safeMenuUrl('http://a.com').url, 'http://a.com');
  assert.equal(g.safeMenuUrl('javascript:alert(1)').ok, false);
  assert.equal(g.safeMenuUrl('file:///c:/x').ok, false);
  assert.equal(g.safeMenuUrl('').ok, false);
  assert.equal(g.safeMenuUrl(null).ok, false);
  assert.equal(g.safeMenuUrl('https://a.com/a\nb').ok, false);
  assert.equal(g.safeMenuUrl('https://' + 'x'.repeat(4100)).ok, false);
});

test('cleanMenuText 折叠空白并移除控制字符', () => {
  assert.equal(g.cleanMenuText('hello\nworld'), 'hello world');
  assert.equal(g.cleanMenuText('a  \t  b'), 'a b');
  // 内联 NUL 被压成空格（防折行伪造），词首尾的空格最终 trim 掉。
  assert.equal(g.cleanMenuText('x\u0000y'), 'x y');
  assert.equal(g.cleanMenuText('a\u2028b'), 'a b');
  assert.equal(g.cleanMenuText('\u0000abc'), 'abc');
  assert.equal(g.cleanMenuText(123), '');
});

test('cleanMenuText 限长', () => {
  assert.equal(g.cleanMenuText('x'.repeat(500), 10).length, 10);
});

test('isDictionaryWord 词形校验', () => {
  assert.equal(g.isDictionaryWord('hello'), true);
  assert.equal(g.isDictionaryWord('你好'), true);
  assert.equal(g.isDictionaryWord('a b'), false);
  assert.equal(g.isDictionaryWord('<script>'), false);
  assert.equal(g.isDictionaryWord('x'.repeat(g.MAX_MENU_WORD_CHARS + 1)), false);
  assert.equal(g.isDictionaryWord('a\x00b'), false);
});

test('cleanSuggestions 去重限量过滤', () => {
  const list = ['cat', 'car', 'cat', '<bad>', 'cab', 'cap', 'can', 'cam', 'cog'];
  const out = g.cleanSuggestions(list);
  assert.ok(out.length <= g.MAX_SUGGESTIONS);
  assert.ok(!out.includes('<bad>'));
  assert.equal(new Set(out).size, out.length);
  assert.deepEqual(g.cleanSuggestions(null), []);
});

test('evaluateContextMenu 链接放行', () => {
  const v = g.evaluateContextMenu({ linkURL: 'https://a.com/x' });
  assert.equal(v.canUseLink, true);
  assert.equal(v.linkUrl, 'https://a.com/x');
});

test('evaluateContextMenu 危险链接标记', () => {
  const v = g.evaluateContextMenu({ linkURL: 'javascript:alert(1)' });
  assert.equal(v.canUseLink, false);
  assert.ok(v.reasons.includes('unsafe-link-url'));
});

test('evaluateContextMenu 选中文本清洗截断', () => {
  const v = g.evaluateContextMenu({ selectionText: 'line1\r\nline2' });
  assert.equal(v.hasSelection, true);
  assert.equal(v.selectionText, 'line1 line2');
  const long = g.evaluateContextMenu({ selectionText: 'x'.repeat(500) });
  assert.equal(long.selectionText.length, g.MAX_MENU_TEXT_CHARS);
  assert.ok(long.reasons.includes('selection-truncated'));
});

test('evaluateContextMenu 可编辑区错词与建议', () => {
  const v = g.evaluateContextMenu({
    isEditable: true,
    misspelledWord: 'helo',
    dictionarySuggestions: ['hello', 'hello', '<x>', 'help'],
  });
  assert.equal(v.misspelledWord, 'helo');
  assert.deepEqual(v.suggestions, ['hello', 'help']);
});

test('evaluateContextMenu 非法错词被丢', () => {
  const v = g.evaluateContextMenu({ isEditable: true, misspelledWord: 'bad word' });
  assert.equal(v.misspelledWord, '');
  assert.ok(v.reasons.includes('misspelled-word-dropped'));
});

test('evaluateContextMenu 非编辑区不处理错词', () => {
  const v = g.evaluateContextMenu({ isEditable: false, misspelledWord: 'helo' });
  assert.equal(v.misspelledWord, '');
  assert.deepEqual(v.suggestions, []);
});

test('evaluateContextMenu 空 params 安全', () => {
  const v = g.evaluateContextMenu(null);
  assert.equal(v.canUseLink, false);
  assert.equal(v.hasSelection, false);
  assert.equal(v.isEditable, false);
});
