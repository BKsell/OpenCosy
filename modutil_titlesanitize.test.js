'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { sanitizeDisplayTitle } = require('./modutil');

function loneSurrogate(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = s.charCodeAt(i + 1);
      if (!(n >= 0xdc00 && n <= 0xdfff)) return true;
      i++;
      continue;
    }
    if (c >= 0xdc00 && c <= 0xdfff) return true;
  }
  return false;
}

test('标题截断不切断代理对（表情在边界处不产生孤立半字符）', () => {
  const head = 'a'.repeat(299);
  const clipped = sanitizeDisplayTitle(head + '\u{1F600}', 300);
  assert.ok(clipped.length <= 300);
  assert.strictEqual(loneSurrogate(clipped), false);
  assert.strictEqual(clipped, head);
});

test('标题不超上界时表情原样保留，控制字符仍被清掉', () => {
  assert.strictEqual(sanitizeDisplayTitle('hello \u{1F600}', 300), 'hello \u{1F600}');
  assert.strictEqual(sanitizeDisplayTitle('a\u0000b\u0007c', 300), 'abc');
});

test('连续表情被截到上界时只保留完整字符', () => {
  const clipped = sanitizeDisplayTitle('\u{1F600}'.repeat(200), 7);
  assert.ok(clipped.length <= 7);
  assert.strictEqual(loneSurrogate(clipped), false);
});
