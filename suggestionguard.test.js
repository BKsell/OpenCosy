'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./suggestionguard');

const R = guard.SUGGEST_REJECT;

test('sanitizeSuggestionItem trims, enforces length and rejects controls', () => {
  assert.strictEqual(guard.sanitizeSuggestionItem('  hello  ', 100), 'hello');
  assert.strictEqual(guard.sanitizeSuggestionItem('', 100), '');
  assert.strictEqual(guard.sanitizeSuggestionItem('   ', 100), '');
  assert.strictEqual(guard.sanitizeSuggestionItem(123, 100), '');
  assert.strictEqual(guard.sanitizeSuggestionItem(null, 100), '');
  assert.strictEqual(guard.sanitizeSuggestionItem('a'.repeat(101), 100), '');
  assert.strictEqual(guard.sanitizeSuggestionItem('ok'.repeat(50), 100), 'ok'.repeat(50));
  assert.strictEqual(guard.sanitizeSuggestionItem('bad\nline', 100), '');
  assert.strictEqual(guard.sanitizeSuggestionItem('tab\there', 100), '');
  assert.strictEqual(guard.sanitizeSuggestionItem('del\x7f', 100), '');
});

test('parse accepts a well-formed OpenSearch payload', () => {
  const body = JSON.stringify(['mine', ['one', ' two ', 'three', 'one']]);
  const res = guard.parseOpenSearchSuggestions(body);
  assert.strictEqual(res.ok, true);
  assert.deepStrictEqual(res.suggestions, ['one', 'two', 'three']);
});

test('parse caps item count and keeps order', () => {
  const items = ['a', 'b', 'c', 'd', 'e'];
  const res = guard.parseOpenSearchSuggestions(JSON.stringify(['q', items]), { maxItems: 3 });
  assert.strictEqual(res.ok, true);
  assert.deepStrictEqual(res.suggestions, ['a', 'b', 'c']);
});

test('parse skips non-string / empty / control entries', () => {
  const res = guard.parseOpenSearchSuggestions(
    JSON.stringify(['q', ['keep', 7, '', '   ', 'bad\tnone', { x: 1 }, 'last']])
  );
  assert.strictEqual(res.ok, true);
  assert.deepStrictEqual(res.suggestions, ['keep', 'last']);
});

test('parse rejects malformed shapes', () => {
  assert.strictEqual(guard.parseOpenSearchSuggestions('').reason, R.EMPTY);
  assert.strictEqual(guard.parseOpenSearchSuggestions('not json').reason, R.INVALID_JSON);
  assert.strictEqual(guard.parseOpenSearchSuggestions('{"a":1}').reason, R.NOT_ARRAY);
  assert.strictEqual(guard.parseOpenSearchSuggestions('["q"]').reason, R.NO_SUGGESTIONS);
  assert.strictEqual(guard.parseOpenSearchSuggestions('["q","x"]').reason, R.NO_SUGGESTIONS);
  assert.strictEqual(guard.parseOpenSearchSuggestions(null).reason, R.BAD_ENCODING);
  assert.strictEqual(guard.parseOpenSearchSuggestions(undefined).reason, R.BAD_ENCODING);
});

test('parse enforces byte cap (UTF-8 counted)', () => {
  // 每个中文 3 字节：构造超过 64B 的最小 payload。
  const longSuggestions = ['中'.repeat(30)];
  const body = JSON.stringify(['q', longSuggestions]);
  assert.ok(Buffer.byteLength(body, 'utf8') > 64);
  const res = guard.parseOpenSearchSuggestions(body, { maxBytes: 64 });
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.reason, R.TOO_LARGE);
});

test('parse accepts Buffer and Uint8Array input', () => {
  const body = JSON.stringify(['q', ['alpha', 'beta']]);
  const fromBuffer = guard.parseOpenSearchSuggestions(Buffer.from(body, 'utf8'));
  assert.deepStrictEqual(fromBuffer.suggestions, ['alpha', 'beta']);
  const u8 = new TextEncoder().encode(body);
  const fromU8 = guard.parseOpenSearchSuggestions(u8);
  assert.deepStrictEqual(fromU8.suggestions, ['alpha', 'beta']);
});

test('createByteBudget accumulates and trips over limit', () => {
  const budget = guard.createByteBudget(10);
  assert.strictEqual(budget.accept(Buffer.alloc(4)), true);
  assert.strictEqual(budget.bytes, 4);
  assert.strictEqual(budget.exceeded, false);
  assert.strictEqual(budget.accept(Buffer.alloc(6)), true);
  assert.strictEqual(budget.bytes, 10);
  assert.strictEqual(budget.accept(Buffer.alloc(1)), false);
  assert.strictEqual(budget.exceeded, true);
  // 已超限后任何后续块都被拒绝。
  assert.strictEqual(budget.accept(Buffer.alloc(1)), false);
});
