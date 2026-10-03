'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  ENTRY_ACCEPT,
  ENTRY_HOLD,
  ENTRY_DROP,
  HOLD_SAME,
  HOLD_TOO_SOON,
  DROP_BAD_URL,
  DROP_FLOOD,
  DROP_COOLDOWN,
  ENTRY_MAX_URL_CHARS,
  ENTRY_MIN_INTERVAL_MS,
  ENTRY_BURST_LIMIT,
  ENTRY_LONG_WINDOW_MS,
  sanitizeEntryUrl,
  createEntryState,
  resetForNavigation,
  decideNavigationEntry,
  describeEntryReason,
} = require('./entryguard');

const T0 = 50_000_000;

test('净化换行/控制字符/ANSI/U+2028 与零宽字符', () => {
  const evil = ' https://a.test/x\r\nFAKE\x1b[31m'
    + String.fromCharCode(0x2028) + String.fromCharCode(0x200b);
  assert.equal(sanitizeEntryUrl(evil).url, 'https://a.test/xFAKE');
});

test('空串与非字符串拒绝', () => {
  assert.equal(sanitizeEntryUrl('  ').ok, false);
  assert.equal(sanitizeEntryUrl(null).ok, false);
});

test('超长 URL 按代码点截断', () => {
  const r = sanitizeEntryUrl('https://x.test/' + 'q'.repeat(ENTRY_MAX_URL_CHARS + 5));
  assert.equal(r.truncated, true);
  assert.ok(Array.from(r.url).length <= ENTRY_MAX_URL_CHARS);
});

test('同 URL 与最小间隔内提交被软合并', () => {
  const st = createEntryState(T0);
  assert.equal(decideNavigationEntry(st, 'https://a', T0).action, ENTRY_ACCEPT);
  assert.equal(decideNavigationEntry(st, 'https://a', T0 + 10).reason, HOLD_SAME);
  const soon = decideNavigationEntry(st, 'https://b', T0 + ENTRY_MIN_INTERVAL_MS - 2);
  assert.equal(soon.action, ENTRY_HOLD);
  assert.equal(soon.reason, HOLD_TOO_SOON);
  assert.equal(decideNavigationEntry(st, 'https://b', T0 + 100).action, ENTRY_ACCEPT);
});

test('高频提交越限进入冷却并丢弃', () => {
  const st = createEntryState(T0);
  let last;
  for (let i = 0; i < ENTRY_BURST_LIMIT + 1; i++) {
    last = decideNavigationEntry(st, 'https://x.test/' + i, T0 + i);
  }
  assert.equal(last.action, ENTRY_DROP);
  assert.ok(last.reason === DROP_FLOOD || last.reason === DROP_COOLDOWN);
  assert.ok(last.cooldownUntil > T0);
  const cooled = decideNavigationEntry(st, 'https://y.test/', T0 + 500);
  assert.equal(cooled.action, ENTRY_DROP);
  assert.equal(cooled.reason, DROP_COOLDOWN);
});

test('冷却结束后恢复接受', () => {
  const st = createEntryState(T0);
  for (let i = 0; i < ENTRY_BURST_LIMIT + 1; i++) {
    decideNavigationEntry(st, 'https://x.test/' + i, T0 + i);
  }
  const r = decideNavigationEntry(st, 'https://recovered.test/', T0 + 100_000);
  assert.equal(r.action, ENTRY_ACCEPT);
});

test('长窗口外旧事件被修剪', () => {
  const st = createEntryState(T0);
  // 40ms 间隔：穿过 30ms 最小间隔；1s 突发窗口约 25 条 < 60。
  for (let i = 0; i < 150; i++) {
    const r = decideNavigationEntry(st, 'https://p.test/' + i, T0 + 40 * (i + 1));
    assert.notEqual(r.action, ENTRY_DROP);
  }
  const r = decideNavigationEntry(st, 'https://fresh.test/', T0 + 40 * 150 + ENTRY_LONG_WINDOW_MS + 10);
  assert.equal(r.action, ENTRY_ACCEPT);
  assert.equal(r.longCount, 1);
});

test('主导航重置冷却与配额', () => {
  const st = createEntryState(T0);
  for (let i = 0; i < ENTRY_BURST_LIMIT + 1; i++) {
    decideNavigationEntry(st, 'https://x.test/' + i, T0 + i);
  }
  resetForNavigation(st);
  assert.equal(decideNavigationEntry(st, 'https://fresh.test/', T0 + 9_000_000).action, ENTRY_ACCEPT);
});

test('原因描述可读', () => {
  for (const reason of [HOLD_SAME, HOLD_TOO_SOON, DROP_BAD_URL, DROP_FLOOD, DROP_COOLDOWN]) {
    assert.ok(describeEntryReason(reason).length > 0);
  }
});
