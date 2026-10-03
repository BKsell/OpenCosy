'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  CONSOLE_ACCEPT,
  CONSOLE_SKIP,
  CONSOLE_DROP,
  CS_EMPTY,
  CS_FLOOD,
  CS_COOLDOWN,
  CONSOLE_MAX_LINE_CHARS,
  CONSOLE_BURST_LIMIT,
  CONSOLE_LONG_WINDOW_MS,
  CONSOLE_LONG_LIMIT,
  sanitizeConsoleText,
  normalizeConsoleLevel,
  sanitizeSourceLocation,
  createConsoleState,
  resetForNavigation,
  decideConsole,
  describeConsoleReason,
} = require('./consoleguard');

const T0 = 9_000_000;

test('ANSI 转义与换行/控制字符被剥离，日志无法断行或变色', () => {
  const evil = 'ok\x1b[31mRED\x1b[0m\r\nFAKE_LOG_LINE\tbell\x07';
  const r = sanitizeConsoleText(evil);
  assert.match(r.text, /^okREDFAKE_LOG_LINEbell$/);
  assert.doesNotMatch(r.text, /[\x00-\x1f\x7f]/);
});

test('U+2028/U+2029 与零宽字符被剥除', () => {
  const evil = 'a' + String.fromCharCode(0x2028) + 'b' + String.fromCharCode(0x2029)
    + 'c' + String.fromCharCode(0x200b) + String.fromCharCode(0xfeff) + 'd';
  const r = sanitizeConsoleText(evil);
  assert.equal(r.text, 'abcd');
});

test('超长单行按代码点截断并标注', () => {
  const big = 'x'.repeat(CONSOLE_MAX_LINE_CHARS + 500);
  const r = sanitizeConsoleText(big);
  assert.equal(r.truncated, true);
  assert.ok(Array.from(r.text).length <= CONSOLE_MAX_LINE_CHARS);
  assert.ok(r.text.endsWith('…'));
  // 代理对不被截断成孤立高代理：构造 BMP+补充平面混合串。
  const astral = '😀'.repeat(CONSOLE_MAX_LINE_CHARS);
  const a = sanitizeConsoleText(astral);
  assert.ok(Array.from(a.text).length <= CONSOLE_MAX_LINE_CHARS);
});

test('非字符串与非正整数级别安全收敛', () => {
  assert.deepEqual(sanitizeConsoleText(null), { text: '', truncated: false, length: 0 });
  assert.equal(normalizeConsoleLevel(3), 3);
  assert.equal(normalizeConsoleLevel(-1), 0);
  assert.equal(normalizeConsoleLevel(4), 0);
  assert.equal(normalizeConsoleLevel('1'), 0);
  const loc = sanitizeSourceLocation('h\x1bttps://x/y', '7abc');
  assert.doesNotMatch(loc.sourceId, /[\x00-\x1f]/);
  assert.equal(loc.line, 0);
  assert.equal(sanitizeSourceLocation('s', 12).line, 12);
});

test('空白消息走 skip 且不计入洪泛', () => {
  const st = createConsoleState(T0);
  const r = decideConsole(st, { level: 1, message: '\x1b[0m\r\n', sourceId: '', line: 1 }, T0 + 5);
  assert.equal(r.action, CONSOLE_SKIP);
  assert.equal(r.reason, CS_EMPTY);
  assert.equal(st.acceptCount, 0);
  assert.equal(st.skipCount, 1);
});

test('突发窗口越限后丢弃并进入冷却，冷却期一律 drop', () => {
  const st = createConsoleState(T0);
  let last;
  for (let i = 0; i < CONSOLE_BURST_LIMIT + 1; i++) {
    last = decideConsole(st, { level: 1, message: 'm' + i }, T0 + 10 * (i + 1));
  }
  assert.equal(last.action, CONSOLE_DROP);
  assert.equal(last.reason, CS_FLOOD);
  assert.ok(last.cooldownUntil > T0);

  const inCooldown = decideConsole(st, { level: 3, message: 'real-error' }, T0 + 1000);
  assert.equal(inCooldown.action, CONSOLE_DROP);
  assert.equal(inCooldown.reason, CS_COOLDOWN);
});

test('冷却结束且滑窗过期后恢复记录', () => {
  const st = createConsoleState(T0);
  for (let i = 0; i < CONSOLE_BURST_LIMIT + 1; i++) {
    decideConsole(st, { level: 0, message: 'm' }, T0 + 10 * (i + 1));
  }
  const r = decideConsole(st, { level: 2, message: 'back' }, T0 + CONSOLE_LONG_WINDOW_MS + 20_000);
  assert.equal(r.action, CONSOLE_ACCEPT);
  assert.equal(r.level, 2);
});

test('低频但持续输出越过长窗口总量上限', () => {
  const st = createConsoleState(T0);
  let last;
  // 间隔 150ms：5s 突发窗口内约 34 条（低于突发上限 40），
  // 但 60s 长窗口内累积约 400 条，越过总量上限 300 后被判洪泛。
  for (let i = 0; i < CONSOLE_LONG_LIMIT + 105; i++) {
    last = decideConsole(st, { level: 1, message: 'm' + i }, T0 + 150 * (i + 1));
  }
  assert.equal(last.action, CONSOLE_DROP);
  assert.ok(last.reason === CS_FLOOD || last.reason === CS_COOLDOWN);
});

test('主导航重置后重新获得配额，但累计丢弃数保留', () => {
  const st = createConsoleState(T0);
  for (let i = 0; i < CONSOLE_BURST_LIMIT + 1; i++) {
    decideConsole(st, { level: 1, message: 'm' }, T0 + 10 * (i + 1));
  }
  const droppedBefore = st.dropped;
  resetForNavigation(st);
  const r = decideConsole(st, { level: 1, message: 'fresh' }, T0 + 500);
  assert.equal(r.action, CONSOLE_ACCEPT);
  assert.equal(r.droppedTotal, droppedBefore);
});

test('原因描述可读', () => {
  for (const reason of [CS_EMPTY, CS_FLOOD, CS_COOLDOWN]) {
    assert.ok(describeConsoleReason(reason).length > 0);
  }
});
