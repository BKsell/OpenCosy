'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  HOVER_SHOW,
  HOVER_HOLD,
  HOVER_DROP,
  HOLD_TOO_SOON,
  HOLD_SAME,
  DROP_BAD,
  DROP_FLOOD,
  DROP_COOLDOWN,
  HOVER_MAX_URL_CHARS,
  HOVER_MIN_INTERVAL_MS,
  HOVER_BURST_LIMIT,
  HOVER_LONG_WINDOW_MS,
  sanitizeHoverUrl,
  createHoverState,
  resetForNavigation,
  decideHoverUrl,
  describeHoverReason,
} = require('./hoverguard');

const T0 = 7_000_000;

test('净化换行/控制字符/ANSI 转义并修剪两端空白', () => {
  const r = sanitizeHoverUrl('  https://safe.example/a\r\nFAKE\x1b[31m  ');
  assert.equal(r.url, 'https://safe.example/aFAKE');
  assert.equal(r.truncated, false);
  assert.equal(r.empty, false);
});

test('U+2028/U+2029 与零宽字符被剥除', () => {
  const evil = 'https://x/' + String.fromCharCode(0x2028) + 'a'
    + String.fromCharCode(0x200b) + String.fromCharCode(0xfeff) + 'b';
  assert.equal(sanitizeHoverUrl(evil).url, 'https://x/ab');
});

test('空串是合法清空信号，非字符串拒绝', () => {
  const e = sanitizeHoverUrl('  \x1b[0m ');
  assert.equal(e.empty, true);
  assert.equal(e.url, '');
  assert.equal(sanitizeHoverUrl(undefined).ok, false);
});

test('超长 URL 按代码点截断并标注', () => {
  const big = 'https://x.test/' + 'a'.repeat(HOVER_MAX_URL_CHARS + 10);
  const r = sanitizeHoverUrl(big);
  assert.equal(r.truncated, true);
  assert.ok(Array.from(r.url).length <= HOVER_MAX_URL_CHARS);
});

test('最小间隔内更新被软节流，同值重复被去抖', () => {
  const st = createHoverState(T0);
  assert.equal(decideHoverUrl(st, 'https://a', T0).action, HOVER_SHOW);
  const soon = decideHoverUrl(st, 'https://b', T0 + HOVER_MIN_INTERVAL_MS - 5);
  assert.equal(soon.action, HOVER_HOLD);
  assert.equal(soon.reason, HOLD_TOO_SOON);
  const same = decideHoverUrl(st, 'https://a', T0 + 5_000);
  assert.equal(same.action, HOVER_HOLD);
  assert.equal(same.reason, HOLD_SAME);
});

test('空串首次显示用于回收状态栏，连续空串合并；冷却期空串仍放行', () => {
  const st = createHoverState(T0);
  assert.equal(decideHoverUrl(st, '', T0).action, HOVER_SHOW);
  assert.equal(decideHoverUrl(st, '', T0 + 100).action, HOVER_HOLD);
});

test('非字符串目标直接丢弃', () => {
  const st = createHoverState(T0);
  const r = decideHoverUrl(st, null, T0 + 10);
  assert.equal(r.action, HOVER_DROP);
  assert.equal(r.reason, DROP_BAD);
});

test('高频事件（即便被软节流）计数累积，突发越限进入冷却并丢弃', () => {
  const st = createHoverState(T0);
  let last;
  // 5ms 间隔的不同 URL：第二次起全被软节流，但每次事件都计入硬洪泛窗口。
  for (let i = 0; i < HOVER_BURST_LIMIT + 1; i++) {
    last = decideHoverUrl(st, 'https://x.test/' + i, T0 + 5 * i);
  }
  assert.equal(last.action, HOVER_DROP);
  assert.ok(last.reason === DROP_FLOOD || last.reason === DROP_COOLDOWN);
  assert.ok(last.cooldownUntil > T0);
  // 冷却期内普通链接一律丢弃。
  const inCooldown = decideHoverUrl(st, 'https://y.test/', T0 + 1_000);
  assert.equal(inCooldown.action, HOVER_DROP);
  assert.equal(inCooldown.reason, DROP_COOLDOWN);
  // 但清空信号仍放行，状态栏不会卡在攻击者伪造的地址上。
  const clear = decideHoverUrl(st, '', T0 + 1_100);
  assert.equal(clear.action, HOVER_SHOW);
  assert.equal(clear.url, '');
});

test('长窗口外旧事件被修剪，配额随时间恢复', () => {
  const st = createHoverState(T0);
  for (let i = 0; i < 110; i++) {
    const r = decideHoverUrl(st, 'https://p.test/' + i, T0 + 65 * (i + 1));
    assert.notEqual(r.action, HOVER_DROP);
  }
  assert.equal(st.times.length, 110);
  const r = decideHoverUrl(st, 'https://p.test/fresh', T0 + 65 * 110 + HOVER_LONG_WINDOW_MS + 100);
  assert.equal(r.action, HOVER_SHOW);
  assert.equal(r.longCount, 1);
});

test('主导航重置配额后恢复显示', () => {
  const st = createHoverState(T0);
  for (let i = 0; i < HOVER_BURST_LIMIT + 1; i++) {
    decideHoverUrl(st, 'https://f.test/' + i, T0 + 5 * i);
  }
  assert.equal(decideHoverUrl(st, 'https://z.test/', T0 + 1_000).action, HOVER_DROP);
  resetForNavigation(st);
  const r = decideHoverUrl(st, 'https://fresh.test/', T0 + 200_000);
  assert.equal(r.action, HOVER_SHOW);
});

test('原因描述可读', () => {
  for (const reason of [HOLD_TOO_SOON, HOLD_SAME, DROP_BAD, DROP_FLOOD, DROP_COOLDOWN]) {
    assert.ok(describeHoverReason(reason).length > 0);
  }
});
