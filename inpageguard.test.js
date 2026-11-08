'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  INPAGE_ACCEPT,
  INPAGE_HOLD,
  INPAGE_REJECT,
  REJECT_BAD_URL,
  REJECT_SCHEME,
  REJECT_TOO_LONG,
  REJECT_CONTROL,
  HOLD_DUPLICATE,
  HOLD_BURST,
  HOLD_COOLDOWN,
  MAX_INPAGE_URL_LEN,
  INPAGE_BURST_LIMIT,
  INPAGE_DUP_MS,
  INPAGE_LONG_WINDOW_MS,
  sanitizeInPageUrl,
  createInPageState,
  resetForNavigation,
  decideInPageNav,
  resetCooldown,
  describeInPageReason,
} = require('./inpageguard');

const T0 = 6_000_000;

test('URL 校验：协议 / 长度 / 控制字符 / 可解析', () => {
  assert.equal(sanitizeInPageUrl('https://a.test/x').ok, true);
  assert.equal(sanitizeInPageUrl('http://a.test/x?q=1#f').ok, true);
  assert.equal(sanitizeInPageUrl('cosy://settings/general').ok, true);

  assert.equal(sanitizeInPageUrl('').reason, REJECT_BAD_URL);
  assert.equal(sanitizeInPageUrl(null).reason, REJECT_BAD_URL);
  assert.equal(sanitizeInPageUrl(123).reason, REJECT_BAD_URL);
  assert.equal(sanitizeInPageUrl('not a url').reason, REJECT_BAD_URL);
  assert.equal(sanitizeInPageUrl('javascript:alert(1)').reason, REJECT_SCHEME);
  assert.equal(sanitizeInPageUrl('file:///etc/passwd').reason, REJECT_SCHEME);
  assert.equal(sanitizeInPageUrl('data:text/html,x').reason, REJECT_SCHEME);
  assert.equal(sanitizeInPageUrl('https://a.test/' + 'x'.repeat(MAX_INPAGE_URL_LEN)).reason, REJECT_TOO_LONG);
  assert.equal(sanitizeInPageUrl('https://a.test/a\x00b').reason, REJECT_CONTROL);
  assert.equal(sanitizeInPageUrl('https://a.test/a\n').reason, REJECT_CONTROL);
});

test('正常 SPA 路由切换全部接受', () => {
  const st = createInPageState(T0);
  const urls = ['https://a.test/', 'https://a.test/home', 'https://a.test/detail/1', 'https://a.test/detail/2'];
  urls.forEach((u, i) => {
    const r = decideInPageNav(st, u, T0 + 300 * (i + 1));
    assert.equal(r.decision, INPAGE_ACCEPT, `${u} 应接受`);
  });
  assert.equal(st.acceptedCount, 4);
});

test('非法 URL 被拒绝且计数', () => {
  const st = createInPageState(T0);
  const r1 = decideInPageNav(st, 'javascript:x', T0 + 10);
  const r2 = decideInPageNav(st, 'bad', T0 + 20);
  assert.equal(r1.decision, INPAGE_REJECT);
  assert.equal(r1.reason, REJECT_SCHEME);
  assert.equal(r2.decision, INPAGE_REJECT);
  assert.equal(st.rejectedCount, 2);
});

test('极短时间相同地址重复压栈被合并', () => {
  const st = createInPageState(T0);
  const r1 = decideInPageNav(st, 'https://a.test/same', T0 + 100);
  const r2 = decideInPageNav(st, 'https://a.test/same', T0 + 100 + INPAGE_DUP_MS - 5);
  assert.equal(r1.decision, INPAGE_ACCEPT);
  assert.equal(r2.decision, INPAGE_HOLD);
  assert.equal(r2.reason, HOLD_DUPLICATE);
  assert.equal(st.acceptedCount, 1);
});

test('超过去重窗口的相同地址重新接受', () => {
  const st = createInPageState(T0);
  decideInPageNav(st, 'https://a.test/s', T0 + 100);
  const r = decideInPageNav(st, 'https://a.test/s', T0 + 100 + INPAGE_DUP_MS + 50);
  assert.equal(r.decision, INPAGE_ACCEPT);
});

test('pushState 洪泛越限进入冷却', () => {
  const st = createInPageState(T0);
  let blocked = null;
  for (let i = 0; i < INPAGE_BURST_LIMIT + 10; i++) {
    const r = decideInPageNav(st, `https://a.test/p${i}`, T0 + i);
    if (r.decision === INPAGE_HOLD && r.reason === HOLD_BURST) blocked = r;
  }
  assert.ok(blocked, '高频不同地址应被突发限流');

  const during = decideInPageNav(st, 'https://a.test/later', T0 + INPAGE_BURST_LIMIT + 50);
  assert.equal(during.decision, INPAGE_HOLD);
  assert.equal(during.reason, HOLD_COOLDOWN);
});

test('冷却解除且窗口滑过后恢复', () => {
  const st = createInPageState(T0);
  for (let i = 0; i < INPAGE_BURST_LIMIT + 5; i++) {
    decideInPageNav(st, `https://a.test/p${i}`, T0 + i);
  }
  resetCooldown(st);
  const r = decideInPageNav(st, 'https://a.test/fresh', T0 + INPAGE_LONG_WINDOW_MS + 1000);
  assert.equal(r.decision, INPAGE_ACCEPT);
});

test('主框架真实导航后配额重置', () => {
  const st = createInPageState(T0);
  for (let i = 0; i < INPAGE_BURST_LIMIT + 5; i++) {
    decideInPageNav(st, `https://a.test/p${i}`, T0 + i);
  }
  assert.equal(decideInPageNav(st, 'https://a.test/x', T0 + 100).decision, INPAGE_HOLD);
  resetForNavigation(st);
  assert.equal(decideInPageNav(st, 'https://b.test/', T0 + 200).decision, INPAGE_ACCEPT);
});

test('无状态对象对合法 URL 也安全收敛', () => {
  const r = decideInPageNav(null, 'https://a.test/', T0);
  assert.equal(r.decision, INPAGE_HOLD);
});

test('所有原因都有可读描述', () => {
  for (const reason of [
    REJECT_BAD_URL, REJECT_SCHEME, REJECT_TOO_LONG, REJECT_CONTROL,
    HOLD_DUPLICATE, HOLD_BURST, HOLD_COOLDOWN,
  ]) {
    assert.ok(describeInPageReason(reason).length > 0);
  }
});
