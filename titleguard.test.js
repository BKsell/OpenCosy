'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  TITLE_ACCEPT,
  TITLE_HOLD,
  HOLD_BURST,
  HOLD_SAME,
  TITLE_SANITIZED,
  MAX_TITLE_LEN,
  TITLE_BURST_LIMIT,
  TITLE_SAME_MS,
  MAX_FAVICONS,
  MAX_FAVICON_URL_LEN,
  sanitizeTabTitle,
  createTitleState,
  decideTitleUpdate,
  isAllowedFaviconScheme,
  sanitizeFavicons,
  resolveFaviconHref,
  describeTitleReason,
} = require('./titleguard');

const T0 = 3_000_000;

test('标题净化：控制字符 / 空白折叠 / 代码点安全截断', () => {
  assert.equal(sanitizeTabTitle('正常标题').title, '正常标题');
  assert.equal(sanitizeTabTitle('a\x00b\x07c').title, 'abc');
  assert.equal(sanitizeTabTitle('  line1\nline2\t ').title, 'line1 line2');
  assert.equal(sanitizeTabTitle(null).title, '');
  assert.equal(sanitizeTabTitle(undefined).title, '');
  assert.equal(sanitizeTabTitle(123).title, '123');

  // emoji 代理对截断不能产生孤立代理。
  const long = '😀'.repeat(MAX_TITLE_LEN + 50);
  const r = sanitizeTabTitle(long);
  assert.equal([...r.title].length, MAX_TITLE_LEN);
  assert.equal(r.truncated, true);
  // 截出的字符串能正常按代码点遍历即说明没有劈坏代理对。
  assert.doesNotThrow(() => Array.from(r.title));
});

test('正常标题更新放行并记录', () => {
  const st = createTitleState(T0);
  const r1 = decideTitleUpdate(st, '首页', T0 + 10);
  const r2 = decideTitleUpdate(st, '详情页', T0 + 2000);
  assert.equal(r1.decision, TITLE_ACCEPT);
  assert.equal(r2.decision, TITLE_ACCEPT);
  assert.equal(r2.title, '详情页');
  assert.equal(st.acceptedCount, 2);
});

test('净化发生时带 sanitized 标记但仍放行', () => {
  const st = createTitleState(T0);
  const r = decideTitleUpdate(st, 'a\x00b', T0 + 10);
  assert.equal(r.decision, TITLE_ACCEPT);
  assert.equal(r.sanitized, true);
  assert.equal(r.reason, TITLE_SANITIZED);
});

test('极短时间相同标题重复被忽略', () => {
  const st = createTitleState(T0);
  decideTitleUpdate(st, 'same', T0 + 10);
  const r = decideTitleUpdate(st, 'same', T0 + 10 + TITLE_SAME_MS - 20);
  assert.equal(r.decision, TITLE_HOLD);
  assert.equal(r.reason, HOLD_SAME);
  assert.equal(st.acceptedCount, 1);
});

test('超过去抖窗口的相同标题重新接受', () => {
  const st = createTitleState(T0);
  decideTitleUpdate(st, 'same', T0 + 10);
  const r = decideTitleUpdate(st, 'same', T0 + 10 + TITLE_SAME_MS + 50);
  assert.equal(r.decision, TITLE_ACCEPT);
});

test('标题翻转洪泛越过突发上限被收敛', () => {
  const st = createTitleState(T0);
  let blocked = null;
  for (let i = 0; i < TITLE_BURST_LIMIT + 5; i++) {
    const r = decideTitleUpdate(st, i % 2 ? '加载中...' : 'open cosy', T0 + i * 20);
    if (r.decision === TITLE_HOLD && r.reason === HOLD_BURST) blocked = r;
  }
  assert.ok(blocked, '快速翻转应被突发限流');
});

test('无状态对象安全收敛', () => {
  const r = decideTitleUpdate(null, 'x', T0);
  assert.equal(r.decision, TITLE_HOLD);
});

test('favicon scheme 白名单', () => {
  assert.equal(isAllowedFaviconScheme('https://a.test/fav.png'), true);
  assert.equal(isAllowedFaviconScheme('http://a.test/fav.png'), true);
  assert.equal(isAllowedFaviconScheme('data:image/png;base64,AAAA'), true);
  assert.equal(isAllowedFaviconScheme('file:///etc/passwd'), false);
  assert.equal(isAllowedFaviconScheme('blob:https://a.test/x'), false);
  assert.equal(isAllowedFaviconScheme('javascript:alert(1)'), false);
  assert.equal(isAllowedFaviconScheme('not a url'), false);
  assert.equal(isAllowedFaviconScheme(123), false);
});

test('sanitizeFavicons 过滤 / 限量 / 保序', () => {
  const list = [
    'https://a.test/1.png',
    'file:///bad',
    '',
    'data:image/png;base64,AAAA',
    'http://b.test/2.png',
    'x'.repeat(MAX_FAVICON_URL_LEN + 1),
    'https://c.test/3.png',
    'https://d.test/4.png',
    'https://e.test/5.png',
  ];
  const { favicons, dropped } = sanitizeFavicons(list);
  assert.ok(favicons.length <= MAX_FAVICONS);
  assert.equal(favicons[0], 'https://a.test/1.png');
  assert.equal(favicons[1], 'data:image/png;base64,AAAA');
  assert.ok(dropped >= 3, `应统计被丢弃数量，得到 ${dropped}`);

  assert.deepEqual(sanitizeFavicons(null).favicons, []);
  assert.deepEqual(sanitizeFavicons('nope').favicons, []);
});

test('resolveFaviconHref 相对路径拼接与非法基址', () => {
  assert.equal(
    resolveFaviconHref('/fav.ico', 'https://a.test/sub/page'),
    'https://a.test/fav.ico'
  );
  assert.equal(resolveFaviconHref('https://x.test/f.png', 'https://a.test/'),
    'https://x.test/f.png');
  assert.equal(resolveFaviconHref('/f.ico', 'not-a-url'), '');
});

test('原因描述可读', () => {
  for (const reason of [HOLD_BURST, HOLD_SAME, TITLE_SANITIZED]) {
    assert.ok(describeTitleReason(reason).length > 0);
  }
});
