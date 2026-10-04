'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const rg = require('./restoreguard');

const NOW = 1_700_000_000_000;

test('sanitizeRestoreTitle 归一换行、删控制字符、压空白、截上界', () => {
  assert.equal(rg.sanitizeRestoreTitle('a\tb\nc\rd'), 'a b c d');
  assert.equal(rg.sanitizeRestoreTitle('x\u0000y\u001Bz\u007F'), 'xyz');
  assert.equal(rg.sanitizeRestoreTitle('  a    b  '), 'a b');
  assert.equal(rg.sanitizeRestoreTitle(7), '');
  const long = '标'.repeat(rg.MAX_TITLE_CHARS + 30);
  assert.equal(rg.sanitizeRestoreTitle(long).length, rg.MAX_TITLE_CHARS);
});

test('sanitizeRestoreUrl 仅接受 http/https 且 host 非空、限长', () => {
  assert.equal(rg.sanitizeRestoreUrl('https://a.test/x').ok, true);
  for (const bad of ['file:///C:/x', 'about:blank', 'cosy://newtab', 'javascript:x',
    'data:text/html,x', 'chrome://flags', 'view-source:https://a.test', 'no', '', undefined]) {
    assert.equal(rg.sanitizeRestoreUrl(bad).ok, false, String(bad));
  }
  assert.equal(rg.sanitizeRestoreUrl('file:///x').reason, rg.SKIP_BAD_PROTOCOL);
  const tooLong = 'https://e.test/' + 'a'.repeat(rg.MAX_URL_CHARS);
  assert.equal(rg.sanitizeRestoreUrl(tooLong).reason, rg.SKIP_URL_TOO_LONG);
});

test('sanitizeSessionTab 拒绝非对象/坏 url，标题空用 host 兜底', () => {
  assert.equal(rg.sanitizeSessionTab(null).ok, false);
  assert.equal(rg.sanitizeSessionTab('x').ok, false);
  assert.equal(rg.sanitizeSessionTab([1]).ok, false);
  assert.equal(rg.sanitizeSessionTab({ url: 'javascript:alert(1)' }).ok, false);

  const ok = rg.sanitizeSessionTab({ url: 'https://www.a.test/', title: 'T\u0007' });
  assert.equal(ok.ok, true);
  assert.equal(ok.tab.url, 'https://www.a.test/');
  assert.equal(ok.tab.title, 'T');

  const fallback = rg.sanitizeSessionTab({ url: 'https://www.a.test/' });
  assert.equal(fallback.tab.title, 'a.test');
});

test('sanitizeSessionList 非数组为空，逐条丢弃脏项并截断到上界', () => {
  assert.deepEqual(rg.sanitizeSessionList(null).tabs, []);
  assert.deepEqual(rg.sanitizeSessionList({}).tabs, []);
  const out = rg.sanitizeSessionList([
    null, 1, 's', { url: 'file:///x' },
    { url: 'https://a.test/' },
    { url: 'https://b.test/', title: 'B' },
  ]);
  assert.equal(out.tabs.length, 2);
  assert.equal(out.dropped, 4);

  const big = [];
  for (let i = 0; i < rg.MAX_SESSION_TABS + 15; i++) big.push({ url: `https://s${i}.test/` });
  const capped = rg.sanitizeSessionList(big);
  assert.equal(capped.tabs.length, rg.MAX_SESSION_TABS);
  assert.equal(capped.dropped, 15);
});

test('isValidClosedAt 只接受有限非负数字', () => {
  assert.equal(rg.isValidClosedAt(0), true);
  assert.equal(rg.isValidClosedAt(123), true);
  assert.equal(rg.isValidClosedAt(-1), false);
  assert.equal(rg.isValidClosedAt(NaN), false);
  assert.equal(rg.isValidClosedAt(Infinity), false);
  assert.equal(rg.isValidClosedAt('1'), false);
  assert.equal(rg.isValidClosedAt(null), false);
});

test('sanitizeClosedTab 净化 url/title 并保留或补 closedAt', () => {
  const r = rg.sanitizeClosedTab({ url: 'https://a.test/', title: 'A', closedAt: 55 }, NOW);
  assert.equal(r.ok, true);
  assert.deepEqual(r.tab, { url: 'https://a.test/', title: 'A', closedAt: 55 });

  const r2 = rg.sanitizeClosedTab({ url: 'https://a.test/' }, NOW);
  assert.equal(r2.tab.closedAt, NOW);

  const r3 = rg.sanitizeClosedTab({ url: 'https://a.test/', closedAt: -9 }, NOW);
  assert.equal(r3.tab.closedAt, NOW);

  assert.equal(rg.sanitizeClosedTab({ url: 'about:blank' }, NOW).ok, false);
});

test('pushRecentlyClosed 入栈净化、超深淘汰最旧；popLastClosed 后进先出', () => {
  const st = rg.createRecentlyClosedState();
  for (let i = 0; i < rg.MAX_RECENTLY_CLOSED + 3; i++) {
    const r = rg.pushRecentlyClosed(st, { url: `https://n${i}.test/`, title: `N${i}`, closedAt: i }, NOW);
    assert.equal(r.status, 'pushed');
  }
  assert.equal(st.items.length, rg.MAX_RECENTLY_CLOSED);
  // 最旧 3 条（n0/n1/n2）被淘汰，栈首应是 n3。
  assert.equal(st.items[0].url, 'https://n3.test/');

  const top = rg.popLastClosed(st);
  assert.equal(top.url, `https://n${rg.MAX_RECENTLY_CLOSED + 2}.test/`);

  // 坏条目被拒绝，不入栈。
  const bad = rg.pushRecentlyClosed(st, { url: 'cosy://x' }, NOW);
  assert.equal(bad.status, 'rejected');
  assert.equal(st.items.length, rg.MAX_RECENTLY_CLOSED - 1);
});

test('popLastClosed 空栈返回 null', () => {
  const st = rg.createRecentlyClosedState();
  assert.equal(rg.popLastClosed(st), null);
  assert.equal(rg.popLastClosed(null), null);
});

test('sanitizeRecentlyClosedList 非数组为空、逐条净化、截断、补时间戳', () => {
  const out = rg.sanitizeRecentlyClosedList([
    null, { url: 'file:///x' },
    { url: 'https://a.test/', title: 'A' },
    { url: 'https://b.test/', title: 'B', closedAt: 9 },
  ], NOW);
  assert.equal(out.items.length, 2);
  assert.equal(out.items[0].closedAt, NOW);   // 缺失时间戳补 now
  assert.equal(out.items[1].closedAt, 9);
  assert.equal(out.dropped, 2);
  assert.deepEqual(rg.sanitizeRecentlyClosedList('x', NOW).items, []);
});
