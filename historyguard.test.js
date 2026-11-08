'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const hg = require('./historyguard');

test('sanitizeHistoryTitle 去除控制字符并压缩空白、截断上界', () => {
  assert.equal(hg.sanitizeHistoryTitle('a\tb\nc\rd'), 'a b c d');
  assert.equal(hg.sanitizeHistoryTitle('x\u0000y\u007Fz'), 'xyz');
  assert.equal(hg.sanitizeHistoryTitle('  多   空格  '), '多 空格');
  assert.equal(hg.sanitizeHistoryTitle(123), '');
  const long = '题'.repeat(hg.MAX_TITLE_CHARS + 50);
  assert.equal(hg.sanitizeHistoryTitle(long).length, hg.MAX_TITLE_CHARS);
});

test('sanitizeHistoryUrl 仅接受 http/https 且可解析、host 非空', () => {
  assert.equal(hg.sanitizeHistoryUrl('https://example.com/p').ok, true);
  assert.equal(hg.sanitizeHistoryUrl('http://a.test:8080/x?q=1').ok, true);
  let r = hg.sanitizeHistoryUrl('file:///C:/secret.txt');
  assert.equal(r.ok, false);
  assert.equal(r.reason, hg.SKIP_BAD_PROTOCOL);
  for (const bad of ['about:blank', 'cosy://settings', 'javascript:alert(1)',
    'data:text/html,x', 'chrome://version', 'view-source:https://a.test', 'not a url', '']) {
    assert.equal(hg.sanitizeHistoryUrl(bad).ok, false, bad);
  }
  assert.equal(hg.sanitizeHistoryUrl('').reason, hg.SKIP_EMPTY);
  const tooLong = 'https://e.test/' + 'a'.repeat(hg.MAX_URL_CHARS);
  assert.equal(hg.sanitizeHistoryUrl(tooLong).reason, hg.SKIP_TOO_LONG);
});

test('新 URL 记为 store 并置于最前', () => {
  const st = hg.createHistoryState();
  const v = hg.decideHistoryWrite(st, { url: 'https://a.test/', title: 'A' }, 1000);
  assert.equal(v.decision, hg.DECISION_STORE);
  assert.equal(st.items[0].url, 'https://a.test/');
  assert.equal(st.items[0].title, 'A');
  assert.equal(st.items[0].timestamp, 1000);
});

test('合并窗内重复访问只 merge 一次且不产生重复条目', () => {
  const st = hg.createHistoryState();
  hg.decideHistoryWrite(st, { url: 'https://a.test/', title: 'A' }, 1000);
  const v2 = hg.decideHistoryWrite(st, { url: 'https://a.test/', title: 'A2' }, 5000);
  assert.equal(v2.decision, hg.DECISION_MERGE);
  assert.equal(st.items.length, 1);
  assert.equal(st.items[0].timestamp, 5000);
  assert.equal(st.items[0].title, 'A2');
});

test('合并窗外再次访问作为新访问 store 但仍去重为一条', () => {
  const st = hg.createHistoryState();
  hg.decideHistoryWrite(st, { url: 'https://a.test/' }, 1000);
  const v2 = hg.decideHistoryWrite(st, { url: 'https://a.test/' }, 1000 + hg.MERGE_WINDOW_MS + 1);
  assert.equal(v2.decision, hg.DECISION_STORE);
  assert.equal(st.items.length, 1);
  assert.equal(st.items[0].timestamp, 1000 + hg.MERGE_WINDOW_MS + 1);
});

test('不同 URL 按最近访问排序', () => {
  const st = hg.createHistoryState();
  hg.decideHistoryWrite(st, { url: 'https://a.test/' }, 1000);
  hg.decideHistoryWrite(st, { url: 'https://b.test/' }, 2000);
  hg.decideHistoryWrite(st, { url: 'https://c.test/' }, 3000);
  assert.deepEqual(st.items.map((i) => i.url),
    ['https://c.test/', 'https://b.test/', 'https://a.test/']);
});

test('非法输入跳过且不写入', () => {
  const st = hg.createHistoryState();
  assert.equal(hg.decideHistoryWrite(st, { url: 'javascript:x' }, 1).decision, hg.DECISION_SKIP);
  assert.equal(hg.decideHistoryWrite(st, { url: '' }, 1).decision, hg.DECISION_SKIP);
  assert.equal(st.items.length, 0);
});

test('硬上界淘汰最旧', () => {
  const st = hg.createHistoryState();
  for (let i = 0; i < hg.MAX_HISTORY_ITEMS + 3; i++) {
    hg.decideHistoryWrite(st, { url: `https://e${i}.test/` }, 1000 + i);
  }
  assert.equal(st.items.length, hg.MAX_HISTORY_ITEMS);
  // 最旧的三条 e0/e1/e2 已被淘汰，最新条目在最前。
  assert.equal(st.items[0].url, `https://e${hg.MAX_HISTORY_ITEMS + 2}.test/`);
  assert.equal(hg.findIndexByUrl(st, 'https://e0.test/'), -1);
});

test('pruneHistoryByTime 仅删除闭区间内条目', () => {
  const st = hg.createHistoryState();
  [100, 200, 300, 400].forEach((t, i) =>
    hg.decideHistoryWrite(st, { url: `https://${i}.test/` }, t));
  const removed = hg.pruneHistoryByTime(st, 200, 300);
  assert.equal(removed, 2);
  assert.deepEqual(st.items.map((i) => i.timestamp).sort((a, b) => a - b), [100, 400]);
});

test('pruneHistoryByTime 对非法/反向范围返回 -1 且不改数据', () => {
  const st = hg.createHistoryState();
  hg.decideHistoryWrite(st, { url: 'https://a.test/' }, 100);
  const before = st.items.length;
  assert.equal(hg.pruneHistoryByTime(st, 300, 100), -1);
  assert.equal(hg.pruneHistoryByTime(st, -1, 100), -1);
  assert.equal(st.items.length, before);
});

test('clearAllHistory 清空并返回数量', () => {
  const st = hg.createHistoryState();
  hg.decideHistoryWrite(st, { url: 'https://a.test/' }, 1);
  hg.decideHistoryWrite(st, { url: 'https://b.test/' }, 2);
  assert.equal(hg.clearAllHistory(st), 2);
  assert.equal(st.items.length, 0);
});

test('createHistoryState 对超长初始数组裁剪到上界', () => {
  const many = [];
  for (let i = 0; i < hg.MAX_HISTORY_ITEMS + 10; i++) {
    many.push({ url: `https://${i}.test/`, title: '', timestamp: i });
  }
  const st = hg.createHistoryState(many);
  assert.equal(st.items.length, hg.MAX_HISTORY_ITEMS);
});
