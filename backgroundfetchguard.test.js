'use strict';

// backgroundfetchguard.test.js —— Background Fetch：SW 门、请求数、总量、虚报、目标 https/私网、标题图标、并发。

const test = require('node:test');
const assert = require('node:assert/strict');
const b = require('./backgroundfetchguard');
const { BackgroundFetchGuard, BF_REASON, isPrivateHost } = b;

function ctx(over) {
  return Object.assign({ origin: 'https://pod.example.com', serviceWorkerActive: true }, over || {});
}
function requests(n) {
  const arr = [];
  for (let i = 0; i < n; i++) arr.push('https://cdn.example.com/ep' + i + '.m4a');
  return arr;
}
function options(over) {
  return Object.assign({ downloadTotal: 10 * 1024 * 1024, title: 'episode' }, over || {});
}

test('合规后台下载放行', () => {
  const g = new BackgroundFetchGuard();
  assert.equal(g.decideFetch(ctx(), 'f1', requests(2), options()).decision, 'allow');
});

test('无活动 SW / 非 https 拒绝', () => {
  const g = new BackgroundFetchGuard();
  assert.equal(g.decideFetch(ctx({ serviceWorkerActive: false }), 'f', requests(1), options()).reason, BF_REASON.NOT_INSTALLED);
  assert.equal(g.decideFetch(ctx({ origin: 'http://x' }), 'f', requests(1), options()).reason, BF_REASON.INSECURE_ORIGIN);
});

test('无请求/请求过多拒绝', () => {
  const g = new BackgroundFetchGuard();
  assert.equal(g.decideFetch(ctx(), 'f', [], options()).reason, BF_REASON.NO_REQUESTS);
  assert.equal(g.decideFetch(ctx(), 'f', requests(9), options()).reason, BF_REASON.TOO_MANY_REQUESTS);
});

test('总量非法/过大拒绝', () => {
  const g = new BackgroundFetchGuard();
  assert.equal(g.decideFetch(ctx(), 'f', requests(1), { downloadTotal: -1 }).reason, BF_REASON.BAD_TOTAL);
  assert.equal(g.decideFetch(ctx(), 'f', requests(1), { downloadTotal: 999 * 1024 * 1024 }).reason, BF_REASON.TOTAL_TOO_LARGE);
});

test('实际体显著超过声明（虚报）拒绝', () => {
  const g = new BackgroundFetchGuard();
  assert.equal(g.decideFetch(ctx(), 'f', requests(1), { downloadTotal: 1000 }, 5000).reason,
    BF_REASON.TOTAL_UNDERREPORTED);
});

test('http/内网目标拒绝', () => {
  const g = new BackgroundFetchGuard();
  assert.equal(g.decideFetch(ctx(), 'f', ['http://cdn.example.com/a'], options()).reason, BF_REASON.INSECURE_TARGET);
  assert.equal(g.decideFetch(ctx(), 'f', ['https://192.168.1.5/a'], options()).reason, BF_REASON.TARGET_PRIVATE);
});

test('标题脏数据/图标过多或非 https 拒绝', () => {
  const g = new BackgroundFetchGuard();
  assert.equal(g.decideFetch(ctx(), 'f', requests(1), options({ title: 'a\nb' })).reason, BF_REASON.BAD_TITLE_ICON);
  const icons = [];
  for (let i = 0; i < 7; i++) icons.push({ src: 'https://x/' + i + '.png' });
  assert.equal(g.decideFetch(ctx(), 'f', requests(1), options({ icons })).reason, BF_REASON.BAD_TITLE_ICON);
  assert.equal(g.decideFetch(ctx(), 'f', requests(1), options({ icons: [{ src: 'http://x/a.png' }] })).reason,
    BF_REASON.BAD_TITLE_ICON);
});

test('每源并发上限，完成后释放', () => {
  const pol = b.defaultBackgroundFetchPolicy();
  pol.maxConcurrentPerOrigin = 1;
  const g = new BackgroundFetchGuard(pol);
  assert.equal(g.decideFetch(ctx(), 'f1', requests(1), options()).decision, 'allow');
  assert.equal(g.decideFetch(ctx(), 'f2', requests(1), options()).reason, BF_REASON.CONCURRENT_FETCHES);
  g.finish(ctx());
  assert.equal(g.decideFetch(ctx(), 'f3', requests(1), options()).decision, 'allow');
});

test('isPrivateHost 判定', () => {
  assert.equal(isPrivateHost('10.1.1.1'), true);
  assert.equal(isPrivateHost('host.local'), true);
  assert.equal(isPrivateHost('93.184.216.34'), false);
});
