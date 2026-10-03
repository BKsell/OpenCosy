'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  REDIRECT_BLOCK,
  REDIRECT_ALLOW,
  REDIRECT_MAX_CHAIN,
  siteLabel,
  createRedirectState,
  resetState,
  normalizeForCompare,
  decideRedirect,
  describeReason,
} = require('./redirectguard');

test('siteLabel 取站点近似标签', () => {
  assert.equal(siteLabel('a.b.example.com'), 'example.com');
  assert.equal(siteLabel('example.com'), 'example.com');
  assert.equal(siteLabel('www.Example.COM.'), 'example.com');
  assert.equal(siteLabel('127.0.0.1'), '127.0.0.1');
  assert.equal(siteLabel('localhost'), 'localhost');
  assert.equal(siteLabel('[::1]'), '[::1]');
  assert.equal(siteLabel(''), '');
});

test('normalizeForCompare 去 hash 与尾斜杠', () => {
  assert.equal(normalizeForCompare('https://a.test/x/#frag'), 'https://a.test/x');
  assert.equal(normalizeForCompare('https://a.test/x///'), 'https://a.test/x');
  assert.equal(normalizeForCompare('https://a.test/x?q=1'), 'https://a.test/x?q=1');
});

test('正常同站 https 重定向放行', () => {
  const st = createRedirectState(0);
  const r = decideRedirect(st, { fromUrl: 'https://a.test/1', toUrl: 'https://a.test/2' }, 1);
  assert.equal(r.action, REDIRECT_ALLOW);
  assert.deepEqual(r.reasons, []);
  assert.equal(r.state.count, 1);
  assert.equal(r.state.startHost, 'a.test');
  assert.equal(r.state.startHttps, true);
});

test('https 到 http 显式降级拦截', () => {
  const st = createRedirectState(0);
  const r = decideRedirect(st, { fromUrl: 'https://a.test/login', toUrl: 'http://a.test/login' }, 2);
  assert.equal(r.action, REDIRECT_BLOCK);
  assert.ok(r.reasons.includes('redirect-downgrade'));
});

test('链路起点 https，在已降级后继续明文跳，判链路降级', () => {
  const st = createRedirectState(0);
  decideRedirect(st, { fromUrl: 'https://a.test/1', toUrl: 'http://b.test/2' }, 1);
  // 第二跳的“上一跳”已是 http，直连降级不再触发，但链起点是 https，
  // 仍应按链路降级标记，防止“先降一级、再连续明文跳”被漏报。
  const r = decideRedirect(st, { fromUrl: 'http://b.test/2', toUrl: 'http://c.test/3' }, 2);
  assert.equal(r.action, REDIRECT_BLOCK);
  assert.ok(r.reasons.includes('redirect-chain-downgrade'));
});

test('重定向到危险 scheme 拦截', () => {
  for (const to of ['file:///C:/x', 'javascript:alert(1)', 'data:text/html,x', 'cosy://settings/']) {
    const st = createRedirectState(0);
    const r = decideRedirect(st, { fromUrl: 'https://a.test/', toUrl: to }, 1);
    assert.equal(r.action, REDIRECT_BLOCK, `${to} 应被拦截`);
    assert.ok(r.reasons.includes('redirect-dangerous-scheme'), `${to} 缺 scheme 原因`);
  }
});

test('目标带 userinfo 判钓鱼', () => {
  const st = createRedirectState(0);
  const r = decideRedirect(st,
    { fromUrl: 'https://a.test/', toUrl: 'https://admin:p%40ss@evil.test/' }, 1);
  assert.equal(r.action, REDIRECT_BLOCK);
  assert.ok(r.reasons.includes('redirect-userinfo'));
});

test('同一目标反复出现判环路', () => {
  const st = createRedirectState(0);
  const pair = [
    { fromUrl: 'https://a.test/a', toUrl: 'https://a.test/b' },
    { fromUrl: 'https://a.test/b', toUrl: 'https://a.test/a' },
  ];
  let blocked = false;
  for (let i = 0; i < 8; i++) {
    const r = decideRedirect(st, pair[i % 2], i + 1);
    if (r.action === REDIRECT_BLOCK && r.reasons.includes('redirect-loop')) blocked = true;
  }
  assert.ok(blocked, 'A→B→A 反复应判 redirect-loop');
});

test('超过最大链长拦截', () => {
  const st = createRedirectState(0);
  let blocked = false;
  for (let i = 0; i < REDIRECT_MAX_CHAIN + 2; i++) {
    const r = decideRedirect(st,
      { fromUrl: `https://a.test/${i}`, toUrl: `https://a.test/${i + 1}` }, i + 1);
    if (r.action === REDIRECT_BLOCK && r.reasons.includes('redirect-chain-too-long')) blocked = true;
  }
  assert.ok(blocked);
});

test('无法解析的目标拦截', () => {
  const st = createRedirectState(0);
  const r = decideRedirect(st, { fromUrl: 'https://a.test/', toUrl: 'ht!tp://%%' }, 1);
  assert.equal(r.action, REDIRECT_BLOCK);
  assert.ok(r.reasons.includes('redirect-malformed-target'));
});

test('resetState 清空链并刷新起点时间', () => {
  const st = createRedirectState(0);
  decideRedirect(st, { fromUrl: 'https://a.test/1', toUrl: 'https://a.test/2' }, 1);
  resetState(st, 50);
  assert.equal(st.count, 0);
  assert.equal(st.startedAt, 50);
  assert.equal(st.seenUrls.size, 0);
  assert.equal(st.hosts.length, 0);
});

test('describeReason 给出中文说明', () => {
  assert.match(describeReason('redirect-downgrade'), /HTTP/);
  assert.equal(describeReason('unknown-code'), 'unknown-code');
});

test('缺 state 时自建，不抛异常', () => {
  const r = decideRedirect(null, { fromUrl: 'https://a.test/', toUrl: 'https://a.test/x' }, 1);
  assert.equal(r.action, REDIRECT_ALLOW);
  assert.ok(r.state);
});
