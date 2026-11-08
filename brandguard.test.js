'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const bg = require('./brandguard');

test('registrableHost 处理多级后缀', () => {
  assert.equal(bg.registrableHost('www.paypal.com'), 'paypal.com');
  assert.equal(bg.registrableHost('news.bbc.co.uk'), 'bbc.co.uk');
  assert.equal(bg.registrableHost('a.b.example.com.cn'), 'example.com.cn');
  assert.equal(bg.registrableHost('example.org'), 'example.org');
});

test('levenshtein 基础距离与剪枝', () => {
  assert.equal(bg.levenshtein('kitten', 'sitting', 3), 3);
  assert.equal(bg.levenshtein('paypal', 'paypl', 1), 1);
  assert.equal(bg.levenshtein('paypal', 'paypal', 1), 0);
  // 长度差超过阈值应提前返回 max+1，不必算出真实距离。
  assert.ok(bg.levenshtein('paypal', 'p', 1) > 1);
});

test('拼写劫持：与品牌差一个编辑操作且非官方域', () => {
  const cases = [
    ['paypl.com', 'paypal'],
    ['goolge.com', 'google'],
    ['amazom.com', 'amazon'],
    ['microsfot.com', 'microsoft'],
    ['githbu.com', 'github'],
    ['netflx.com', 'netflix'],
  ];
  for (const [host, brand] of cases) {
    const r = bg.analyzeBrand(host);
    assert.ok(r, `${host} 应判为可疑`);
    assert.equal(r.reason, 'typo-domain');
    assert.equal(r.brand, brand);
  }
});

test('品牌词被放进子域、注册域陌生 → brand-in-subdomain', () => {
  const r = bg.analyzeBrand('paypal.com.evil-login.xyz');
  assert.ok(r);
  assert.equal(r.reason, 'brand-in-subdomain');
  assert.equal(r.brand, 'paypal');
});

test('注册域同时含品牌词与诱导词 → brand-keyword-impersonation', () => {
  const r = bg.analyzeBrand('appleid-security-verify.com');
  assert.ok(r);
  assert.equal(r.reason, 'brand-keyword-impersonation');
  assert.equal(r.brand, 'apple');

  const r2 = bg.analyzeBrand('paypal-account-update.org');
  assert.ok(r2);
  assert.equal(r2.brand, 'paypal');
});

test('官方域名零误伤', () => {
  const official = [
    'www.paypal.com', 'paypal.com', 'paypal.co.uk',
    'appleid.apple.com', 'icloud.com',
    'mail.google.com', 'gmail.com', 'googleapis.com',
    'login.microsoftonline.com', 'outlook.com', 'office.com',
    'github.com', 'raw.githubusercontent.com', 'gist.github.com',
    'smile.amazon.com', 's3.amazonaws.com',
    'world.taobao.com', 'login.alipay.com',
  ];
  for (const host of official) {
    assert.equal(bg.analyzeBrand(host), null, `${host} 不应报警`);
  }
});

test('普通无关域名不误报', () => {
  const normal = [
    'example.com', 'wikipedia.org', 'developer.mozilla.org',
    'my-personal-blog.net', 'news.cn', 'stackoverflow.com',
    'localhost', '127.0.0.1', 'a.b.c.d', '',
  ];
  for (const host of normal) {
    assert.equal(bg.analyzeBrand(host), null, `${host} 不应报警`);
  }
});

test('非 ASCII 主机交给 homograph，这里不重复判定', () => {
  // 含非拉丁字符的由 main.js analyzeHostForSpoof 负责。
  assert.equal(bg.analyzeBrand('раypal.com'), null);
});

test('hostFromUrl 只接受 http(s) 且容错', () => {
  assert.equal(bg.hostFromUrl('https://paypl.com/a?b=1'), 'paypl.com');
  assert.equal(bg.hostFromUrl('http://x.co'), 'x.co');
  assert.equal(bg.hostFromUrl('ftp://paypal.com'), '');
  assert.equal(bg.hostFromUrl('not a url'), '');
  assert.equal(bg.hostFromUrl(null), '');
});

test('短品牌（x/qq）不做单字拼写距离，避免大面积误伤', () => {
  // 合法的单字母近邻域名不应被当成 x.com 的拼写劫持。
  assert.equal(bg.analyzeBrand('z.com'), null);
  assert.equal(bg.analyzeBrand('q.com'), null);
});

test('结论字段形状稳定、可序列化', () => {
  const r = bg.analyzeBrand('paypl.com');
  assert.deepEqual(Object.keys(r).sort(), ['brand', 'hint', 'hostname', 'reason']);
  assert.doesNotThrow(() => JSON.stringify(r));
});
