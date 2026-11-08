'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const cg = require('./cookieguard');

// ===== 解析 =====

test('parseSetCookieEntry 解析名称、值与各属性', () => {
  const e = cg.parseSetCookieEntry('sid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict');
  assert.ok(e);
  assert.equal(e.name, 'sid');
  assert.equal(e.nameValue, 'sid=abc123');
  assert.equal(e.secure, true);
  assert.equal(e.sameSite, 'strict');
  assert.equal(e.pathSet, true);
  assert.equal(e.domainSet, false);
});

test('parseSetCookieEntry 对无等号/空名/空串返回 null', () => {
  assert.equal(cg.parseSetCookieEntry('NotACookie'), null);
  assert.equal(cg.parseSetCookieEntry('=novalue'), null);
  assert.equal(cg.parseSetCookieEntry('   '), null);
});

test('parseSetCookieEntry SameSite 大小写与无值', () => {
  assert.equal(cg.parseSetCookieEntry('a=1; sAmEsItE=NoNe').sameSite, 'none');
  assert.equal(cg.parseSetCookieEntry('a=1; SameSite=Lax').sameSite, 'lax');
  assert.equal(cg.parseSetCookieEntry('a=1; SameSite').sameSite, 'lax');
  assert.equal(cg.parseSetCookieEntry('a=1; Domain=example.com').domainSet, true);
});

// ===== 可注册域 / 跨站判定 =====

test('registrableDomain 处理多级后缀', () => {
  assert.equal(cg.registrableDomain('a.b.example.com'), 'example.com');
  assert.equal(cg.registrableDomain('shop.example.co.uk'), 'example.co.uk');
  assert.equal(cg.registrableDomain('x.gov.cn'), 'x.gov.cn');
  assert.equal(cg.registrableDomain('a.b.com.cn'), 'b.com.cn');
  assert.equal(cg.registrableDomain('localhost'), 'localhost');
});

test('isThirdPartyContext 第一方与第三方', () => {
  const first = {
    url: 'https://cdn.shop.example.com/x.js',
    documentURL: 'https://shop.example.com/page',
  };
  assert.equal(cg.isThirdPartyContext(first), false);

  const third = {
    url: 'https://tracker.evil.net/pixel.gif',
    documentURL: 'https://shop.example.com/page',
  };
  assert.equal(cg.isThirdPartyContext(third), true);

  // 顶层导航没有可比较的页面上下文时按第一方处理，避免误删登录 Cookie。
  const nav = { url: 'https://example.com/', documentURL: '' };
  assert.equal(cg.isThirdPartyContext(nav), false);
});

// ===== 前缀校验 =====

test('__Host- 前缀必须 Secure + Path=/ + 无 Domain', () => {
  const ok = cg.parseSetCookieEntry('__Host-s=1; Path=/; Secure');
  assert.equal(cg.cookiePrefixViolation(ok, true), null);

  const noSecure = cg.parseSetCookieEntry('__Host-s=1; Path=/');
  assert.equal(cg.cookiePrefixViolation(noSecure, true), 'host-prefix-not-secure');

  const domain = cg.parseSetCookieEntry('__Host-s=1; Path=/; Secure; Domain=x.com');
  assert.equal(cg.cookiePrefixViolation(domain, true), 'host-prefix-domain');

  const path = cg.parseSetCookieEntry('__Host-s=1; Path=/app; Secure');
  assert.equal(cg.cookiePrefixViolation(path, true), 'host-prefix-path');
});

test('__Secure- 前缀必须 Secure', () => {
  const ok = cg.parseSetCookieEntry('__Secure-id=1; Secure; Path=/');
  assert.equal(cg.cookiePrefixViolation(ok, true), null);
  const bad = cg.parseSetCookieEntry('__Secure-id=1; Path=/');
  assert.equal(cg.cookiePrefixViolation(bad, true), 'secure-prefix-not-secure');
});

test('普通 Cookie 名不受前缀规则约束', () => {
  const e = cg.parseSetCookieEntry('session=1');
  assert.equal(cg.cookiePrefixViolation(e, false), null);
});

// ===== 加固主流程 =====

test('第三方 Cookie 在开关打开时被剥离', () => {
  const headers = ['sid=track; Path=/; Secure'];
  const details = {
    url: 'https://tracker.evil.net/pixel',
    documentURL: 'https://shop.example.com/home',
  };
  const r = cg.hardenSetCookieHeader(headers, details, { blockThirdParty: true });
  assert.deepEqual(r.lines, []);
  assert.equal(r.actions.length, 1);
  assert.equal(r.actions[0].action, 'block-third-party');
  assert.equal(r.actions[0].crossSite, true);
});

test('第一方 Cookie 保留并补 SameSite=Lax', () => {
  const headers = ['sid=abc; Path=/; HttpOnly'];
  const details = { url: 'https://shop.example.com/', documentURL: '' };
  const r = cg.hardenSetCookieHeader(headers, details, { blockThirdParty: true });
  assert.equal(r.lines.length, 1);
  assert.match(r.lines[0], /SameSite=Lax/);
  assert.equal(r.actions[0].action, 'samesite-default-lax');
});

test('SameSite=None 缺 Secure 时降级为 Lax', () => {
  const headers = ['sid=abc; SameSite=None; Path=/'];
  // 用 https 响应：SameSite=None 无 Secure 非法。
  const details = { url: 'https://shop.example.com/', documentURL: '' };
  const r = cg.hardenSetCookieHeader(headers, details, {});
  assert.equal(r.lines.length, 1);
  assert.match(r.lines[0], /SameSite=Lax/);
  assert.doesNotMatch(r.lines[0], /SameSite=None/);
});

test('合规的 SameSite=None; Secure 保持不变', () => {
  const headers = ['sid=abc; SameSite=None; Secure; Path=/'];
  const details = { url: 'https://shop.example.com/', documentURL: '' };
  const r = cg.hardenSetCookieHeader(headers, details, {});
  assert.equal(r.lines[0], headers[0]);
  assert.equal(r.actions.length, 0);
});

test('非安全上下文带 Secure 的 Cookie 被剥离', () => {
  const headers = ['token=x; Secure'];
  const details = { url: 'http://shop.example.com/', documentURL: '' };
  const r = cg.hardenSetCookieHeader(headers, details, {});
  assert.deepEqual(r.lines, []);
  assert.equal(r.actions[0].reason, 'secure-on-insecure-origin');
});

test('__Host- 前缀违规被剥离，合规条目保留', () => {
  const headers = [
    '__Host-bad=1; Path=/app; Secure',
    '__Host-good=1; Path=/; Secure',
  ];
  const details = { url: 'https://shop.example.com/', documentURL: '' };
  const r = cg.hardenSetCookieHeader(headers, details, {});
  assert.equal(r.lines.length, 1);
  assert.match(r.lines[0], /__Host-good/);
  assert.equal(r.actions[0].reason, 'host-prefix-path');
});

test('关闭第三方拦截时跨站 Cookie 不剥离但仍补 SameSite', () => {
  const headers = ['sid=1'];
  const details = {
    url: 'https://tracker.evil.net/x',
    documentURL: 'https://shop.example.com/p',
  };
  const r = cg.hardenSetCookieHeader(headers, details, { blockThirdParty: false });
  assert.equal(r.lines.length, 1);
  assert.match(r.lines[0], /SameSite=Lax/);
});

// ===== 台账聚合 =====

test('createCookieLedger 去重累加、封顶与统计', () => {
  const ledger = cg.createCookieLedger(2);
  ledger.addMany([
    { host: 'a.com', name: 'x', action: 'block-third-party', reason: 'cross-site-set-cookie', crossSite: true },
    { host: 'a.com', name: 'x', action: 'block-third-party', reason: 'cross-site-set-cookie', crossSite: true },
    { host: 'b.com', name: 'y', action: 'samesite-default-lax', reason: 'samesite-missing-default-lax' },
    { host: 'c.com', name: 'z', action: 'block-third-party', reason: 'cross-site-set-cookie' },
  ]);
  assert.equal(ledger.size(), 2); // cap=2，最旧的一条被挤掉
  const s = ledger.stats();
  assert.equal(s.hosts, 2);
  assert.ok(s.blocked >= 1);
  assert.ok(s.rewritten >= 1 || s.blocked >= 1);

  ledger.clear();
  assert.equal(ledger.size(), 0);
});

test('ledger toJSON/load 往返', () => {
  const ledger = cg.createCookieLedger(100);
  ledger.add({ host: 'a.com', name: 'n', action: 'drop-prefix', reason: 'host-prefix-path' });
  const json = ledger.toJSON();
  const ledger2 = cg.createCookieLedger(100);
  ledger2.load(json);
  assert.equal(ledger2.size(), 1);
  assert.equal(ledger2.list()[0].host, 'a.com');
});
