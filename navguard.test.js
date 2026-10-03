'use strict';

// navguard.test.js —— 导航安全内核：脚本族分类、整标签同形映射、混合脚本拦截、
// Punycode 提示、整词同形警告、HTTPS→HTTP 降级（同站警告/跨站拦截）。

const test = require('node:test');
const assert = require('node:assert/strict');
const ng = require('./navguard');

test('脚本族分类：拉丁 / 数字 / 西里尔 / 希腊', () => {
  assert.equal(ng.scriptOfCodePoint('a'.codePointAt(0)), 'Latin');
  assert.equal(ng.scriptOfCodePoint('Z'.codePointAt(0)), 'Latin');
  assert.equal(ng.scriptOfCodePoint('7'.codePointAt(0)), 'Digit');
  assert.equal(ng.scriptOfCodePoint('а'.codePointAt(0)), 'Cyrillic');
  assert.equal(ng.scriptOfCodePoint('ο'.codePointAt(0)), 'Greek');
  assert.equal(ng.scriptOfCodePoint('-'.codePointAt(0)), 'Common');
});

test('countScripts 统计一个标签里的字母脚本族', () => {
  const s = ng.countScripts('раypal');
  assert.ok(s.has('Latin'));
  assert.ok(s.has('Cyrillic'));
  assert.equal(s.has('Greek'), false);
});

test('整标签西里尔同形词可映射成拉丁串', () => {
  // р(а)у? 用纯西里尔 “рара” → papa 之类；这里选整词都能映射的。
  const r = ng.mapToLatinLookalike('рара');
  assert.equal(r.ok, true);
  assert.equal(r.changed, true);
  assert.match(r.mapped, /^[A-Za-z0-9-]+$/);
});

test('混入无法映射字符时不算整词同形候选', () => {
  const r = ng.mapToLatinLookalike('ффа'); // ф 未收录
  assert.equal(r.ok, false);
});

test('纯拉丁标签不产生 changed 映射', () => {
  assert.equal(ng.mapToLatinLookalike('paypal').changed, false);
});

test('混合脚本标签（拉丁+西里尔）直接 block', () => {
  const ana = ng.analyzeHostname('раypal.com');
  assert.equal(ana.risk, ng.RISK_BLOCK);
  assert.equal(ana.mixedScript, true);
  assert.ok(ana.reasons.some(r => r.startsWith('mixed-script-label')));
});

test('混合脚本标签（拉丁+希腊）直接 block', () => {
  // gοοgle：ο 为希腊 omicron，其余拉丁
  const ana = ng.analyzeHostname('gοοgle.com');
  assert.equal(ana.risk, ng.RISK_BLOCK);
});

test('整词西里尔同形（无拉丁混写）给 warn', () => {
  // 全西里尔 “рара”.com
  const ana = ng.analyzeHostname('рара.com');
  assert.equal(ana.risk, ng.RISK_WARN);
  assert.ok(ana.lookalikes.length >= 1);
});

test('普通拉丁域名 allow', () => {
  assert.equal(ng.analyzeHostname('paypal.com').risk, ng.RISK_OK);
  assert.equal(ng.analyzeHostname('www.example.co.uk').risk, ng.RISK_OK);
});

test('Punycode 标签至少 warn', () => {
  // xn-- 前缀但解码内容不构成更强信号时，仍应提示。
  const ana = ng.analyzeHostname('xn--nxasmq6b.example');
  assert.ok([ng.RISK_WARN, ng.RISK_BLOCK].includes(ana.risk));
  assert.equal(ana.punycode, true);
});

test('著名西里尔苹果 Punycode 域被识别为风险', () => {
  // xn--80ak6aa92e → аррӏе（经典 apple 同形钓鱼 PoC 域）。
  const decoded = ng.decodePunyLabel('xn--80ak6aa92e');
  if (decoded) {
    const ana = ng.analyzeHostname('xn--80ak6aa92e.com');
    assert.notEqual(ana.risk, ng.RISK_OK);
  }
  // 环境无 domainToUnicode 时跳过强断言，但函数不应抛错。
  assert.equal(typeof ng.decodePunyLabel('xn--zzz'), 'string');
});

test('降级判定：https→http 同主机', () => {
  const dg = ng.isDowngradeNavigation('https://example.com/login', 'http://example.com/home');
  assert.equal(dg.downgrade, true);
  assert.equal(dg.sameHost, true);
});

test('降级判定：https→http 跨主机', () => {
  const dg = ng.isDowngradeNavigation('https://example.com/', 'http://examp1e.com/');
  assert.equal(dg.downgrade, true);
  assert.equal(dg.sameHost, false);
});

test('http→http 或 https→https 不算降级', () => {
  assert.equal(ng.isDowngradeNavigation('http://a.com/', 'http://b.com/').downgrade, false);
  assert.equal(ng.isDowngradeNavigation('https://a.com/', 'https://b.com/').downgrade, false);
});

test('decideNavigation：正常 https 导航 allow', () => {
  const d = ng.decideNavigation({ currentUrl: 'https://a.com/', targetUrl: 'https://b.com/x' });
  assert.equal(d.action, ng.RISK_OK);
});

test('decideNavigation：混合脚本域 block', () => {
  const d = ng.decideNavigation({ currentUrl: 'https://x.com/', targetUrl: 'https://раypal.com/' });
  assert.equal(d.action, ng.RISK_BLOCK);
  assert.ok(d.reasons.host.length >= 1);
});

test('decideNavigation：跨主机 http 降级 block', () => {
  const d = ng.decideNavigation({ currentUrl: 'https://example.com/', targetUrl: 'http://evil.example/' });
  assert.equal(d.action, ng.RISK_BLOCK);
  assert.ok(d.reasons.nav.includes('https-to-http-cross-host'));
});

test('decideNavigation：同主机 http 降级 warn（不误伤站点自身）', () => {
  const d = ng.decideNavigation({ currentUrl: 'https://example.com/', targetUrl: 'http://example.com/x' });
  assert.equal(d.action, ng.RISK_WARN);
  assert.ok(d.reasons.nav.includes('https-to-http-same-host'));
});

test('decideNavigation：同时命中混合脚本+降级时取最高档 block', () => {
  const d = ng.decideNavigation({ currentUrl: 'https://a.com/', targetUrl: 'http://раypal.com/' });
  assert.equal(d.action, ng.RISK_BLOCK);
});

test('hostnameOf 对非法 URL 返回空串', () => {
  assert.equal(ng.hostnameOf('not a url'), '');
  assert.equal(ng.hostnameOf('https://Example.COM:8443/'), 'example.com');
});

test('空输入安全返回 allow 而不抛错', () => {
  assert.equal(ng.decideNavigation({}).action, ng.RISK_OK);
  assert.equal(ng.analyzeHostname('').risk, ng.RISK_OK);
});
