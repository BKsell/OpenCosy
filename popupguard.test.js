'use strict';

// popupguard.test.js —— 弹窗安全内核：危险协议拦截、特性串解析、跨源 noopener、
// 反向 tabnabbing 评估、小窗伪装识别。

const test = require('node:test');
const assert = require('node:assert/strict');
const pg = require('./popupguard');

test('javascript:/data:/vbscript:/file: 弹窗一律拦截', () => {
  for (const u of [
    'javascript:alert(1)',
    '  javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'vbscript:msgbox',
    'file:///C:/Windows/win.ini',
  ]) {
    assert.equal(pg.isDangerousPopupUrl(u), true, `应判危险: ${u}`);
    const d = pg.decidePopup({ currentUrl: 'https://a.com/', targetUrl: u });
    assert.equal(d.action, 'block', `应 block: ${u}`);
  }
});

test('普通 http(s) 弹窗不被拦截', () => {
  const d = pg.decidePopup({ currentUrl: 'https://a.com/', targetUrl: 'https://a.com/x' });
  assert.notEqual(d.action, 'block');
});

test('about:blank 弹窗不被误杀（OAuth/支付常用）', () => {
  const d = pg.decidePopup({ currentUrl: 'https://a.com/', targetUrl: 'about:blank' });
  assert.notEqual(d.action, 'block');
});

test('外部协议由确认流负责，不被本内核拦截', () => {
  const d = pg.decidePopup({ currentUrl: 'https://a.com/', targetUrl: 'mailto:x@y.com', isExternal: true });
  assert.notEqual(d.action, 'block');
  assert.ok(d.reasons.includes('external-scheme'));
});

test('特性串解析：布尔特性与键值', () => {
  const f = pg.normalizeFeatures('noopener=yes,width=400,height=300,popup');
  assert.equal(f.noopener, true);
  assert.equal(f.popup, true);
  assert.equal(f.width, '400');
  assert.equal(f.height, '300');
});

test('noopener=no 显式关闭时布尔特性为 false', () => {
  const f = pg.normalizeFeatures('noopener=0');
  assert.equal(f.noopener, false);
});

test('空/非字符串特性串返回空 map', () => {
  assert.equal(Object.keys(pg.normalizeFeatures('')).length, 0);
  assert.equal(Object.keys(pg.normalizeFeatures(null)).length, 0);
});

test('跨源弹窗默认 noopener', () => {
  const d = pg.decidePopup({ currentUrl: 'https://a.com/', targetUrl: 'https://b.com/' });
  assert.equal(d.noopener, true);
  assert.ok(d.reasons.includes('cross-origin-noopener'));
});

test('同源弹窗不强制 noopener，但页面显式要求时生效', () => {
  const same = pg.decidePopup({ currentUrl: 'https://a.com/', targetUrl: 'https://a.com/p' });
  assert.equal(same.noopener, false);
  const forced = pg.decidePopup({
    currentUrl: 'https://a.com/', targetUrl: 'https://a.com/p', features: 'noopener',
  });
  assert.equal(forced.noopener, true);
});

test('noreferrer 特性也触发 noopener 隔离', () => {
  const d = pg.decidePopup({
    currentUrl: 'https://a.com/', targetUrl: 'https://a.com/p', features: 'noreferrer',
  });
  assert.equal(d.noopener, true);
});

test('background-tab disposition 映射为后台打开', () => {
  const d = pg.decidePopup({
    currentUrl: 'https://a.com/', targetUrl: 'https://b.com/', disposition: 'background-tab',
  });
  assert.equal(d.action, 'open-background');
});

test('反向 tabnabbing：跨源 _blank 缺 noopener 时要求补全', () => {
  const r = pg.evaluateRel('https://a.com/', 'https://b.com/', '');
  assert.equal(r.crossOrigin, true);
  assert.equal(r.needsNoopener, true);
  assert.match(r.recommendedRel, /noopener/);
});

test('已有 noopener/noreferrer 的跨源链接不再要求补', () => {
  assert.equal(pg.evaluateRel('https://a.com/', 'https://b.com/', 'noopener').needsNoopener, false);
  assert.equal(pg.evaluateRel('https://a.com/', 'https://b.com/', 'noreferrer').needsNoopener, false);
});

test('同源 _blank 不需要 noopener', () => {
  const r = pg.evaluateRel('https://a.com/', 'https://a.com/page', '');
  assert.equal(r.crossOrigin, false);
  assert.equal(r.needsNoopener, false);
});

test('超小尺寸小窗被标记（不阻断，仅留痕）', () => {
  assert.equal(pg.isSmallWindowFeatures('width=200,height=150'), true);
  assert.equal(pg.isSmallWindowFeatures('width=800,height=600'), false);
  const d = pg.decidePopup({
    currentUrl: 'https://a.com/', targetUrl: 'https://a.com/', features: 'width=200,height=150',
  });
  assert.ok(d.reasons.includes('small-window-features-ignored'));
  assert.notEqual(d.action, 'block');
});

test('schemeOf 大小写与空白归一', () => {
  assert.equal(pg.schemeOf('JAVAscript:alert(1)'), 'javascript:');
  assert.equal(pg.schemeOf('HTTPS://a.com'), 'https:');
  assert.equal(pg.schemeOf('not a url'), '');
});

test('originOfUrl 对危险协议返回空源', () => {
  assert.equal(pg.originOfUrl('data:text/html,x'), '');
  assert.equal(pg.originOfUrl('javascript:1'), '');
  assert.equal(pg.originOfUrl('https://a.com:8443/x'), 'https://a.com:8443');
});

test('isBlockedTopNavUrl 拦截窗内 javascript:/file: 顶层导航', () => {
  assert.equal(pg.isBlockedTopNavUrl('javascript:alert(1)'), true);
  assert.equal(pg.isBlockedTopNavUrl('file:///c:/x'), true);
  assert.equal(pg.isBlockedTopNavUrl('https://a.com'), false);
});
