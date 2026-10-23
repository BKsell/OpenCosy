'use strict';

// fontfpguard.test.js —— 字体名归一、通用字体免预算、非通用字体预算、滑动窗口频控、超长名。

const test = require('node:test');
const assert = require('node:assert/strict');
const ff = require('./fontfpguard');
const { FontFpGuard, FF_REASON, normalizeFontName, isCommonFont, defaultFontFpPolicy } = ff;

function ctx(over) {
  return Object.assign({ origin: 'https://ads.fingerprint.net', blocked: false, now: 0 }, over || {});
}

test('字体名归一：去引号/首族/小写', () => {
  assert.equal(normalizeFontName('"Times New Roman", serif'), 'times new roman');
  assert.equal(normalizeFontName("'Arial'"), 'arial');
  assert.equal(normalizeFontName('  MONOSPACE  '), 'monospace');
});

test('通用字体识别', () => {
  assert.ok(isCommonFont('monospace'));
  assert.ok(isCommonFont('arial'));
  assert.ok(!isCommonFont('某稀有中文字体'));
});

test('通用字体不占预算', () => {
  const g = new FontFpGuard();
  for (let i = 0; i < 100; i++) {
    assert.equal(g.decideMeasure(ctx({ now: i }), 'monospace').decision, 'allow');
  }
  assert.equal(g.distinctCount('https://ads.fingerprint.net'), 0);
});

test('非通用字体受预算限制', () => {
  const pol = defaultFontFpPolicy();
  pol.maxDistinctFontsPerOrigin = 3;
  pol.maxMeasurementsPerWindow = 10000;
  const g = new FontFpGuard(pol);
  assert.equal(g.decideMeasure(ctx({ now: 0 }), 'RareFontA').decision, 'allow');
  assert.equal(g.decideMeasure(ctx({ now: 1 }), 'RareFontB').decision, 'allow');
  assert.equal(g.decideMeasure(ctx({ now: 2 }), 'RareFontC').decision, 'allow');
  assert.equal(g.decideMeasure(ctx({ now: 3 }), 'RareFontD').reason, FF_REASON.BUDGET_EXCEEDED);
  // 已记录的重复测量仍允许（不新增预算）
  assert.equal(g.decideMeasure(ctx({ now: 4 }), 'RareFontA').decision, 'allow');
});

test('滑动窗口测量频控', () => {
  const pol = defaultFontFpPolicy();
  pol.maxDistinctFontsPerOrigin = 10000;
  pol.maxMeasurementsPerWindow = 3;
  pol.windowMs = 5000;
  const g = new FontFpGuard(pol);
  assert.equal(g.decideMeasure(ctx({ now: 0 }), 'A').decision, 'allow');
  assert.equal(g.decideMeasure(ctx({ now: 10 }), 'B').decision, 'allow');
  assert.equal(g.decideMeasure(ctx({ now: 20 }), 'C').decision, 'allow');
  assert.equal(g.decideMeasure(ctx({ now: 30 }), 'D').reason, FF_REASON.WINDOW_THROTTLED);
  // 窗口滑过后恢复
  assert.equal(g.decideMeasure(ctx({ now: 6000 }), 'E').decision, 'allow');
});

test('超长字体名拒绝', () => {
  const g = new FontFpGuard();
  assert.equal(g.decideMeasure(ctx({ now: 0 }), 'x'.repeat(129)).reason, FF_REASON.FONT_NAME_TOO_LONG);
});

test('非字符串拒绝', () => {
  const g = new FontFpGuard();
  assert.equal(g.decideMeasure(ctx({ now: 0 }), 123).reason, FF_REASON.NON_STRING_FONT);
});

test('坏 origin/被拦截拒绝', () => {
  const g = new FontFpGuard();
  assert.equal(g.decideMeasure({ origin: 'bad' }, 'A').reason, FF_REASON.BAD_ORIGIN);
  assert.equal(g.decideMeasure(ctx({ blocked: true }), 'A').reason, FF_REASON.BLOCKED_ORIGIN);
});
