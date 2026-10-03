'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const g = require('./frameguard');

test('classifyFrame 区分主子框架', () => {
  assert.equal(g.classifyFrame({ url: 'https://a.com', parent: null }), g.FRAME_MAIN);
  assert.equal(g.classifyFrame({ url: 'https://a.com' }), g.FRAME_MAIN);
  assert.equal(g.classifyFrame({ url: 'https://a.com', parent: {} }), g.FRAME_CHILD);
  assert.equal(g.classifyFrame(null), 'unknown');
  assert.equal(g.classifyFrame('x'), 'unknown');
});

test('主框架恒放行且不参与洪泛', () => {
  const st = g.createFrameState(0);
  for (let i = 0; i < 10000; i++) {
    const v = g.evaluateFrame({ url: 'https://a.com', parent: null }, st, i);
    assert.equal(v.action, g.FRAME_PASS);
  }
  assert.equal(st.child, 0);
  assert.equal(st.main, 10000);
});

test('正常 https 子框架放行', () => {
  const st = g.createFrameState(0);
  const v = g.evaluateFrame({ url: 'https://cdn.a.com/widget', parent: {} }, st, 0);
  assert.equal(v.action, g.FRAME_PASS);
  assert.equal(v.kind, g.FRAME_CHILD);
  assert.equal(v.origin, 'https://cdn.a.com');
});

test('危险协议子框架被丢', () => {
  const st = g.createFrameState(0);
  const urls = ['javascript:alert(1)', 'file:///etc/passwd', 'chrome://settings', 'vbscript:x'];
  for (const url of urls) {
    const v = g.evaluateFrame({ url, parent: {} }, st, 0);
    assert.equal(v.action, g.FRAME_DROP, url);
    assert.ok(v.reasons.some(r => r.startsWith('dangerous-scheme')), url);
  }
});

test('超长 / 控制字符 URL 子框架被丢', () => {
  const st = g.createFrameState(0);
  const longUrl = 'https://a.com/?' + 'x'.repeat(g.FRAME_MAX_URL_CHARS);
  const v1 = g.evaluateFrame({ url: longUrl, parent: {} }, st, 0);
  assert.ok(v1.reasons.includes('frame-url-too-long'));
  const v2 = g.evaluateFrame({ url: 'https://a.com/\u2028', parent: {} }, st, 0);
  assert.ok(v2.reasons.includes('frame-url-control-char'));
});

test('畸形 frame 对象被丢', () => {
  const st = g.createFrameState(0);
  const v = g.evaluateFrame(undefined, st, 0);
  assert.equal(v.action, g.FRAME_DROP);
  assert.ok(v.reasons.includes('malformed-frame'));
});

test('短窗框架爆炸触发冷却', () => {
  const st = g.createFrameState(0);
  let flooded = false;
  for (let i = 0; i < g.FRAME_BURST_MAX + 1; i++) {
    const v = g.evaluateFrame({ url: 'https://a.com/f' + i, parent: {} }, st, 0);
    if (v.reasons.includes('frame-flood')) flooded = true;
  }
  assert.equal(flooded, true);
  // 冷却期内继续丢。
  const during = g.evaluateFrame({ url: 'https://a.com/x', parent: {} }, st, 1000);
  assert.ok(during.reasons.includes('frame-flood'));
  // 冷却结束恢复。
  const after = g.evaluateFrame(
    { url: 'https://a.com/x', parent: {} }, st, g.FRAME_COOLDOWN_MS + 1);
  assert.equal(after.action, g.FRAME_PASS);
});

test('长窗慢速累积触发冷却', () => {
  const st = g.createFrameState(0);
  const step = 50; // 50ms 一个：短窗 5s 内约 100 个（<120 不触发），长窗 30s 内可超 400
  let flooded = false;
  for (let i = 0; i < g.FRAME_LONG_MAX + 1; i++) {
    const v = g.evaluateFrame({ url: 'https://a.com/f', parent: {} }, st, i * step);
    if (v.reasons.includes('frame-flood')) flooded = true;
  }
  assert.equal(flooded, true);
});

test('resetForNavigation 清零', () => {
  const st = g.createFrameState(0);
  for (let i = 0; i < 50; i++) {
    g.evaluateFrame({ url: 'https://a.com', parent: {} }, st, 0);
  }
  assert.equal(st.child, 50);
  g.resetForNavigation(st, 100);
  assert.equal(st.child, 0);
  assert.equal(st.dropped, 0);
  assert.equal(st.cooldownUntil, 0);
});

test('containsControlChar 覆盖 C0/DEL/行分隔/BOM', () => {
  assert.equal(g.containsControlChar('a\x00b'), true);
  assert.equal(g.containsControlChar('a\x7fb'), true);
  assert.equal(g.containsControlChar('a\u2028b'), true);
  assert.equal(g.containsControlChar('a\u2029b'), true);
  assert.equal(g.containsControlChar('plain'), false);
  assert.equal(g.containsControlChar(123), false);
});
