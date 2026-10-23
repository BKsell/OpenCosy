'use strict';

// webglfpguard.test.js —— 调试扩展拦截、renderer 泛化、能力参数分桶、扩展列表过滤、频控。

const test = require('node:test');
const assert = require('node:assert/strict');
const wg = require('./webglfpguard');
const { WebglFpGuard, WG_REASON, quantizePow2, defaultWebglFpPolicy } = wg;

const UNMASKED_VENDOR = 37445;
const UNMASKED_RENDERER = 37446;
const MAX_TEX = 34921;

function ctx(over) {
  return Object.assign({ origin: 'https://game.example.com', blocked: false, now: 0 }, over || {});
}

test('能力值量化到 2 的幂', () => {
  assert.equal(quantizePow2(33), 32);
  assert.equal(quantizePow2(16), 16);
  assert.equal(quantizePow2(17), 16);
});

test('renderer/vendor 参数返回泛化串', () => {
  const g = new WebglFpGuard();
  const v = g.decideGetParameter(ctx(), UNMASKED_VENDOR);
  assert.equal(v.decision, 'spoof');
  assert.equal(v.value, 'WebKit');
  const r = g.decideGetParameter(ctx({ now: 200 }), UNMASKED_RENDERER);
  assert.equal(r.value, 'WebKit WebGL');
});

test('身份参数频控拒绝', () => {
  const g = new WebglFpGuard();
  assert.equal(g.decideGetParameter(ctx({ now: 0 }), UNMASKED_VENDOR).decision, 'spoof');
  assert.equal(g.decideGetParameter(ctx({ now: 50 }), UNMASKED_VENDOR).reason, WG_REASON.READ_THROTTLED);
});

test('能力参数被量化标记', () => {
  const g = new WebglFpGuard();
  const r = g.decideGetParameter(ctx({ now: 0 }), MAX_TEX);
  assert.equal(r.decision, 'spoof');
  assert.equal(g.applyParameter(MAX_TEX, 33), 32);
});

test('普通参数放行', () => {
  const g = new WebglFpGuard();
  assert.equal(g.decideGetParameter(ctx({ now: 0 }), 0x1f00).decision, 'allow'); // VENDOR 普通字符串不在名单
});

test('敏感扩展拒绝', () => {
  const g = new WebglFpGuard();
  assert.equal(g.decideExtension('WEBGL_debug_renderer_info').allowed, false);
  assert.equal(g.decideExtension('WEBGL_debug_shaders').allowed, false);
  assert.equal(g.decideExtension('OES_texture_float').allowed, true);
});

test('扩展列表过滤', () => {
  const g = new WebglFpGuard();
  const { kept, removed } = g.filterExtensionList(['OES_texture_float', 'WEBGL_debug_renderer_info', 'ANGLE_instanced_arrays']);
  assert.ok(kept.indexOf('WEBGL_debug_renderer_info') < 0);
  assert.ok(removed.indexOf('WEBGL_debug_renderer_info') >= 0);
  assert.equal(kept.length, 2);
});

test('上下文数量上限', () => {
  const g = new WebglFpGuard();
  let last = true;
  for (let i = 0; i < 10; i++) last = g.noteContextCreated('https://game.example.com');
  assert.equal(last, false);
});

test('坏 origin 拒绝', () => {
  const g = new WebglFpGuard();
  assert.equal(g.decideGetParameter({ origin: 'garbage' }, MAX_TEX).reason, WG_REASON.BAD_ORIGIN);
});

test('关闭泛化后放行 renderer 真值', () => {
  const pol = defaultWebglFpPolicy();
  pol.redactRendererInfo = false;
  const g = new WebglFpGuard(pol);
  assert.equal(g.decideGetParameter(ctx({ now: 0 }), UNMASKED_VENDOR).decision, 'allow');
});
