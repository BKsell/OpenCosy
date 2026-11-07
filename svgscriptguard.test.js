'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./svgscriptguard');

const SAFE = '<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10"/></svg>';

test('普通图形 SVG 通过', () => {
  const r = guard.applySvgScriptGuard(SAFE);
  assert.strictEqual(r.changed, false);
  assert.deepStrictEqual(r.matches, []);
});

test('script 标签被拒', () => {
  const r = guard.inspectSvg('<svg><script>alert(1)</script></svg>');
  assert.strictEqual(r.reason, guard.REASON.SCRIPT_TAG);
});

test('事件处理属性被拒', () => {
  const r = guard.inspectSvg('<svg onload="alert(1)"></svg>');
  assert.strictEqual(r.reason, guard.REASON.EVENT_HANDLER);
});

test('foreignObject 被拒', () => {
  const r = guard.inspectSvg('<svg><foreignObject><body/></foreignObject></svg>');
  assert.strictEqual(r.reason, guard.REASON.FOREIGN_OBJECT);
});

test('javascript URI 被拒', () => {
  const r = guard.inspectSvg('<svg><a xlink:href="javascript:alert(1)">x</a></svg>');
  assert.strictEqual(r.reason, guard.REASON.JAVASCRIPT_URI);
});

test('data:text/html URI 被拒', () => {
  const r = guard.inspectSvg('<svg><image href="data:text/html,<b>x</b>"/></svg>');
  assert.strictEqual(r.reason, guard.REASON.JAVASCRIPT_URI);
});

test('iframe 被拒', () => {
  const r = guard.inspectSvg('<svg><iframe src="https://evil.example.com"/></svg>');
  assert.strictEqual(r.reason, guard.REASON.IFRAME_EMBED);
});

test('实体声明被拒', () => {
  const r = guard.inspectSvg('<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg/>');
  assert.strictEqual(r.reason, guard.REASON.ENTITY_DECL);
});

test('外部 DTD 被拒', () => {
  const r = guard.inspectSvg('<!DOCTYPE svg SYSTEM "http://evil.example.com/a.dtd"><svg/>');
  assert.strictEqual(r.reason, guard.REASON.EXTERNAL_DTD);
});

test('空内容被拒', () => {
  const r = guard.inspectSvg('   ');
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
});

test('非文本被拒', () => {
  const r = guard.inspectSvg(null);
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
});

test('超体积被拒', () => {
  const r = guard.inspectSvg('<svg>' + 'a'.repeat(guard.MAX_BYTES + 1) + '</svg>');
  assert.strictEqual(r.reason, guard.REASON.TOO_LARGE);
});

test('描述文本覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
