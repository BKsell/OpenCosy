'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const sg = require('./schemeorigin');

test('originSpace 正确归类', () => {
  assert.equal(sg.originSpace('https://example.com/'), 'web');
  assert.equal(sg.originSpace('http://example.com:8080/x'), 'web');
  assert.equal(sg.originSpace('file:///C:/Windows/a.txt'), 'file');
  assert.equal(sg.originSpace('cosy://security'), 'internal');
  assert.equal(sg.originSpace('blob:https://example.com/uuid'), 'blob');
  assert.equal(sg.originSpace('data:text/html,<h1>x</h1>'), 'data');
  assert.equal(sg.originSpace('about:blank'), 'about');
  assert.equal(sg.originSpace('mailto:a@b.com'), 'other');
  assert.equal(sg.originSpace('not a url'), 'other');
  assert.equal(sg.originSpace(''), 'other');
});

test('blob/fiesystem 内嵌来源被解析', () => {
  assert.equal(sg.effectiveInitiatorSpace('blob:https://example.com/u'), 'web');
  assert.equal(sg.effectiveInitiatorSpace('blob:file:///tmp/x'), 'file');
  assert.equal(sg.effectiveInitiatorSpace('blob:cosy://security/x'), 'internal');
  // 解析不出内嵌来源时按不可信 web 处理。
  assert.equal(sg.effectiveInitiatorSpace('blob:???'), 'web');
});

test('网页禁止顶窗跳到本地 file://', () => {
  const target = 'file:///C:/Windows/System32/';
  const r = sg.evaluate(target, 'https://evil.example/');
  assert.equal(r.action, 'block');
  assert.equal(r.reason, 'untrusted-to-file');
  // 说明文案是固定枚举，不得回显具体路径。
  assert.equal(sg.describeBlock(r.reason).includes(target), false);
  assert.equal(sg.describeBlock(r.reason).includes('System32'), false);
});

test('http 与 https 网页互相导航到 file 都拦', () => {
  for (const from of ['http://a.com/', 'https://a.com/', 'blob:https://a.com/x', 'data:text/html,x']) {
    const r = sg.evaluate('file:///C:/x', from);
    assert.equal(r.action, 'block', `来源 ${from} 不应能跳到 file:`);
  }
});

test('file 页 / 内部页 / 浏览器自身可以到 file:', () => {
  assert.equal(sg.evaluate('file:///C:/b', 'file:///C:/a').action, 'allow');
  assert.equal(sg.evaluate('file:///C:/b', 'cosy://security').action, 'allow');
  assert.equal(sg.evaluate('file:///C:/b', '').action, 'allow');
  assert.equal(sg.evaluate('file:///C:/b', 'about:blank').action, 'allow');
});

test('网页禁止顶窗跳到内部 cosy: 特权页', () => {
  const r = sg.evaluate('cosy://security', 'https://evil.example/');
  assert.equal(r.action, 'block');
  assert.equal(r.reason, 'untrusted-to-internal');

  assert.equal(sg.evaluate('cosy://settings', 'http://a.com/').action, 'block');
  assert.equal(sg.evaluate('cosy://security', 'data:text/html,x').action, 'block');
  assert.equal(sg.evaluate('cosy://security', 'blob:https://a.com/u').action, 'block');
  assert.equal(sg.evaluate('cosy://security', 'file:///C:/a').action, 'block');
});

test('内部页之间与浏览器自身可以进入 cosy:', () => {
  assert.equal(sg.evaluate('cosy://settings', 'cosy://security').action, 'allow');
  assert.equal(sg.evaluate('cosy://security', '').action, 'allow');
  assert.equal(sg.evaluate('cosy://security', 'about:blank').action, 'allow');
});

test('普通 web 导航照常放行，交给既有链路', () => {
  assert.equal(sg.evaluate('https://b.com/', 'https://a.com/').action, 'allow');
  assert.equal(sg.evaluate('https://b.com/', 'file:///C:/a').action, 'allow');
  assert.equal(sg.evaluate('mailto:a@b.com', 'https://a.com/').action, 'allow');
});
