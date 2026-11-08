'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const p = require('./preloadpolicy');

test('parseProtocol 只认真实 scheme，大小写归一', () => {
  assert.equal(p.parseProtocol('https://example.com'), 'https:');
  assert.equal(p.parseProtocol('COSY://newtab'), 'cosy:');
  assert.equal(p.parseProtocol('file:///C:/src/index.html'), 'file:');
  assert.equal(p.parseProtocol('cosy://security'), 'cosy:');
  assert.equal(p.parseProtocol('  http://x  '), 'http:');
  assert.equal(p.parseProtocol('\nhttps://x'), 'https:');
});

test('parseProtocol 拒绝畸形 / 无协议 / 伪造', () => {
  const bad = [
    '', '   ', 'not a url', '1https://x', 'ht tps://x',
    'https//x', '://x', 'java\nscript:x', null, undefined, 42, {},
  ];
  for (const b of bad) {
    assert.equal(p.parseProtocol(b), '', `应拒: ${JSON.stringify(b)}`);
  }
});

test('内部上下文只有 file:/cosy:', () => {
  assert.ok(p.isInternalContext('file:///app/src/index.html'));
  assert.ok(p.isInternalContext('cosy://newtab'));
  assert.ok(p.isInternalContext('cosy://security/cert'));
});

test('远程与不可信文档不是内部上下文', () => {
  const remote = [
    'http://example.com', 'https://example.com/p',
    'data:text/html,<script>', 'blob:https://example.com/uuid',
    'about:blank', 'javascript:alert(1)', 'vbscript:msgbox',
    'filesystem:https://x/t', 'chrome:gpu', '', '   ', null, undefined,
  ];
  for (const r of remote) {
    assert.equal(p.isInternalContext(r), false, `应拒: ${JSON.stringify(r)}`);
  }
});

test('classifyLocation 分类精确', () => {
  assert.equal(p.classifyLocation('file:///a/b.html'), p.ORIGIN_SHELL_FILE);
  assert.equal(p.classifyLocation('cosy://newtab'), p.ORIGIN_INTERNAL_COSY);
  assert.equal(p.classifyLocation('http://a'), p.ORIGIN_WEB);
  assert.equal(p.classifyLocation('https://a'), p.ORIGIN_WEB);
  assert.equal(p.classifyLocation('data:text/html,x'), p.ORIGIN_UNTRUSTED);
  assert.equal(p.classifyLocation('blob:https://a/x'), p.ORIGIN_UNTRUSTED);
  assert.equal(p.classifyLocation('about:blank'), p.ORIGIN_UNTRUSTED);
  assert.equal(p.classifyLocation(''), p.ORIGIN_UNKNOWN);
  assert.equal(p.classifyLocation(null), p.ORIGIN_UNKNOWN);
  assert.equal(p.classifyLocation('garbage'), p.ORIGIN_UNTRUSTED);
});

test('buildExposure 内部给 API，远程一律不给', () => {
  for (const u of ['file:///x/index.html', 'cosy://newtab']) {
    const e = p.buildExposure(u);
    assert.ok(e.exposeAPI, `${u} 应注入 API`);
    assert.ok(e.privileged);
    assert.ok(e.cspReporter, 'CSP 上报始终安装，由主进程判源');
  }
  for (const u of ['https://evil.test', 'http://x', 'data:text/html,x', 'about:blank', '', null]) {
    const e = p.buildExposure(u);
    assert.equal(e.exposeAPI, false, `${JSON.stringify(u)} 不应注入 API`);
    assert.equal(e.privileged, false);
    assert.ok(e.cspReporter);
  }
});

test('selectChannels 内部原样返回，远程清空且无旁路', () => {
  const chs = ['create-tab', 'clear-browsing-data', 'approve-cert-exception'];
  assert.deepEqual(p.selectChannels('cosy://newtab', chs), chs);
  assert.deepEqual(p.selectChannels('file:///x.html', new Set(chs)), chs);
  assert.deepEqual(p.selectChannels('https://evil.test', chs), []);
  assert.deepEqual(p.selectChannels('data:text/html,x', chs), []);
  // 非字符串成员在内部上下文也会被过滤
  assert.deepEqual(p.selectChannels('cosy://x', ['a', 1, null, {}]), ['a']);
  assert.deepEqual(p.selectChannels('https://x', null), []);
});

test('伪造内部协议的大小写/空白花招不成立', () => {
  // 协议解析做 trim 与大小写归一，但不允许内部插空格 / 用相似 scheme 冒充
  assert.equal(p.isInternalContext('  cosy://x'), true, '外围空白可容忍');
  assert.equal(p.isInternalContext('COSY://x'), true);
  assert.equal(p.isInternalContext('co sy://x'), false);
  // 只缺双斜杠不改变协议归属：scheme 仍是 cosy:（Electron 实际只会给规范化的 cosy://）
  assert.equal(p.isInternalContext('cosy:/x'), true);
  assert.equal(p.isInternalContext('cosy.evil://x'), false, '相似后缀 scheme 不算 cosy');
  assert.equal(p.isInternalContext('xcosy://x'), false, '前缀伪装不算 cosy');
  assert.equal(p.isInternalContext('https://cosy://x'), false, '把 cosy 放进路径无效');
});
