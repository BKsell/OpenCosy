'use strict';

const test = require('node:test');
const assert = require('node:assert');

const delegates = require('./cosymaindelegates');

const SOURCES = [
  require('./cosyguardmain'),
  require('./cosyledgerchainmain'),
  require('./cosysettingsmain'),
  require('./cosytabsmain'),
  require('./cosywinmain'),
];

test('委托层导出的每个名字都能在唯一来源模块找到实现', () => {
  const names = Object.keys(delegates);
  assert.ok(names.length >= 165, `委托数量异常：${names.length}`);
  for (const name of names) {
    assert.strictEqual(typeof delegates[name], 'function', `${name} 不是函数`);
    const hits = SOURCES.filter((mod) => typeof mod[name] === 'function');
    assert.strictEqual(hits.length, 1, `${name} 的来源模块数量为 ${hits.length}`);
  }
});

test('委托层把参数与返回值原样透传给来源模块', () => {
  let seen = null;
  const name = 'originOf';
  assert.strictEqual(typeof delegates[name], 'function');
  const raw = SOURCES.find((mod) => typeof mod[name] === 'function');
  const stub = (...a) => {
    seen = a;
    return 'sentinel';
  };
  const had = Object.prototype.hasOwnProperty.call(raw, name);
  const backup = raw[name];
  try {
    raw[name] = stub;
    assert.strictEqual(delegates[name]('x', 2), 'sentinel');
    assert.deepStrictEqual(seen, ['x', 2]);
  } finally {
    if (had) raw[name] = backup; else delete raw[name];
  }
});
