'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = __dirname;

function stubDeps(channels) {
  return {
    ipcMain: { handle: (name) => { channels.push(name); } },
    isMainSender: () => true,
  };
}

test('站点数据 IPC 注册不再因依赖未定义抛错', () => {
  const wire = require('./cosyipcwire');
  const channels = [];
  wire.bindDeps(stubDeps(channels));
  assert.doesNotThrow(() => wire.registerSiteDataIpc());
  assert.ok(channels.includes('list-site-data'));
});

test('封禁规则与搜索建议注册到同一条线束', () => {
  const wire = require('./cosyipcwire');
  const channels = [];
  wire.bindDeps(stubDeps(channels));
  wire.registerBlockRulesIpc();
  wire.registerSearchSuggestIpc();
  assert.ok(channels.includes('get-block-rules'));
  assert.ok(channels.includes('add-block-rule'));
  assert.ok(channels.includes('get-search-suggestions'));
});

test('证书错误处理器挂在同一条线束上', () => {
  const wire = require('./cosyipcwire');
  assert.strictEqual(typeof wire.installCertificateErrorHandler, 'function');
});

test('独立的分片线束模块已不存在', () => {
  for (const name of ['cosyipcwire3.js', 'cosyipcwire4.js']) {
    assert.strictEqual(fs.existsSync(path.join(ROOT, name)), false, name + ' 应已并入 cosyipcwire.js');
  }
});
