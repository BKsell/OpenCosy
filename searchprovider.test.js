'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const sp = require('./searchprovider');

test('内置 provider 覆盖四种搜索引擎且模板合法', () => {
  const ids = sp.BUILTIN_PROVIDERS.map(p => p.id);
  assert.deepEqual(ids, ['bing', 'baidu', 'google', 'ddg']);
  for (const p of sp.BUILTIN_PROVIDERS) {
    const v = sp.validateTemplate(p.search, sp.allowedProviderHosts);
    assert.ok(v.ok, `${p.id} search 模板非法: ${v.reason}`);
    if (p.suggest) {
      const vs = sp.validateTemplate(p.suggest, sp.allowedProviderHosts);
      assert.ok(vs.ok, `${p.id} suggest 模板非法: ${vs.reason}`);
    }
  }
});

test('默认 provider 是 bing 且未知 id 回落默认', () => {
  assert.equal(sp.DEFAULT_PROVIDER_ID, 'bing');
  assert.equal(sp.sanitizeProviderChoice('evil'), 'bing');
  assert.equal(sp.sanitizeProviderChoice(''), 'bing');
  assert.equal(sp.sanitizeProviderChoice(null), 'bing');
  assert.equal(sp.sanitizeProviderChoice('baidu'), 'baidu');
});

test('validateTemplate 拒绝非 HTTPS / 白名单外 host / 无占位 / 多占位 / 控制字符', () => {
  const allow = ['www.example.com'];
  assert.equal(sp.validateTemplate('http://www.example.com/search?q={q}', allow).ok, false);
  assert.equal(sp.validateTemplate('https://evil.com/search?q={q}', allow).ok, false);
  assert.equal(sp.validateTemplate('https://www.example.com/search', allow).ok, false);
  assert.equal(sp.validateTemplate('https://www.example.com/search?q={q}&x={x}', allow).ok, false);
  assert.equal(sp.validateTemplate('https://www.example.com/search?q={q}{q}', allow).ok, false);
  assert.equal(sp.validateTemplate('https://www.example.com/search?q={q}\u0000', allow).ok, false);
  assert.equal(sp.validateTemplate('https://www.example.com/search?q={q}', allow).ok, true);
});

test('hostAllowed 精确与子域匹配，拒绝前缀伪装', () => {
  assert.ok(sp.hostAllowed('www.example.com', ['example.com']));
  assert.ok(sp.hostAllowed('a.example.com', ['example.com']));
  assert.ok(!sp.hostAllowed('evilexample.com', ['example.com']));
  assert.ok(!sp.hostAllowed('example.com.evil.org', ['example.com']));
  assert.ok(!sp.hostAllowed('', ['example.com']));
});

test('buildSearchUrl 正常拼接并 URL 编码查询词', () => {
  const u = sp.buildSearchUrl('bing', 'hello world & co');
  assert.ok(u);
  assert.ok(u.startsWith('https://www.bing.com/search?q='));
  assert.ok(u.includes('hello%20world%20%26%20co'));
});

test('buildSearchUrl 未知 provider / 空查询 / 超长 / 控制字符返回 null', () => {
  assert.equal(sp.buildSearchUrl('nope', 'x'), null);
  assert.equal(sp.buildSearchUrl('bing', ''), null);
  assert.equal(sp.buildSearchUrl('bing', '   '), null);
  assert.equal(sp.buildSearchUrl('bing', 'x'.repeat(3000)), null);
  assert.equal(sp.buildSearchUrl('bing', 'a\u0001b'), null);
});

test('buildSuggestUrl 各 provider 有效且含编码词', () => {
  for (const p of sp.BUILTIN_PROVIDERS) {
    const u = sp.buildSuggestUrl(p.id, 'minecraft 启动');
    if (p.suggest) {
      assert.ok(u, `${p.id} suggest URL 应生成`);
      assert.ok(u.includes(encodeURIComponent('minecraft 启动')));
    }
  }
});

test('sanitizeQuery 修剪空白并限长', () => {
  const s = sp.sanitizeQuery('  hi  ', 10);
  assert.ok(s.ok);
  assert.equal(s.q, 'hi');
  assert.equal(sp.sanitizeQuery('x'.repeat(11), 10).ok, false);
  assert.equal(sp.sanitizeQuery('a\nb', 10).ok, false);
});

test('providerSummary 返回只读视图不含模板', () => {
  const list = sp.providerSummary();
  assert.equal(list.length, 4);
  for (const item of list) {
    assert.ok('id' in item && 'name' in item && 'home' in item);
    assert.ok(!('search' in item));
  }
});

test('providerById 深拷贝不受外部篡改影响', () => {
  const p = sp.providerById('bing');
  p.search = 'https://evil.com/?q={q}';
  const again = sp.providerById('bing');
  assert.equal(again.search, 'https://www.bing.com/search?q={q}');
});

test('模板 host 提取支持端口与路径边界', () => {
  const v = sp.validateTemplate('https://www.example.com:8443/search?q={q}', ['www.example.com']);
  assert.ok(v.ok);
  assert.equal(v.host, 'www.example.com');
});
