'use strict';

const test = require('node:test');
const assert = require('node:assert');
const H = require('./httpsonly');

test('isHttpString 只接受 http:// 字面量', () => {
  assert.strictEqual(H.isHttpString('http://a.com'), true);
  assert.strictEqual(H.isHttpString('http://'), true);
  assert.strictEqual(H.isHttpString('https://a.com'), false);
  assert.strictEqual(H.isHttpString('HTTP://a.com'), false); // 大小写敏感，调用方应先归一
  assert.strictEqual(H.isHttpString(''), false);
  assert.strictEqual(H.isHttpString(null), false);
  assert.strictEqual(H.isHttpString(42), false);
});

test('hostLooksPrivate 命中回环 / 本地惯例域名', () => {
  for (const h of ['localhost', 'LOCALHOST', 'localhost.localdomain',
    '127.0.0.1', '127.9.9.9', '0.0.0.0', '[::1]', '::1',
    'foo.localhost', 'printer.local', 'svc.internal', 'router.lan']) {
    assert.strictEqual(H.hostLooksPrivate(h), true, h);
  }
  for (const h of ['example.com', '192.168.1.1', '10.0.0.1', '169.254.1.1', '', null]) {
    // 注：字面量内核不负责私网段（10/192.168/169.254 由 hostmatch 注入判定）。
    assert.strictEqual(H.hostLooksPrivate(h), false, String(h));
  }
});

test('normalizeExceptionHost 收敛主机名并拒绝危险 / 畸形输入', () => {
  assert.strictEqual(H.normalizeExceptionHost('Example.COM'), 'example.com');
  assert.strictEqual(H.normalizeExceptionHost('  example.com  '), 'example.com');
  assert.strictEqual(H.normalizeExceptionHost('http://Example.COM/x?y=1'), 'example.com');
  assert.strictEqual(H.normalizeExceptionHost('https://[2001:db8::1]/'), '2001:db8::1');
  for (const bad of ['', '   ', 'a/b', 'a\\b', 'a@b', 'a:8080', 'a?x', 'a#h',
    'a b.com', 'a\tb', 123, null, {}, 'http://', '://x']) {
    assert.strictEqual(H.normalizeExceptionHost(bad), '', JSON.stringify(bad));
  }
  const long = 'a'.repeat(H.MAX_HOST_BYTES + 1) + '.com';
  assert.strictEqual(H.normalizeExceptionHost(long), '');
  const atLimit = 'a'.repeat(H.MAX_HOST_BYTES);
  assert.strictEqual(H.normalizeExceptionHost(atLimit), atLimit);
});

test('upgradeHttpUrl 升级默认端口并保留路径 / 查询 / 哈希', () => {
  const r = H.upgradeHttpUrl('http://example.com/a/b?x=1&y=2#frag');
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.reason, H.REASON_UPGRADED);
  assert.strictEqual(r.host, 'example.com');
  assert.strictEqual(r.url, 'https://example.com/a/b?x=1&y=2#frag');
});

test('upgradeHttpUrl 显式 80 端口收敛到 https 默认 443', () => {
  const r = H.upgradeHttpUrl('http://example.com:80/');
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.url, 'https://example.com/');
});

test('upgradeHttpUrl 非标准端口不自动升级', () => {
  const r = H.upgradeHttpUrl('http://example.com:8080/app');
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.reason, H.REASON_NONSTANDARD_PORT);
  assert.strictEqual(r.host, 'example.com');
});

test('upgradeHttpUrl 私网 / 回环主机保留 http', () => {
  assert.strictEqual(H.upgradeHttpUrl('http://127.0.0.1:3000/').reason, H.REASON_PRIVATE_HOST);
  assert.strictEqual(H.upgradeHttpUrl('http://localhost/').reason, H.REASON_PRIVATE_HOST);
  assert.strictEqual(H.upgradeHttpUrl('http://router.lan/').reason, H.REASON_PRIVATE_HOST);
  // 注入 hostmatch 的私网判定后，内网名也保留 http。
  const injected = H.upgradeHttpUrl('http://intranet.corp/', (host) => host === 'intranet.corp');
  assert.strictEqual(injected.reason, H.REASON_PRIVATE_HOST);
  // 注入回调抛错时退回字面量判定，不影响公网升级。
  const pub = H.upgradeHttpUrl('http://example.com/', () => { throw new Error('x'); });
  assert.strictEqual(pub.ok, true);
});

test('upgradeHttpUrl 保留 userinfo 且把主机名归一为小写', () => {
  const r = H.upgradeHttpUrl('http://user:p%40ss@EXAMPLE.com/');
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.url, 'https://user:p%40ss@example.com/');
});

test('upgradeHttpUrl 拒绝非 http / 空主机 / 畸形 URL', () => {
  assert.strictEqual(H.upgradeHttpUrl('https://example.com/').ok, false);
  assert.strictEqual(H.upgradeHttpUrl('ftp://example.com/').reason, H.REASON_NOT_HTTP);
  // Node 的 URL 解析器下，缺失主机名的 http URL（http://、http://?x…）一律直接
  // 抛 Invalid URL，因此这里只断言 invalid；内核里的 empty-host 分支为防御性保留。
  assert.strictEqual(H.upgradeHttpUrl('http://').reason, H.REASON_INVALID);
  assert.strictEqual(H.upgradeHttpUrl('http://?x').reason, H.REASON_INVALID);
  assert.strictEqual(H.upgradeHttpUrl('http://exa mple.com/').reason, H.REASON_INVALID);
});

test('downgradeHttpsUrlForFallback 只还原默认端口形态', () => {
  assert.strictEqual(H.downgradeHttpsUrlForFallback('https://example.com/a?b=1'),
    'http://example.com/a?b=1');
  assert.strictEqual(H.downgradeHttpsUrlForFallback('https://example.com:443/'),
    'http://example.com/');
  assert.strictEqual(H.downgradeHttpsUrlForFallback('https://example.com:8443/'), '');
  assert.strictEqual(H.downgradeHttpsUrlForFallback('http://example.com/'), '');
  assert.strictEqual(H.downgradeHttpsUrlForFallback('not a url'), '');
});

test('isFallbackableUpgradeError 只接受无-TLS-能力强信号码', () => {
  for (const code of [-102, -107, -112, -156]) {
    assert.strictEqual(H.isFallbackableUpgradeError(code), true, String(code));
  }
  for (const code of [-105, -118, -109, -200, -202, 0, 200, '-102', 1.5, null, undefined]) {
    assert.strictEqual(H.isFallbackableUpgradeError(code), false, String(code));
  }
});

test('HttpExceptionStore 增删查清空与主机名规范化', () => {
  const s = new H.HttpExceptionStore();
  assert.strictEqual(s.size(), 0);
  assert.strictEqual(s.add('Example.COM'), 'example.com');
  assert.strictEqual(s.has('example.com'), true);
  assert.strictEqual(s.has('other.com'), false);
  assert.strictEqual(s.add('bad/host'), '');
  assert.strictEqual(s.size(), 1);
  assert.strictEqual(s.remove('EXAMPLE.com'), true);
  assert.strictEqual(s.remove('example.com'), false);
  s.add('a.com');
  s.add('b.com');
  s.clear();
  assert.strictEqual(s.size(), 0);
});

test('HttpExceptionStore 超容量淘汰最老，重复加入刷新', () => {
  const s = new H.HttpExceptionStore(2);
  s.add('old.com', 1000);
  s.add('mid.com', 2000);
  s.add('new.com', 3000); // old.com 被淘汰
  assert.strictEqual(s.has('old.com'), false);
  assert.strictEqual(s.has('mid.com'), true);
  assert.strictEqual(s.has('new.com'), true);
  // 重复加入：删后重插，成为最新，再次超容量时 mid.com 先被淘汰。
  s.add('mid.com', 4000);
  s.add('fresh.com', 5000);
  assert.strictEqual(s.has('new.com'), false);
  assert.strictEqual(s.has('mid.com'), true);
  assert.strictEqual(s.has('fresh.com'), true);
});

test('HttpExceptionStore toJSON / load 往返并丢弃脏数据', () => {
  const s = new H.HttpExceptionStore();
  s.add('a.com', 111);
  s.add('b.com', 222);
  const json = s.toJSON();
  assert.strictEqual(json.version, 1);
  assert.strictEqual(json.hosts.length, 2);

  const s2 = new H.HttpExceptionStore();
  const loaded = s2.load({
    version: 1,
    hosts: [
      { host: 'A.com', addedAt: 1 },
      { host: 'bad/host' },            // 非法，丢弃
      { addedAt: 2 },                  // 缺 host，丢弃
      null,
      { host: 'c.com', addedAt: 'xx' }, // 时间戳非法归一为 0，仍保留
    ],
  });
  assert.strictEqual(loaded, 2);
  assert.strictEqual(s2.has('a.com'), true);
  assert.strictEqual(s2.has('c.com'), true);

  const reloaded = s2.load(json); // load 先清空再重建，返回条目数
  assert.strictEqual(reloaded, 2);
  assert.strictEqual(s2.has('c.com'), false);
  assert.strictEqual(s2.has('a.com'), true);
  assert.strictEqual(s2.has('b.com'), true);
});

test('HttpExceptionStore load 超容量按序保留最新', () => {
  const s = new H.HttpExceptionStore(2);
  s.load({ hosts: [{ host: 'x1.com' }, { host: 'x2.com' }, { host: 'x3.com' }] });
  assert.strictEqual(s.size(), 2);
  assert.strictEqual(s.has('x1.com'), false);
  assert.strictEqual(s.has('x2.com'), true);
  assert.strictEqual(s.has('x3.com'), true);
});

test('HttpExceptionStore 非法容量回退默认值', () => {
  const s = new H.HttpExceptionStore(0);
  assert.strictEqual(s.capacity, H.DEFAULT_EXCEPTION_CAPACITY);
  s.add('a.com');
  assert.strictEqual(s.has('a.com'), true);
});
