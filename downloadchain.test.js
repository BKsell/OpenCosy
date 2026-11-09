'use strict';

const test = require('node:test');
const assert = require('node:assert');
const C = require('./downloadchain');

test('analyzeDownloadChain 放行无链与空链', () => {
  const none = C.analyzeDownloadChain(null);
  assert.strictEqual(none.verdict, C.VERDICT.OK);
  assert.strictEqual(none.reason, C.REASON.NO_CHAIN);
  const empty = C.analyzeDownloadChain([]);
  assert.strictEqual(empty.verdict, C.VERDICT.OK);
});

test('analyzeDownloadChain 放行普通 https 链', () => {
  const r = C.analyzeDownloadChain([
    'https://example.test/a.zip',
    'https://cdn.example.test/a.zip',
    'https://cdn.example.test:443/a.zip?sig=1',
  ]);
  assert.strictEqual(r.verdict, C.VERDICT.OK);
  assert.strictEqual(r.reason, C.REASON.OK);
  assert.strictEqual(r.hops, 3);
  assert.strictEqual(r.finalHost, 'cdn.example.test');
  assert.strictEqual(r.finalScheme, 'https');
});

test('analyzeDownloadChain 拦截 https 到 http 的降级', () => {
  const r = C.analyzeDownloadChain([
    'https://example.test/a.zip',
    'http://example.test/a.zip',
  ]);
  assert.strictEqual(r.verdict, C.VERDICT.BLOCK);
  assert.strictEqual(r.reason, C.REASON.HTTPS_DOWNGRADE);
  assert.strictEqual(r.downgraded, true);
});

test('analyzeDownloadChain 放行纯 http 链与升级链', () => {
  const plain = C.analyzeDownloadChain(['http://example.test/a', 'http://example.test/b']);
  assert.strictEqual(plain.verdict, C.VERDICT.OK);
  const upgrade = C.analyzeDownloadChain(['http://example.test/a', 'https://example.test/a']);
  assert.strictEqual(upgrade.verdict, C.VERDICT.OK);
});

test('analyzeDownloadChain 拦截非法协议与内嵌凭据', () => {
  const file = C.analyzeDownloadChain(['https://example.test/a', 'file:///etc/passwd']);
  assert.strictEqual(file.verdict, C.VERDICT.BLOCK);
  assert.strictEqual(file.reason, C.REASON.BAD_SCHEME);
  const cred = C.analyzeDownloadChain(['https://user:pass@example.test/a.zip']);
  assert.strictEqual(cred.verdict, C.VERDICT.BLOCK);
  assert.strictEqual(cred.reason, C.REASON.USERINFO);
  const js = C.analyzeDownloadChain(['javascript:alert(1)']);
  assert.strictEqual(js.reason, C.REASON.BAD_SCHEME);
});

test('analyzeDownloadChain 拦截坏形状与超长链', () => {
  const shape = C.analyzeDownloadChain('https://example.test/a');
  assert.strictEqual(shape.verdict, C.VERDICT.BLOCK);
  assert.strictEqual(shape.reason, C.REASON.BAD_SHAPE);
  const long = [];
  for (let i = 0; i <= C.MAX_CHAIN_HOPS; i += 1) {
    long.push('https://example.test/' + i);
  }
  const r = C.analyzeDownloadChain(long);
  assert.strictEqual(r.verdict, C.VERDICT.BLOCK);
  assert.strictEqual(r.reason, C.REASON.TOO_LONG);
});

test('analyzeDownloadChain 拦截非法/超长 URL 与空主机', () => {
  assert.strictEqual(C.analyzeDownloadChain(['not a url']).reason, C.REASON.BAD_URL);
  assert.strictEqual(C.analyzeDownloadChain(['https://example.test/' + 'a'.repeat(9000)]).reason, C.REASON.BAD_URL);
  const schemeOnly = 'https://' + 'a'.repeat(9000);
  assert.strictEqual(C.analyzeDownloadChain([schemeOnly]).reason, C.REASON.BAD_URL);
});

test('inspectDownloadChainHop 返回协议与主机', () => {
  const hop = C.inspectDownloadChainHop('HTTPS://Example.TEST:8443/a?b=1');
  assert.strictEqual(hop.ok, true);
  assert.strictEqual(hop.scheme, 'https');
  assert.strictEqual(hop.host, 'example.test');
  const bad = C.inspectDownloadChainHop(null);
  assert.strictEqual(bad.ok, false);
  assert.strictEqual(bad.reason, C.REASON.BAD_URL);
});

test('analyzeDownloadChain 拦截畸形主机名', () => {
  const bad = [
    'https://a..b.test/x',
    'https://-bad.test/x',
    'https://bad-.test/x',
    'https://localhost/x',
    'https://example.123/x',
    'https://' + 'a'.repeat(64) + '.test/x',
  ];
  for (const u of bad) {
    const r = C.analyzeDownloadChain([u]);
    assert.strictEqual(r.verdict, C.VERDICT.BLOCK);
    assert.ok([C.REASON.BAD_HOST, C.REASON.BAD_URL].includes(r.reason), 'unexpected reason: ' + r.reason);
  }
  assert.strictEqual(C.validHostLabels('a_b.example.test'), true);
  assert.strictEqual(C.validHostLabels('example.test'), true);
  assert.strictEqual(C.validHostLabels(''), false);
});

test('describeDownloadChain 覆盖全部原因码', () => {
  const codes = Object.values(C.REASON);
  const seen = new Set();
  for (const code of codes) {
    const text = C.describeDownloadChain({ reason: code });
    assert.ok(text.length > 0);
    assert.ok(!seen.has(text), 'duplicate text: ' + text);
    seen.add(text);
  }
  assert.ok(C.describeDownloadChain({ reason: 'unknown' }).length > 0);
});
