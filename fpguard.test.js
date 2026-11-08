'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fp = require('./fpguard');

test('sanitizeOutboundHeaders 删除高熵 Client Hints（大小写不敏感）', () => {
  const headers = {
    'Sec-CH-UA-Arch': '"x86"',
    'sec-ch-ua-full-version': '"131.0.6778.86"',
    'Sec-CH-UA': '"Chromium";v="131"', // 低熵基础头应保留
    'Sec-CH-UA-Platform': '"Windows"', // 低熵平台应保留
    'Accept': 'text/html',
  };
  const r = fp.sanitizeOutboundHeaders({ resourceType: 'script' }, headers, {});
  assert.equal(headers['Sec-CH-UA-Arch'], undefined);
  assert.equal(headers['sec-ch-ua-full-version'], undefined);
  assert.ok(headers['Sec-CH-UA'], '低熵 sec-ch-ua 不应被剥离');
  assert.ok(headers['Sec-CH-UA-Platform'], '低熵 platform 不应被剥离');
  assert.equal(headers.Accept, 'text/html');
  assert.ok(r.clientHints.includes('sec-ch-ua-arch'));
  assert.ok(r.clientHints.includes('sec-ch-ua-full-version'));
});

test('关闭 reduceClientHints 时保留高熵头', () => {
  const headers = { 'Sec-CH-UA-Model': '"Pixel"', 'Attribution-Reporting-Eligible': 'event-source' };
  const r = fp.sanitizeOutboundHeaders({}, headers, { reduceClientHints: false, blockAdSignals: false });
  assert.equal(headers['Sec-CH-UA-Model'], '"Pixel"');
  assert.equal(headers['Attribution-Reporting-Eligible'], 'event-source');
  assert.deepEqual(r.clientHints, []);
});

test('剥离广告 / 归因 / Topics 信号头', () => {
  const headers = {
    'Sec-Browsing-Topics': '()',
    'Attribution-Reporting-Eligible': 'navigation-source',
    'Attribution-Reporting-Support': 'web,os',
    'Sec-Ad-Availability': '?0',
    'Cookie': 'a=1',
  };
  const r = fp.sanitizeOutboundHeaders({}, headers, { reduceClientHints: false });
  assert.equal(headers['Sec-Browsing-Topics'], undefined);
  assert.equal(headers['Attribution-Reporting-Eligible'], undefined);
  assert.equal(headers['Sec-Ad-Availability'], undefined);
  assert.equal(headers.Cookie, 'a=1');
  assert.equal(r.adSignals.length, 4);
});

test('stripAcceptClientHints 移除 Accept-CH / Critical-CH', () => {
  const res = {
    'Accept-CH': 'Sec-CH-UA-Arch, Sec-CH-UA-Model',
    'Critical-CH': 'Sec-CH-UA-Arch',
    'Content-Type': ['text/html'],
  };
  const removed = fp.stripAcceptClientHints(res, {});
  assert.equal(res['Accept-CH'], undefined);
  assert.equal(res['Critical-CH'], undefined);
  assert.ok(Array.isArray(res['Content-Type']));
  assert.ok(removed.includes('accept-ch'));
  assert.ok(removed.includes('critical-ch'));
});

test('stripAcceptClientHints 可被选项关闭', () => {
  const res = { 'Accept-CH': 'Sec-CH-UA-Bitness' };
  const removed = fp.stripAcceptClientHints(res, { stripAcceptCh: false });
  assert.deepEqual(removed, []);
  assert.equal(res['Accept-CH'], 'Sec-CH-UA-Bitness');
});

test('isHyperlinkPing 识别 resourceType=ping 与 Ping-To 头', () => {
  assert.equal(fp.isHyperlinkPing({ resourceType: 'ping' }, {}), true);
  assert.equal(fp.isHyperlinkPing({ resourceType: 'mainFrame' }, {}), false);
  assert.equal(fp.isHyperlinkPing(
    { resourceType: 'xhr', requestHeaders: { 'Ping-To': 'https://x.test/hit' } }, {}), true);
  assert.equal(fp.isHyperlinkPing({ resourceType: 'ping' }, { blockHyperlinkPing: false }), false);
});

test('WebRTC 模式归一与策略解析', () => {
  assert.equal(fp.normalizeWebRtcMode('balanced'), 'balanced');
  assert.equal(fp.normalizeWebRtcMode('bogus'), 'strict');
  assert.equal(fp.resolveWebRtcPolicy('strict'), 'default_public_interface_only');
  assert.equal(fp.resolveWebRtcPolicy('balanced'),
    'default_public_and_private_interfaces');
  assert.equal(fp.resolveWebRtcPolicy('legacy'), 'default');
  assert.equal(fp.resolveWebRtcPolicy(undefined), 'default_public_interface_only');
});

test('hostOf 安全取主机', () => {
  assert.equal(fp.hostOf('https://example.com:8443/a?q=1'), 'example.com');
  assert.equal(fp.hostOf('not a url'), '');
});

test('台账按主机+类别聚合并有界淘汰', () => {
  const ledger = fp.createFingerprintLedger(3);
  ledger.record('a.test', 'client-hints', ['sec-ch-ua-arch', 'sec-ch-ua-model']);
  ledger.record('a.test', 'client-hints', ['sec-ch-ua-arch']); // 同键累加
  ledger.record('a.test', 'ad-signals', ['sec-browsing-topics']);
  ledger.record('b.test', 'ping');
  const s = ledger.stats();
  assert.equal(s.hosts, 3);
  assert.equal(s.hits, 4);
  assert.equal(s.byCategory['client-hints'], 2);
  assert.equal(s.byCategory['ad-signals'], 1);

  const entries = ledger.entries();
  const aCh = entries.find((e) => e.host === 'a.test' && e.category === 'client-hints');
  assert.equal(aCh.hits, 2);
  assert.deepEqual(aCh.signals, ['sec-ch-ua-arch', 'sec-ch-ua-model']);

  // 超过上限，最旧条目被淘汰，但新条目可写入。
  ledger.record('c.test', 'accept-ch');
  ledger.record('d.test', 'ping');
  assert.ok(ledger.size() <= 3);
});

test('台账 toJSON / load 往返保留信号与计数', () => {
  const ledger = fp.createFingerprintLedger();
  ledger.record('z.test', 'accept-ch', ['accept-ch']);
  const json = ledger.toJSON();
  const ledger2 = fp.createFingerprintLedger();
  ledger2.load(json);
  const e = ledger2.entries().find((x) => x.host === 'z.test');
  assert.ok(e);
  assert.equal(e.category, 'accept-ch');
  assert.equal(e.hits, 1);
  assert.deepEqual(e.signals, ['accept-ch']);
});

test('台账忽略非法输入', () => {
  const ledger = fp.createFingerprintLedger();
  assert.equal(ledger.record('', 'ping'), null);
  ledger.load(null);
  ledger.load({ rows: 'nope' });
  assert.equal(ledger.size(), 0);
});

test('非对象 headers 不抛错', () => {
  assert.doesNotThrow(() => fp.sanitizeOutboundHeaders({}, null, {}));
  assert.doesNotThrow(() => fp.stripAcceptClientHints(null, {}));
});
