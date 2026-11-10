'use strict';

const test = require('node:test');
const assert = require('node:assert');
const E = require('./externalcall');

function harness(overrides) {
  const calls = { tabs: [], events: [] };
  E.bindDeps(Object.assign({
    isSafeUrl: (u) => /^https?:\/\/[^\s]+$/i.test(u),
    createNewTab: (u) => calls.tabs.push(u),
    recordSecurityEvent: (kind, level, msg, origin) => calls.events.push({ kind, level, msg, origin }),
  }, overrides || {}));
  return calls;
}

test('confirmAndOpenExternal 对大小写混写的 http(s) 仍走标签页而不是外部协议', async () => {
  const calls = harness();
  for (const url of ['HTTPS://example.com/a', 'Http://example.com/b', 'https://example.com/c']) {
    const r = await E.confirmAndOpenExternal(url, 'https://site.test');
    assert.deepStrictEqual(r, { ok: true });
    assert.strictEqual(calls.tabs.pop(), url);
  }
  assert.strictEqual(calls.events.length, 0);
});

test('isWebUrl 只认 http/https，其余协议与畸形串一律不认', () => {
  assert.strictEqual(E.isWebUrl('https://a.test/x'), true);
  assert.strictEqual(E.isWebUrl('HtTp://a.test/x'), true);
  assert.strictEqual(E.isWebUrl('javascript:alert(1)'), false);
  assert.strictEqual(E.isWebUrl('mailto:a@b.test'), false);
  assert.strictEqual(E.isWebUrl(''), false);
  assert.strictEqual(E.isWebUrl('not a url'), false);
});

test('不安全的 http(s) 地址在进入标签页前被拒并记 critical', async () => {
  const calls = harness({ isSafeUrl: () => false });
  const r = await E.confirmAndOpenExternal('https://evil.test/', 'https://site.test');
  assert.deepStrictEqual(r, { ok: false, reason: 'unsafe url' });
  assert.strictEqual(calls.tabs.length, 0);
  assert.strictEqual(calls.events[0].level, 'critical');
});
