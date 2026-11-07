'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./updateartifactguard');

function manifest(overrides) {
  const base = {
    version: '1.4.2',
    url: 'https://downloads.example.com/cosy-1.4.2.zip',
    sha512: 'a'.repeat(128),
    size: 52428800,
    signature: Buffer.alloc(64, 7).toString('base64'),
    platform: 'darwin-arm64',
  };
  return Object.assign(base, overrides || {});
}

test('合法更新清单通过', () => {
  const r = guard.applyUpdateArtifactGuard(manifest());
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.manifest.platform, 'darwin-arm64');
});

test('预发布版本通过', () => {
  const r = guard.inspectUpdateManifest(manifest({ version: '2.0.0-beta.1' }));
  assert.strictEqual(r.ok, true);
});

test('非法版本被拒', () => {
  const r = guard.inspectUpdateManifest(manifest({ version: '1.4' }));
  assert.strictEqual(r.reason, guard.REASON.VERSION);
});

test('HTTP 地址被拒', () => {
  const r = guard.inspectUpdateManifest(manifest({ url: 'http://downloads.example.com/x.zip' }));
  assert.strictEqual(r.reason, guard.REASON.URL);
});

test('内嵌凭据被拒', () => {
  const r = guard.inspectUpdateManifest(manifest({ url: 'https://user:pass@downloads.example.com/x.zip' }));
  assert.strictEqual(r.reason, guard.REASON.USERINFO);
});

test('哈希长度不符被拒', () => {
  const r = guard.inspectUpdateManifest(manifest({ sha512: 'abc' }));
  assert.strictEqual(r.reason, guard.REASON.HASH);
});

test('大写哈希归一化后通过', () => {
  const r = guard.inspectUpdateManifest(manifest({ sha512: 'A'.repeat(128) }));
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.manifest.sha512, 'a'.repeat(128));
});

test('签名长度不符被拒', () => {
  const r = guard.inspectUpdateManifest(manifest({ signature: Buffer.alloc(32, 1).toString('base64') }));
  assert.strictEqual(r.reason, guard.REASON.SIGNATURE);
});

test('体积为负被拒', () => {
  const r = guard.inspectUpdateManifest(manifest({ size: -1 }));
  assert.strictEqual(r.reason, guard.REASON.SIZE);
});

test('体积超上限被拒', () => {
  const r = guard.inspectUpdateManifest(manifest({ size: guard.MAX_SIZE + 1 }));
  assert.strictEqual(r.reason, guard.REASON.SIZE);
});

test('不支持的平台被拒', () => {
  const r = guard.inspectUpdateManifest(manifest({ platform: 'freebsd-x64' }));
  assert.strictEqual(r.reason, guard.REASON.PLATFORM);
});

test('空清单被拒', () => {
  const r = guard.inspectUpdateManifest(null);
  assert.strictEqual(r.reason, guard.REASON.INVALID);
});

test('描述文本覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
