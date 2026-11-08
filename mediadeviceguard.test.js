'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./mediadeviceguard');

test('缺失 origin 被拒绝', () => {
  const r = guard.applyMediaDeviceGuard({ kinds: ['audioinput'] });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.NO_ORIGIN);
});

test('http origin 被拒绝', () => {
  const r = guard.applyMediaDeviceGuard({ origin: 'http://a.example.com', kinds: ['audioinput'] });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.INSECURE);
});

test('音频约束带降噪', () => {
  const r = guard.applyMediaDeviceGuard({ origin: 'https://a.example.com', kinds: ['audioinput'] });
  assert.strictEqual(r.allowed, true);
  assert.strictEqual(r.constraints.audio.echoCancellation, true);
});

test('视频约束限分辨率', () => {
  const r = guard.applyMediaDeviceGuard({ origin: 'https://a.example.com', kinds: ['videoinput'] });
  assert.strictEqual(r.constraints.video.width.max, 1280);
  assert.strictEqual(r.constraints.video.frameRate.max, 30);
});

test('未知设备类型被拒绝', () => {
  const r = guard.applyMediaDeviceGuard({ origin: 'https://a.example.com', kinds: ['midi'] });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.UNKNOWN_DEVICE);
});

test('枚举设备被拒绝', () => {
  const r = guard.applyMediaDeviceGuard({ origin: 'https://a.example.com', kinds: ['audioinput'], enumerateDevices: true });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.DEVICE_ENUMERATION);
});

test('持久 deviceId 被拒绝', () => {
  const r = guard.applyMediaDeviceGuard({ origin: 'https://a.example.com', kinds: ['audioinput'], deviceId: 'abc', persistDeviceId: true });
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.reason, guard.REASON.PERSISTED_DEVICE);
});

test('audioOnly 标记降级原因', () => {
  const r = guard.applyMediaDeviceGuard({ origin: 'https://a.example.com', kinds: ['audioinput'], audioOnly: true });
  assert.strictEqual(r.reason, guard.REASON.AUDIO_ONLY_DOWNGRADE);
});

test('批量审计统计拒绝数', () => {
  const report = guard.auditMediaBatch([
    { origin: 'https://a.example.com', kinds: ['audioinput'] },
    { origin: 'http://b.example.com', kinds: ['videoinput'] },
  ]);
  assert.strictEqual(report.total, 2);
  assert.strictEqual(report.denied, 1);
});
