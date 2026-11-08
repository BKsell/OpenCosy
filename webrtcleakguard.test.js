'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./webrtcleakguard');

test('policy=disable 直接阻断', () => {
  const r = guard.applyWebRtcLeakGuard({ policy: 'disable', userPermission: true });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.POLICY_BLOCKED);
});

test('无权限阻断', () => {
  const r = guard.applyWebRtcLeakGuard({ policy: 'default' });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.NO_PERMISSION);
});

test('policy=all 阻断', () => {
  const r = guard.applyWebRtcLeakGuard({ policy: 'all', userPermission: true });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.IP_EXPOSED);
});

test('host 候选地址阻断', () => {
  const sdp = 'a=candidate:1 1 udp 2122260223 192.168.1.5 5000 typ host';
  const r = guard.applyWebRtcLeakGuard({ policy: 'default', userPermission: true, sdp });
  assert.strictEqual(r.blocked, true);
  assert.ok(r.candidateTypes.includes('host'));
});

test('srflx 候选地址阻断', () => {
  const sdp = 'a=candidate:2 1 udp 1686052607 1.2.3.4 5000 typ srflx';
  const r = guard.applyWebRtcLeakGuard({ policy: 'default', userPermission: true, sdp });
  assert.strictEqual(r.blocked, true);
});

test('relay 策略放行', () => {
  const sdp = 'a=candidate:2 1 udp 1686052607 1.2.3.4 5000 typ srflx';
  const r = guard.applyWebRtcLeakGuard({ policy: 'relay', userPermission: true, sdp });
  assert.strictEqual(r.blocked, false);
  assert.strictEqual(r.constraints.iceTransportPolicy, 'relay');
});

test('跨源创建阻断', () => {
  const r = guard.applyWebRtcLeakGuard({ policy: 'default', userPermission: true, origin: 'https://a.example.com', topOrigin: 'https://b.example.org' });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.CROSS_ORIGIN);
});

test('constraints 强制 rtcpMux', () => {
  const r = guard.applyWebRtcLeakGuard({ policy: 'relay', userPermission: true });
  assert.strictEqual(r.constraints.rtcpMuxPolicy, 'require');
  assert.strictEqual(r.constraints.bundlePolicy, 'max-bundle');
});

test('批量审计统计阻断数', () => {
  const report = guard.auditWebRtcBatch([
    { policy: 'all', userPermission: true },
    { policy: 'relay', userPermission: true },
  ]);
  assert.strictEqual(report.total, 2);
  assert.strictEqual(report.blocked, 1);
});
