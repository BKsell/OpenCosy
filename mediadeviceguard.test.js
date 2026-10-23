'use strict';

// mediadeviceguard.test.js —— 枚举脱敏、采集门、约束上限、频控与并发轨道。

const test = require('node:test');
const assert = require('node:assert/strict');
const md = require('./mediadeviceguard');
const {
  MediaDeviceGuard, MD_REASON, defaultMediaPolicy, redactDevices, numConstraint, clampConstraints,
} = md;

const ORIGIN = 'https://meet.example.com';
function ctx(over) {
  return Object.assign({
    origin: ORIGIN, isSecureContext: true, hasUserGesture: true,
    isBackground: false, blocked: false, now: 1000,
  }, over || {});
}
const DEVICES = [
  { deviceId: 'cam1', kind: 'videoinput', label: 'Logitech BRIO 4K', groupId: 'g1' },
  { deviceId: 'mic1', kind: 'audioinput', label: 'Yeti Stereo', groupId: 'g1' },
  { deviceId: 'spk1', kind: 'audiooutput', label: 'Speakers', groupId: 'g2' },
  { deviceId: 'x', kind: 'bogus', label: 'nope', groupId: '' },
];

test('未授权枚举脱敏 label/groupId/deviceId，丢弃非法 kind', () => {
  const out = redactDevices(DEVICES, {}, defaultMediaPolicy());
  assert.equal(out.length, 3);
  assert.equal(out[0].label, '');
  assert.equal(out[0].deviceId, '');
  assert.ok(!out.some((d) => d.kind === 'bogus'));
});

test('授权对应 kind 后保留 label', () => {
  const out = redactDevices(DEVICES, { videoinput: true }, defaultMediaPolicy());
  const cam = out.find((d) => d.kind === 'videoinput');
  const mic = out.find((d) => d.kind === 'audioinput');
  assert.equal(cam.label, 'Logitech BRIO 4K');
  assert.equal(mic.label, '');
});

test('枚举频控', () => {
  const g = new MediaDeviceGuard();
  assert.equal(g.decideEnumerate(ctx({ now: 0 })).decision, 'allow');
  assert.equal(g.decideEnumerate(ctx({ now: 100 })).reason, MD_REASON.ENUM_THROTTLED);
  assert.equal(g.decideEnumerate(ctx({ now: 251 })).decision, 'allow');
});

test('非安全上下文/无手势/后台拒绝采集', () => {
  const g = new MediaDeviceGuard();
  assert.equal(g.decideRequest(ctx({ isSecureContext: false }), { video: true }).reason, MD_REASON.INSECURE_CONTEXT);
  assert.equal(g.decideRequest(ctx({ hasUserGesture: false }), { video: true }).reason, MD_REASON.NO_GESTURE);
  assert.equal(g.decideRequest(ctx({ isBackground: true }), { video: true }).reason, MD_REASON.BACKGROUND_CAPTURE);
});

test('采集弹窗节流', () => {
  const g = new MediaDeviceGuard();
  assert.equal(g.decideRequest(ctx({ now: 0 }), { video: true }).decision, 'prompt');
  assert.equal(g.decideRequest(ctx({ now: 1000 }), { video: true }).reason, MD_REASON.REQUEST_THROTTLED);
});

test('exact 分辨率约束默认拒绝', () => {
  const g = new MediaDeviceGuard();
  const r = g.decideRequest(ctx({ now: 0 }), { video: { width: { exact: 1920 } } });
  assert.equal(r.reason, MD_REASON.EXACT_CONSTRAINT_FORBIDDEN);
});

test('超限理想分辨率/帧率拒绝', () => {
  const g = new MediaDeviceGuard();
  const r1 = g.decideRequest(ctx({ now: 0 }), { video: { width: { ideal: 4000 } } });
  assert.equal(r1.reason, MD_REASON.EXCESSIVE_RESOLUTION);
  const r2 = g.decideRequest(ctx({ now: 1600 }), { video: { frameRate: { ideal: 120 } } });
  assert.equal(r2.reason, MD_REASON.EXCESSIVE_FPS);
});

test('手电筒与摄像头机械能力探测默认拒绝', () => {
  const g = new MediaDeviceGuard();
  const r = g.decideRequest(ctx({ now: 0 }), { video: { torch: true } });
  assert.equal(r.reason, MD_REASON.TORCH_NOT_ALLOWED);
});

test('并发轨道上限', () => {
  const g = new MediaDeviceGuard();
  g.noteTracksStarted(ORIGIN, 4);
  const r = g.decideRequest(ctx({ now: 0 }), { audio: true, video: true });
  assert.equal(r.reason, MD_REASON.TOO_MANY_DEVICES);
  g.noteTracksStopped(ORIGIN, 2);
  assert.equal(g.decideRequest(ctx({ now: 1600 }), { audio: true }).decision, 'prompt');
});

test('clampConstraints 收敛分辨率与帧率', () => {
  const pol = defaultMediaPolicy();
  const c = clampConstraints({ audio: true, video: { width: { ideal: 4000 }, height: { ideal: 2000 }, frameRate: { ideal: 120 } } }, pol);
  assert.equal(c.video.width.ideal, 1280);
  assert.equal(c.video.height.ideal, 720);
  assert.equal(c.video.frameRate.ideal, 30);
});

test('numConstraint 读取顺序 exact>ideal>max>min', () => {
  assert.deepEqual(numConstraint({ ideal: 720 }), { value: 720, exact: false });
  assert.deepEqual(numConstraint({ exact: 1080, ideal: 720 }), { value: 1080, exact: true });
  assert.equal(numConstraint(undefined), null);
});
