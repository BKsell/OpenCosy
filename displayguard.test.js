'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  DISPLAY_DECISION_DENY,
  BLUETOOTH_DECISION_CANCEL,
  normalizeMediaTypes,
  originFromUrl,
  decideDisplayMedia,
  decideBluetoothSelection,
  isDisplayMediaHandlerAvailable,
} = require('./displayguard');

test('normalizeMediaTypes 去重并过滤未知类型', () => {
  assert.deepEqual(normalizeMediaTypes(['screen', 'screen', 'window', 'camera', ' AUDIO ']),
    ['screen', 'window', 'audio']);
  assert.deepEqual(normalizeMediaTypes(undefined), []);
  assert.deepEqual(normalizeMediaTypes('screen'), []);
  assert.deepEqual(normalizeMediaTypes([null, '', 'window']), ['window']);
});

test('originFromUrl 安全取源', () => {
  assert.equal(originFromUrl('https://a.test:8443/x?q=1'), 'https://a.test:8443');
  assert.equal(originFromUrl('not a url'), '');
  assert.equal(originFromUrl(undefined), '');
});

test('屏幕/窗口采集一律拒绝', () => {
  const r1 = decideDisplayMedia({ frame: { url: 'https://evil.test/' }, mediaTypes: ['screen'] });
  assert.equal(r1.decision, DISPLAY_DECISION_DENY);
  assert.equal(r1.reason, 'display-capture');
  assert.equal(r1.origin, 'https://evil.test');

  const r2 = decideDisplayMedia({ frame: { url: 'https://evil.test/' }, mediaTypes: ['window', 'audio'] });
  assert.equal(r2.decision, DISPLAY_DECISION_DENY);
  assert.equal(r2.reason, 'display-capture');
});

test('仅系统音频也拒绝并单独标记', () => {
  const r = decideDisplayMedia({ frame: { url: 'https://evil.test/' }, mediaTypes: ['audio'] });
  assert.equal(r.decision, DISPLAY_DECISION_DENY);
  assert.equal(r.reason, 'display-audio-only');
});

test('畸形屏幕共享请求拒绝', () => {
  const r1 = decideDisplayMedia({ frame: { url: 'https://evil.test/' }, mediaTypes: [] });
  assert.equal(r1.reason, 'display-malformed');
  const r2 = decideDisplayMedia({ frame: { url: 'https://evil.test/' } });
  assert.equal(r2.reason, 'display-malformed');
  const r3 = decideDisplayMedia(null);
  assert.equal(r3.reason, 'display-malformed');
  assert.equal(r3.origin, '');
});

test('即便内部 cosy: 文档也不放行屏幕共享', () => {
  const r = decideDisplayMedia({ frame: { url: 'cosy://settings/' }, mediaTypes: ['screen'] });
  assert.equal(r.decision, DISPLAY_DECISION_DENY);
});

test('蓝牙设备选择恒取消并报告设备数', () => {
  const r = decideBluetoothSelection({
    url: 'https://evil.test/',
    devices: [{ deviceId: 'aa' }, { deviceId: 'bb' }],
  });
  assert.equal(r.decision, BLUETOOTH_DECISION_CANCEL);
  assert.equal(r.reason, 'bluetooth-auto-select');
  assert.equal(r.origin, 'https://evil.test');
  assert.equal(r.deviceCount, 2);

  const empty = decideBluetoothSelection({ url: 'bad url', devices: null });
  assert.equal(empty.decision, BLUETOOTH_DECISION_CANCEL);
  assert.equal(empty.origin, '');
  assert.equal(empty.deviceCount, 0);
});

test('能力探测', () => {
  assert.equal(isDisplayMediaHandlerAvailable(undefined), false);
  assert.equal(isDisplayMediaHandlerAvailable({}), false);
  assert.equal(isDisplayMediaHandlerAvailable({ setDisplayMediaRequestHandler() {} }), true);
});
