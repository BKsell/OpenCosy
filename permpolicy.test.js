'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const p = require('./permpolicy');

test('特性名白名单：未知特性被拒绝', () => {
  assert.equal(p.isValidFeatureName('camera'), true);
  assert.equal(p.isValidFeatureName('interest-cohort'), true);
  assert.equal(p.isValidFeatureName('evil\nx'), false);
  assert.equal(p.isValidFeatureName(''), false);
});

test('normalizeAllowValue 归一', () => {
  assert.deepEqual(p.normalizeAllowValue(false), []);
  assert.deepEqual(p.normalizeAllowValue('none'), []);
  assert.deepEqual(p.normalizeAllowValue(undefined), []);
  assert.deepEqual(p.normalizeAllowValue(true), ['self']);
  assert.deepEqual(p.normalizeAllowValue('self'), ['self']);
  assert.deepEqual(p.normalizeAllowValue('*'), ['*']);
  assert.deepEqual(p.normalizeAllowValue([]), []);
});

test('sanitizeOrigins 只保留 self/* 与 https 源，去路径/查询', () => {
  const r = p.sanitizeOrigins([
    'self',
    'https://meet.example.com/path?q=1',
    'http://insecure.test',
    'javascript:alert(1)',
    'data:text/html,x',
    'https://a.test',
    'https://a.test', // 去重
  ]);
  assert.deepEqual(r, ['self', 'https://meet.example.com', 'https://a.test']);
});

test('formatAllowlist 渲染', () => {
  assert.equal(p.formatAllowlist([]), '()');
  assert.equal(p.formatAllowlist(['self']), '(self)');
  assert.equal(p.formatAllowlist(['*']), '(*)');
  assert.equal(p.formatAllowlist(['https://a.test']), '("https://a.test")');
  assert.equal(p.formatAllowlist(['self', 'https://a.test']), '(self "https://a.test")');
});

test('强制关闭的广告/追踪特性无法被放开', () => {
  const h = p.buildPermissionsPolicy({
    featureOverrides: {
      'interest-cohort': '*',
      'join-ad-interest-group': 'self',
      'run-ad-auction': ['https://ad.test'],
      'browsing-topics': true,
      'private-state-token-issuance': '*',
      camera: 'self',
    },
  });
  for (const f of p.FORCED_DISABLE) {
    assert.equal(p.isFeatureDisabled(h, f), true, `${f} 必须强制全禁`);
  }
  assert.equal(p.isFeatureDisabled(h, 'camera'), false);
});

test('defaultHeader 强制关闭广告/追踪且不禁用摄像头等能力', () => {
  const h = p.defaultHeader();
  for (const f of p.FORCED_DISABLE) {
    assert.ok(h.includes(`${f}=()`), `默认头应包含 ${f}=()`);
  }
  assert.ok(!h.includes('camera='), '默认不应禁摄像头');
  assert.ok(!h.includes('geolocation='), '默认不应禁地理位置');
});

test('按来源放开能力生成引号源', () => {
  const h = p.buildPermissionsPolicy({
    featureOverrides: { payment: ['https://pay.example.com'], fullscreen: 'self' },
  });
  assert.ok(h.includes('payment=("https://pay.example.com")'));
  assert.ok(h.includes('fullscreen=(self)'));
});

test('非法 override 值被忽略', () => {
  const h = p.buildPermissionsPolicy({
    featureOverrides: { camera: 12345, geolocation: ['http://x.test'] },
  });
  // camera 非法 -> 不出现在可配置输出；geolocation 的 http 源被清空 -> ()
  assert.ok(!h.includes('camera='));
  assert.ok(h.includes('geolocation=()'));
});

test('parsePermissionsPolicy 往返', () => {
  const h = p.buildPermissionsPolicy({
    featureOverrides: { usb: ['https://x.test', 'self'], midi: [] },
  });
  const parsed = p.parsePermissionsPolicy(h);
  assert.deepEqual(parsed.usb.sort(), ['self', 'https://x.test'].sort());
  assert.deepEqual(parsed.midi, []);
  assert.deepEqual(parsed['interest-cohort'], []);
});

test('parsePermissionsPolicy 跳过非法片段与头注入尝试', () => {
  const evil = 'camera=(self), bogus, evil\nx=(self), microphone=()';
  const parsed = p.parsePermissionsPolicy(evil);
  assert.ok(!('bogus' in parsed));
  assert.ok(!('evil\nx' in parsed));
  assert.deepEqual(parsed.microphone, []);
  assert.equal(parsed.camera[0], 'self');
});

test('picture-in-picture 属于已知可配置能力', () => {
  assert.equal(p.CONFIGURABLE_FEATURES.includes('picture-in-picture'), true);
  assert.equal(p.isValidFeatureName('picture-in-picture'), true);
  assert.equal(p.FORCED_DISABLE.includes('picture-in-picture'), false);
});

test('headerWithPictureInPicture 允许时放开为 * 且仍钉死追踪特性', () => {
  const h = p.headerWithPictureInPicture(true);
  assert.ok(h.includes('picture-in-picture=(*)'), '允许时应输出 (*)');
  assert.equal(p.isFeatureDisabled(h, 'picture-in-picture'), false);
  for (const f of p.FORCED_DISABLE) {
    assert.equal(p.isFeatureDisabled(h, f), true, `${f} 仍须强制全禁`);
  }
});

test('headerWithPictureInPicture 关闭时全禁画中画', () => {
  const h = p.headerWithPictureInPicture(false);
  assert.ok(h.includes('picture-in-picture=()'), '关闭时应输出 ()');
  assert.equal(p.isFeatureDisabled(h, 'picture-in-picture'), true);
});

test('画中画策略可被解析回允许令牌', () => {
  const parsed = p.parsePermissionsPolicy(p.headerWithPictureInPicture(true));
  assert.deepEqual(parsed['picture-in-picture'], ['*']);
});
