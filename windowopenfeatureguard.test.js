'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./windowopenfeatureguard');

test('空 features 仍强制 noopener 与 noreferrer', () => {
  const r = guard.applyWindowOpenFeatureGuard({});
  assert.strictEqual(r.features.includes('noopener=yes'), true);
  assert.strictEqual(r.features.includes('noreferrer=yes'), true);
  assert.strictEqual(r.findings.length, 2);
});

test('已有 noopener 不重复添加', () => {
  const r = guard.applyWindowOpenFeatureGuard({ features: 'noopener=yes,noreferrer=yes' });
  assert.strictEqual(r.features.split(',').filter((t) => t.startsWith('noopener')).length, 1);
  assert.strictEqual(r.findings.length, 0);
});

test('危险特性被剔除', () => {
  const r = guard.applyWindowOpenFeatureGuard({ features: 'alwaysOnTop=yes,width=400' });
  assert.strictEqual(r.features.includes('alwaysontop'), false);
  assert.strictEqual(r.features.includes('width=400'), true);
  assert.ok(r.findings.some((f) => f.reason === guard.REASON.DANGEROUS_FEATURE));
});

test('未知特性被丢弃并记录', () => {
  const parsed = guard.parseFeatures('width=400,foo=1');
  assert.deepStrictEqual(parsed.invalid, ['foo']);
  assert.strictEqual(parsed.features.width, '400');
});

test('尺寸解析保留数值', () => {
  const parsed = guard.parseFeatures('width=800,height=600,left=10,top=20');
  assert.strictEqual(parsed.features.width, '800');
  assert.strictEqual(parsed.features.height, '600');
});

test('同源窗口可不强制 noopener', () => {
  const r = guard.applyWindowOpenFeatureGuard({ crossOrigin: false, stripReferrer: false, features: 'width=300' });
  assert.strictEqual(r.features, 'width=300');
  assert.strictEqual(r.findings.length, 0);
});

test('布尔 yes 规范化为 yes', () => {
  const parsed = guard.parseFeatures('menubar,toolbar=no');
  assert.strictEqual(guard.applyWindowOpenFeatureGuard({ features: 'menubar' }).features.includes('menubar=yes'), true);
  assert.strictEqual(typeof parsed.features.menubar, 'boolean');
});

test('批量审计统计重写并限制 finding', () => {
  const report = guard.auditWindowOpenBatch([
    { features: 'alwaysOnTop=yes' },
    { features: 'noopener=yes,noreferrer=yes' },
    { features: 'bad=1' },
  ], { maxFindings: 3 });
  assert.strictEqual(report.total, 3);
  assert.strictEqual(report.rewritten, 2);
  assert.ok(report.findings.length <= 3);
});
