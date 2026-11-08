'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./datatopnavigationguard');

test('普通 https 导航放行', () => {
  const r = guard.applyDataTopNavigationGuard({ url: 'https://example.com/x' });
  assert.strictEqual(r.blocked, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('data URL 顶层导航被阻断', () => {
  const r = guard.applyDataTopNavigationGuard({ url: 'data:text/html,<b>hi</b>', topLevel: true });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.DATA_TOPLEVEL);
});

test('含脚本的 data URL 即使子资源也被阻断', () => {
  const r = guard.applyDataTopNavigationGuard({ url: 'data:text/html,<script>alert(1)</script>' });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.ACTIVE_CONTENT);
});

test('base64 编码的活动内容被识别', () => {
  const payload = Buffer.from('<script>alert(1)</script>').toString('base64');
  const r = guard.applyDataTopNavigationGuard({ url: 'data:text/html;base64,' + payload });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.ACTIVE_CONTENT);
});

test('blob URL 顶层导航被阻断', () => {
  const r = guard.applyDataTopNavigationGuard({ url: 'blob:https://example.com/uuid', topLevel: true });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.BLOB_TOPLEVEL);
});

test('javascript URL 被阻断', () => {
  const r = guard.applyDataTopNavigationGuard({ url: 'java\nscript:alert(1)' });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.JAVASCRIPT);
});

test('超大 data URL 被阻断', () => {
  const big = 'data:text/plain,' + 'a'.repeat(2 * 1024 * 1024 + 1);
  const r = guard.applyDataTopNavigationGuard({ url: big });
  assert.strictEqual(r.blocked, true);
  assert.strictEqual(r.reason, guard.REASON.TOO_LARGE);
});

test('下载场景允许 data URL', () => {
  const r = guard.applyDataTopNavigationGuard({ url: 'data:text/plain,ok', topLevel: true, isDownload: true });
  assert.strictEqual(r.blocked, false);
  assert.strictEqual(r.action, 'download');
});

test('sanitizeDataUrl 按 MIME 白名单', () => {
  const ok = guard.sanitizeDataUrl('data:image/png,abc', ['image/png']);
  assert.strictEqual(ok.url.startsWith('data:image/png'), true);
  const bad = guard.sanitizeDataUrl('data:text/html,abc', ['image/png']);
  assert.strictEqual(bad.url, '');
  assert.strictEqual(bad.changed, true);
});

test('批量审计统计阻断', () => {
  const report = guard.auditDataNavigationBatch([
    { url: 'data:text/html,<script>x</script>' },
    { url: 'https://example.com' },
  ]);
  assert.strictEqual(report.total, 2);
  assert.strictEqual(report.blocked, 1);
});
