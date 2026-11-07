'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./downloadpolicyguard');

test('普通 PDF 下载通过', () => {
  const r = guard.applyDownloadPolicyGuard({ filename: 'report.pdf', mimeType: 'application/pdf', url: 'https://example.com/report.pdf', size: 1024 });
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.name, 'report.pdf');
});

test('可执行扩展名被拒', () => {
  const r = guard.applyDownloadPolicyGuard({ filename: 'setup.exe', url: 'https://example.com/setup.exe' });
  assert.strictEqual(r.reason, guard.REASON.DANGEROUS_EXTENSION);
});

test('脚本扩展名被拒', () => {
  for (const name of ['a.ps1', 'a.jar', 'a.sh', 'a.apk']) {
    const r = guard.inspectDownload({ filename: name, url: 'https://example.com/x' });
    assert.strictEqual(r.reason, guard.REASON.DANGEROUS_EXTENSION);
  }
});

test('双扩展名伪装被拒', () => {
  const r = guard.inspectDownload({ filename: 'invoice.pdf.exe', url: 'https://example.com/x' });
  assert.strictEqual(r.reason, guard.REASON.DOUBLE_EXTENSION);
});

test('RTL 覆盖字符被拒', () => {
  const r = guard.inspectDownload({ filename: 'invoice\u202efexe.pdf', url: 'https://example.com/x' });
  assert.strictEqual(r.reason, guard.REASON.BIDI_OVERRIDE);
});

test('控制字符被拒', () => {
  const r = guard.inspectDownload({ filename: 'a\u0000.pdf', url: 'https://example.com/x' });
  assert.strictEqual(r.reason, guard.REASON.CONTROL_CHARS);
});

test('以点结尾被拒', () => {
  const r = guard.inspectDownload({ filename: 'report.', url: 'https://example.com/x' });
  assert.strictEqual(r.reason, guard.REASON.TRAILING_DOT);
});

test('超长文件名被拒', () => {
  const r = guard.inspectDownload({ filename: 'a'.repeat(guard.MAX_NAME_LENGTH + 1) + '.pdf', url: 'https://example.com/x' });
  assert.strictEqual(r.reason, guard.REASON.TOO_LONG);
});

test('MIME 不一致被拒', () => {
  const r = guard.inspectDownload({ filename: 'photo.png', mimeType: 'text/html', url: 'https://example.com/x' });
  assert.strictEqual(r.reason, guard.REASON.MIME_MISMATCH);
});

test('超大文件被拒', () => {
  const r = guard.inspectDownload({ filename: 'big.zip', url: 'https://example.com/x', size: guard.MAX_SIZE + 1 });
  assert.strictEqual(r.reason, guard.REASON.TOO_LARGE);
});

test('HTTP 来源被拒', () => {
  const r = guard.inspectDownload({ filename: 'a.txt', url: 'http://example.com/a.txt' });
  assert.strictEqual(r.reason, guard.REASON.INSECURE_URL);
});

test('缺少文件名被拒', () => {
  const r = guard.inspectDownload({ url: 'https://example.com/a.txt' });
  assert.strictEqual(r.reason, guard.REASON.MISSING_NAME);
});

test('描述文本覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
