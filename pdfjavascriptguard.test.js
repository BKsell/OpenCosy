'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./pdfjavascriptguard');

function pdf(body) {
  return Buffer.from('%PDF-1.7\n' + body + '\ntrailer\n%%EOF', 'latin1');
}

test('普通 PDF 通过', () => {
  const r = guard.applyPdfJavaScriptGuard(pdf('1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj'));
  assert.strictEqual(r.changed, false);
  assert.deepStrictEqual(r.markers, []);
});

test('含 JavaScript 动作被拒', () => {
  const r = guard.inspectPdf(pdf('<< /S /JavaScript /JS (app.alert(1)) >>'));
  assert.strictEqual(r.reason, guard.REASON.JAVASCRIPT);
});

test('含 Launch 动作被拒', () => {
  const r = guard.inspectPdf(pdf('<< /S /Launch /F (cmd.exe) >>'));
  assert.strictEqual(r.reason, guard.REASON.LAUNCH);
});

test('含内嵌附件被拒', () => {
  const r = guard.inspectPdf(pdf('<< /Type /Filespec /EF << /F 5 0 R >> >> /EmbeddedFile'));
  assert.strictEqual(r.reason, guard.REASON.EMBEDDED_FILE);
});

test('含 OpenAction 被拒', () => {
  const r = guard.inspectPdf(pdf('<< /OpenAction 3 0 R >>'));
  assert.strictEqual(r.reason, guard.REASON.OPEN_ACTION);
});

test('含 RichMedia 被拒', () => {
  const r = guard.inspectPdf(pdf('<< /Subtype /RichMedia >>'));
  assert.strictEqual(r.reason, guard.REASON.RICH_MEDIA);
});

test('加密 PDF 被拒', () => {
  const r = guard.inspectPdf(pdf('trailer << /Encrypt 9 0 R >>'));
  assert.strictEqual(r.reason, guard.REASON.ENCRYPTED);
});

test('非 PDF 被拒', () => {
  const r = guard.inspectPdf(Buffer.from('GIF89a body'));
  assert.strictEqual(r.reason, guard.REASON.NOT_PDF);
});

test('空缓冲被拒', () => {
  const r = guard.inspectPdf(Buffer.alloc(0));
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
});

test('非 Buffer 被拒', () => {
  const r = guard.inspectPdf('%PDF-1.7');
  assert.strictEqual(r.reason, guard.REASON.NOT_BUFFER);
});

test('超体积被拒', () => {
  const r = guard.inspectPdf(Buffer.alloc(guard.MAX_BYTES + 1, 0x41));
  assert.strictEqual(r.reason, guard.REASON.TOO_LARGE);
});

test('多标记全部记录', () => {
  const r = guard.inspectPdf(pdf('<< /OpenAction 1 0 R /Launch (x) /JS (y) >>'));
  assert.strictEqual(r.markers.length >= 3, true);
});

test('描述文本覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
