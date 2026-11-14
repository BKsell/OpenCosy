'use strict';

const test = require('node:test');
const assert = require('node:assert');
const pdf = require('./cosyipcpdfexport');

test('normalizePdfName 拒绝穿越、控制字符与非 pdf', () => {
  assert.strictEqual(pdf.normalizePdfName('report.pdf'), 'report.pdf');
  assert.strictEqual(pdf.normalizePdfName('  a/b/c.PDF  '), 'c.PDF');
  assert.strictEqual(pdf.normalizePdfName('../etc/passwd'), null);
  assert.strictEqual(pdf.normalizePdfName('..'), null);
  assert.strictEqual(pdf.normalizePdfName('a\x00.pdf'), null);
  assert.strictEqual(pdf.normalizePdfName('a\nb.pdf'), null);
  assert.strictEqual(pdf.normalizePdfName('x.txt'), null);
  assert.strictEqual(pdf.normalizePdfName(''), null);
  assert.strictEqual(pdf.normalizePdfName(123), null);
  assert.strictEqual(pdf.normalizePdfName('a'.repeat(201) + '.pdf'), null);
});

test('buildPdfOptions 只透传白名单字段', () => {
  const o = pdf.buildPdfOptions({ pageSize: 'A3', landscape: true, scale: 1.5, headerTemplate: '<img onerror=alert(1)>', footerTemplate: 'x' });
  assert.strictEqual(o.pageSize, 'A3');
  assert.strictEqual(o.landscape, true);
  assert.strictEqual(o.scale, 1.5);
  assert.strictEqual(o.printBackground, true);
  assert.strictEqual(o.headerTemplate, undefined);
  assert.strictEqual(o.footerTemplate, undefined);
  assert.deepStrictEqual(o.margins, { top: 0.5, bottom: 0.5, left: 0.5, right: 0.5 });
});

test('buildPdfOptions 收敛非法值', () => {
  const o = pdf.buildPdfOptions({ pageSize: 'B7', scale: 99, printBackground: false });
  assert.strictEqual(o.pageSize, 'A4');
  assert.strictEqual(o.scale, 1);
  assert.strictEqual(o.printBackground, false);
  const d = pdf.buildPdfOptions(null);
  assert.strictEqual(d.pageSize, 'A4');
  assert.strictEqual(d.landscape, false);
});

test('classifyPdfError 映射错误码', () => {
  assert.strictEqual(pdf.classifyPdfError({ code: 'EACCES' }), 'permission-denied');
  assert.strictEqual(pdf.classifyPdfError({ code: 'EPERM' }), 'permission-denied');
  assert.strictEqual(pdf.classifyPdfError({ code: 'ENOSPC' }), 'no-space');
  assert.strictEqual(pdf.classifyPdfError({ code: 'ENOENT' }), 'not-found');
  assert.strictEqual(pdf.classifyPdfError({}), 'write-failed');
  assert.strictEqual(pdf.classifyPdfError(new Error('x')), 'write-failed');
});
