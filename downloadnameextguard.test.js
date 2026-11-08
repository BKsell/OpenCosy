'use strict';

const nodeTest = require('node:test');
const assert = require('node:assert');
const guard = require('./downloadnameextguard');

const { REASON, inspectDownloadName, parseDisposition, applyDownloadNameGuard, describeReason } = guard;

nodeTest.test('plain document name passes', () => {
  const verdict = inspectDownloadName('report-2026.pdf');
  assert.equal(verdict.reason, REASON.ok);
  assert.equal(verdict.dangerous, false);
});

nodeTest.test('executable behind decoy extension is caught', () => {
  const verdict = inspectDownloadName('invoice.pdf.exe');
  assert.equal(verdict.reason, REASON.doubleExtension);
  assert.equal(verdict.dangerous, true);
  assert.equal(verdict.sanitized, 'invoice.download');
});

nodeTest.test('triple extension still resolves to the decoy', () => {
  const verdict = inspectDownloadName('photo.jpg.scr');
  assert.equal(verdict.reason, REASON.doubleExtension);
  assert.equal(verdict.sanitized, 'photo.download');
});

nodeTest.test('plain executable without decoy is allowed', () => {
  const verdict = inspectDownloadName('setup.exe');
  assert.equal(verdict.reason, REASON.ok);
  assert.equal(verdict.dangerous, false);
});

nodeTest.test('right-to-left override is stripped', () => {
  const name = 'invoice\u202efdp.exe';
  const verdict = inspectDownloadName(name);
  assert.equal(verdict.reason, REASON.bidiOverride);
  assert.ok(!verdict.sanitized.includes('\u202e'));
  assert.ok(verdict.sanitized.endsWith('.download'));
});

nodeTest.test('control characters are rejected', () => {
  const verdict = inspectDownloadName('bad\u0000name.exe');
  assert.equal(verdict.reason, REASON.controlChars);
  assert.equal(verdict.dangerous, true);
});

nodeTest.test('trailing dot is rejected', () => {
  assert.equal(inspectDownloadName('invoice.pdf.').reason, REASON.trailingDotSpace);
  assert.equal(inspectDownloadName('invoice.pdf ').reason, REASON.trailingDotSpace);
});

nodeTest.test('reserved device names are rejected', () => {
  assert.equal(inspectDownloadName('CON.txt').reason, REASON.reservedDevice);
  assert.equal(inspectDownloadName('LPT1').reason, REASON.reservedDevice);
  assert.equal(inspectDownloadName('nul.dat').reason, REASON.reservedDevice);
});

nodeTest.test('hidden executable is rejected', () => {
  assert.equal(inspectDownloadName('.hidden.exe').reason, REASON.hiddenFile);
});

nodeTest.test('oversized name is rejected', () => {
  const name = `${'a'.repeat(guard.MAX_NAME_LENGTH + 5)}.pdf`;
  assert.equal(inspectDownloadName(name).reason, REASON.tooLong);
});

nodeTest.test('disposition parser handles quoted and unquoted names', () => {
  assert.equal(parseDisposition('attachment; filename="a b.pdf"').filename, 'a b.pdf');
  assert.equal(parseDisposition('attachment; filename=a.pdf').filename, 'a.pdf');
  assert.equal(parseDisposition('inline').filename, null);
});

nodeTest.test('disposition parser rejects bad types', () => {
  assert.equal(parseDisposition('attac hment; filename=a.pdf'), null);
  assert.equal(parseDisposition('attächment; filename=a.pdf'), null);
});

nodeTest.test('filter forces attachment for dangerous names', () => {
  const headers = { 'content-disposition': ['inline; filename="invoice.pdf.exe"'] };
  const result = applyDownloadNameGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(result.forcedAttachment, true);
  assert.ok(String(headers['Content-Disposition'][0]).startsWith('attachment;'));
  assert.ok(String(headers['Content-Disposition'][0]).includes('invoice.download'));
});

nodeTest.test('clean disposition is untouched', () => {
  const headers = { 'content-disposition': ['attachment; filename="report.pdf"'] };
  const result = applyDownloadNameGuard(headers);
  assert.equal(result.changed, false);
  assert.deepEqual(headers['content-disposition'], ['attachment; filename="report.pdf"']);
});

nodeTest.test('missing disposition is a no-op', () => {
  const headers = { 'content-type': ['application/pdf'] };
  assert.equal(applyDownloadNameGuard(headers).changed, false);
});

nodeTest.test('describeReason covers every reason', () => {
  for (const reason of Object.values(REASON)) {
    assert.ok(describeReason(reason).length > 0, reason);
  }
});
