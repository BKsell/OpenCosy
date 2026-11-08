'use strict';

const test = require('node:test');
const assert = require('node:assert');

const guard = require('./contentdispositionguard');

test('missing header is left alone', () => {
  const headers = {};
  const result = guard.applyContentDispositionGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(result.reason, guard.REASON.MISSING);
});

test('attachment with safe filename is kept', () => {
  const headers = { 'content-disposition': 'attachment; filename="report.pdf"' };
  const result = guard.applyContentDispositionGuard(headers);
  assert.equal(result.changed, false);
  assert.equal(headers['content-disposition'], 'attachment; filename="report.pdf"');
});

test('inline html is forced to attachment', () => {
  const headers = {
    'content-disposition': 'inline; filename="page.html"',
    'content-type': 'text/html; charset=utf-8',
  };
  const result = guard.applyContentDispositionGuard(headers);
  assert.equal(result.changed, true);
  assert.equal(result.reason, guard.REASON.INLINE_RISKY);
  assert.ok(String(headers['content-disposition']).startsWith('attachment'));
});

test('inline svg is forced to attachment', () => {
  const headers = {
    'content-disposition': 'inline',
    'content-type': 'image/svg+xml',
  };
  const result = guard.applyContentDispositionGuard(headers);
  assert.equal(result.reason, guard.REASON.INLINE_RISKY);
  assert.equal(headers['content-disposition'], 'attachment');
});

test('inline pdf stays inline', () => {
  const headers = {
    'content-disposition': 'inline; filename="a.pdf"',
    'content-type': 'application/pdf',
  };
  const result = guard.applyContentDispositionGuard(headers);
  assert.equal(result.changed, false);
});

test('traversal filename is stripped', () => {
  const headers = { 'content-disposition': 'attachment; filename="../../evil.sh"' };
  const result = guard.applyContentDispositionGuard(headers);
  assert.equal(result.reason, guard.REASON.BAD_FILENAME);
  assert.equal(headers['content-disposition'], 'attachment');
});

test('windows separator filename is stripped', () => {
  const headers = { 'content-disposition': 'attachment; filename="C:\\\\Windows\\\\evil.exe"' };
  const result = guard.applyContentDispositionGuard(headers);
  assert.equal(result.reason, guard.REASON.BAD_FILENAME);
  assert.equal(headers['content-disposition'], 'attachment');
});

test('control character filename is stripped', () => {
  const headers = { 'content-disposition': 'attachment; filename="a\u0000b.txt"' };
  const result = guard.applyContentDispositionGuard(headers);
  assert.equal(result.reason, guard.REASON.BAD_FILENAME);
});

test('bad percent encoding is stripped', () => {
  const headers = { 'content-disposition': "attachment; filename*=utf-8''bad%zzname.txt" };
  const result = guard.applyContentDispositionGuard(headers);
  assert.equal(result.reason, guard.REASON.BAD_FILENAME);
  assert.equal(headers['content-disposition'], 'attachment');
});

test('non utf-8 filename star is stripped', () => {
  const headers = { 'content-disposition': "attachment; filename*=iso-8859-1''x.txt" };
  const result = guard.applyContentDispositionGuard(headers);
  assert.equal(result.reason, guard.REASON.BAD_FILENAME);
  assert.equal(headers['content-disposition'], 'attachment');
});

test('valid filename star is kept', () => {
  const headers = { 'content-disposition': "attachment; filename*=UTF-8''%E4%B8%AD.txt" };
  const result = guard.applyContentDispositionGuard(headers);
  assert.equal(result.changed, false);
});

test('unknown disposition type is removed', () => {
  const headers = { 'content-disposition': 'form-data; name="x"' };
  const result = guard.applyContentDispositionGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
  assert.equal(headers['content-disposition'], undefined);
});

test('empty disposition is removed', () => {
  const headers = { 'content-disposition': '' };
  const result = guard.applyContentDispositionGuard(headers);
  assert.equal(result.reason, guard.REASON.MALFORMED);
});

test('overlong disposition is removed', () => {
  const headers = { 'content-disposition': 'attachment; filename="' + 'a'.repeat(guard.MAX_VALUE_LENGTH) + '"' };
  const result = guard.applyContentDispositionGuard(headers);
  assert.equal(result.reason, guard.REASON.TOO_LONG);
  assert.equal(headers['content-disposition'], undefined);
});

test('filenameIsUnsafe rejects dot segments', () => {
  assert.equal(guard.filenameIsUnsafe('..'), true);
  assert.equal(guard.filenameIsUnsafe('ok.txt'), false);
});

test('parseDisposition handles quoted semicolons', () => {
  const parsed = guard.parseDisposition('attachment; filename="a;b.txt"');
  assert.equal(parsed.reason, guard.REASON.OK);
  assert.equal(parsed.params.filename, 'a;b.txt');
});

test('describeReason covers each branch', () => {
  assert.equal(guard.describeReason(guard.REASON.OK), '内容处置方式安全');
  assert.equal(guard.describeReason('other'), '内容处置方式安全');
});
