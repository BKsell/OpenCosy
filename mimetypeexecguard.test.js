'use strict';

const nodeTest = require('node:test');
const assert = require('node:assert');
const guard = require('./mimetypeexecguard');

const { REASON, evaluateContentDisposition, applyContentDispositionGuard, describeReason } = guard;

nodeTest.test('ordinary html response is untouched', () => {
  const headers = { 'content-type': ['text/html; charset=utf-8'] };
  const verdict = evaluateContentDisposition(headers, { resourceType: 'mainFrame' });
  assert.equal(verdict.action, 'allow');
  assert.equal(verdict.reason, REASON.OK);
});

nodeTest.test('exe inline on top level is forced to attachment', () => {
  const headers = { 'content-type': ['application/x-msdownload'] };
  const result = applyContentDispositionGuard(headers, { resourceType: 'mainFrame' });
  assert.equal(result.changed, true);
  assert.equal(result.verdict.reason, REASON.EXECUTABLE_INLINE);
  assert.deepEqual(headers['Content-Type'], ['application/octet-stream']);
  assert.deepEqual(headers['Content-Disposition'], ['attachment']);
  assert.deepEqual(headers['X-Content-Type-Options'], ['nosniff']);
});

nodeTest.test('exe already attachment is allowed', () => {
  const headers = {
    'content-type': ['application/x-msdownload'],
    'content-disposition': ['attachment; filename="setup.exe"'],
  };
  const verdict = evaluateContentDisposition(headers, { resourceType: 'mainFrame' });
  assert.equal(verdict.action, 'allow');
});

nodeTest.test('jar served inline is forced to download', () => {
  const headers = { 'content-type': ['application/java-archive'] };
  const verdict = evaluateContentDisposition(headers, { resourceType: 'subFrame' });
  assert.equal(verdict.reason, REASON.ARCHIVE_INLINE);
});

nodeTest.test('zip on subresource stays as-is', () => {
  const headers = { 'content-type': ['application/zip'] };
  const verdict = evaluateContentDisposition(headers, { resourceType: 'xhr' });
  assert.equal(verdict.action, 'allow');
});

nodeTest.test('disposition control characters are stripped', () => {
  const headers = { 'content-disposition': ['attachment; filename="a\r\nSet-Cookie: x"'] };
  const result = applyContentDispositionGuard(headers, { resourceType: 'mainFrame' });
  assert.equal(result.verdict.reason, REASON.HEADER_INJECTION);
  assert.equal(headers['Content-Disposition'], undefined);
});

nodeTest.test('unknown disposition type is stripped', () => {
  const headers = { 'content-disposition': ['form-data; name="f"'] };
  const result = applyContentDispositionGuard(headers, { resourceType: 'mainFrame' });
  assert.equal(result.verdict.reason, REASON.BAD_DISPOSITION);
  assert.equal(headers['Content-Disposition'], undefined);
});

nodeTest.test('missing content type is allowed', () => {
  assert.equal(evaluateContentDisposition({}, { resourceType: 'mainFrame' }).action, 'allow');
});

nodeTest.test('type parameters are ignored when matching', () => {
  const headers = { 'content-type': ['application/x-msdownload; charset=binary'] };
  assert.equal(evaluateContentDisposition(headers, { resourceType: 'mainFrame' }).reason, REASON.EXECUTABLE_INLINE);
});

nodeTest.test('case insensitive header lookup works', () => {
  const headers = { 'CONTENT-TYPE': ['application/x-msi'] };
  assert.equal(evaluateContentDisposition(headers, { resourceType: 'mainFrame' }).reason, REASON.EXECUTABLE_INLINE);
});

nodeTest.test('string header values are accepted', () => {
  const headers = { 'content-type': 'application/x-executable' };
  assert.equal(evaluateContentDisposition(headers, { resourceType: 'mainFrame' }).reason, REASON.EXECUTABLE_INLINE);
});

nodeTest.test('apply keeps unrelated headers', () => {
  const headers = { 'content-type': ['application/x-msdownload'], 'cache-control': ['no-store'] };
  applyContentDispositionGuard(headers, { resourceType: 'mainFrame' });
  assert.deepEqual(headers['cache-control'], ['no-store']);
});

nodeTest.test('describeReason covers every reason', () => {
  for (const reason of Object.values(REASON)) {
    assert.ok(describeReason(reason).length > 0, reason);
  }
});
