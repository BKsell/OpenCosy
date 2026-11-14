'use strict';

const test = require('node:test');
const assert = require('node:assert');

const guard = require('./pathcontainmentguard_core');

test('inspectPath rejects empty and non-string input', () => {
  assert.strictEqual(guard.inspectPath('C:/base', '').reason, guard.REASON.EMPTY);
  assert.strictEqual(guard.inspectPath('C:/base', null).reason, guard.REASON.EMPTY);
});

test('inspectPath rejects over-long and control-character paths', () => {
  const long = 'a'.repeat(guard.MAX_PATH_LENGTH + 1);
  assert.strictEqual(guard.inspectPath('C:/base', long).reason, guard.REASON.TOO_LONG);
  assert.strictEqual(guard.inspectPath('C:/base', 'a\u0001/b.txt').reason, guard.REASON.CONTROL);
});

test('inspectPath rejects absolute, UNC and drive-relative paths', () => {
  assert.strictEqual(guard.inspectPath('C:/base', '/etc/passwd').reason, guard.REASON.ABSOLUTE);
  assert.strictEqual(guard.inspectPath('C:/base', 'D:/Games/x.exe').reason, guard.REASON.ABSOLUTE);
  assert.strictEqual(guard.inspectPath('C:/base', '//srv/share/x').reason, guard.REASON.UNC);
  assert.strictEqual(guard.inspectPath('C:/base', 'C:evil/x').reason, guard.REASON.DRIVE_RELATIVE);
});

test('inspectPath rejects traversal and encoded traversal', () => {
  assert.strictEqual(guard.inspectPath('C:/base', '../x').reason, guard.REASON.TRAVERSAL);
  assert.strictEqual(guard.inspectPath('C:/base', 'a/../../x').reason, guard.REASON.TRAVERSAL);
  assert.strictEqual(guard.inspectPath('C:/base', '%2e%2e/x').reason, guard.REASON.ENCODED_TRAVERSAL);
  assert.strictEqual(guard.inspectPath('C:/base', 'x%2f..%2fy').reason, guard.REASON.ENCODED_TRAVERSAL);
});

test('inspectPath rejects NTFS alternate data streams', () => {
  assert.strictEqual(guard.inspectPath('C:/base', 'a.txt:payload.exe').reason, guard.REASON.ALT_STREAM);
  assert.strictEqual(guard.inspectPath('C:/base', 'sub/a.txt:zone').reason, guard.REASON.ALT_STREAM);
});

test('inspectPath accepts contained relative paths', () => {
  const r = guard.inspectPath('C:/base', 'sub/ok.txt');
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.strictEqual(r.resolved.toLowerCase(), 'c:/base/sub/ok.txt');
});

test('inspectPath rejects sibling directory escape after join', () => {
  const r = guard.inspectPath('C:/Downloads', 'C:/Downloads-evil/x.exe');
  assert.strictEqual(r.ok, false);
});

test('describeReason renders each reason code', () => {
  for (const code of Object.values(guard.REASON)) {
    const text = guard.describeReason(code);
    assert.strictEqual(typeof text, 'string');
    assert.notStrictEqual(text.length, 0);
  }
});
