'use strict';

// filesystemaccessguard.test.js —— 选择器门、文件名穿越/设备名/可执行扩展、
// MIME 伪装、句柄上限、写入大小与目录深度/条目。

const test = require('node:test');
const assert = require('node:assert/strict');
const fa = require('./filesystemaccessguard');
const {
  FileSystemAccessGuard, FA_REASON, defaultFsPolicy,
  validateName, isReservedDeviceName, acceptMismatch, extOfName,
} = fa;

const ORIGIN = 'https://editor.example.com';
function ctx(over) {
  return Object.assign({
    origin: ORIGIN, isSecureContext: true, hasUserGesture: true, hasFocus: true,
    isBackground: false, blocked: false, now: 0,
  }, over || {});
}

test('扩展名/词干提取', () => {
  assert.equal(extOfName('a.tar.gz'), 'gz');
  assert.equal(extOfName('noext'), '');
  assert.equal(extOfName('trailing.'), '');
});

test('保留设备名识别', () => {
  assert.ok(isReservedDeviceName('CON'));
  assert.ok(isReservedDeviceName('nul.txt'));
  assert.ok(isReservedDeviceName('COM1'));
  assert.ok(isReservedDeviceName('lpt9.log'));
  assert.ok(!isReservedDeviceName('composer'));
  assert.ok(!isReservedDeviceName('normal.txt'));
});

test('正常文件名通过', () => {
  assert.equal(validateName('report-2026_最终.docx', defaultFsPolicy()), '');
});

test('穿越/分隔/盘符拒绝', () => {
  assert.equal(validateName('../evil', defaultFsPolicy()), FA_REASON.PATH_TRAVERSAL);
  assert.equal(validateName('a/b.txt', defaultFsPolicy()), FA_REASON.PATH_TRAVERSAL);
  assert.equal(validateName('a\\b.txt', defaultFsPolicy()), FA_REASON.PATH_TRAVERSAL);
  assert.equal(validateName('C:evil', defaultFsPolicy()), FA_REASON.PATH_TRAVERSAL);
});

test('控制字符/末尾点空格拒绝', () => {
  assert.equal(validateName('a\x00.txt', defaultFsPolicy()), FA_REASON.CONTROL_CHAR);
  assert.equal(validateName('evil.', defaultFsPolicy()), FA_REASON.BAD_SUGGESTED_NAME);
  assert.equal(validateName('evil ', defaultFsPolicy()), FA_REASON.BAD_SUGGESTED_NAME);
});

test('可执行扩展拒绝', () => {
  assert.equal(validateName('payload.exe', defaultFsPolicy()), FA_REASON.EXECUTABLE_EXTENSION);
  assert.equal(validateName('x.SCR', defaultFsPolicy()), FA_REASON.EXECUTABLE_EXTENSION);
  assert.equal(validateName('a.ps1', defaultFsPolicy()), FA_REASON.EXECUTABLE_EXTENSION);
});

test('accept MIME 与可执行扩展不符', () => {
  assert.ok(acceptMismatch({ 'image/png': ['.exe'] }));
  assert.ok(!acceptMismatch({ 'image/png': ['.png'] }));
});

test('非安全/无手势/失焦/后台拒绝选择器', () => {
  const g = new FileSystemAccessGuard();
  assert.equal(g.decideSavePicker(ctx({ isSecureContext: false }), 'a.txt').reason, FA_REASON.INSECURE_CONTEXT);
  assert.equal(g.decideSavePicker(ctx({ hasUserGesture: false }), 'a.txt').reason, FA_REASON.NO_GESTURE);
  assert.equal(g.decideSavePicker(ctx({ hasFocus: false }), 'a.txt').reason, FA_REASON.NOT_FOCUSED);
  assert.equal(g.decideSavePicker(ctx({ isBackground: true }), 'a.txt').reason, FA_REASON.BACKGROUND);
});

test('选择器节流', () => {
  const g = new FileSystemAccessGuard();
  assert.equal(g.decideSavePicker(ctx({ now: 0 }), 'a.txt').decision, 'prompt');
  assert.equal(g.decideSavePicker(ctx({ now: 1000 }), 'b.txt').reason, FA_REASON.PICKER_THROTTLED);
});

test('保存危险名拒绝且不记节流', () => {
  const g = new FileSystemAccessGuard();
  assert.equal(g.decideSavePicker(ctx({ now: 0 }), 'x.exe').reason, FA_REASON.EXECUTABLE_EXTENSION);
  assert.equal(g.decideSavePicker(ctx({ now: 0 }), 'ok.txt').decision, 'prompt');
});

test('句柄数量上限', () => {
  const g = new FileSystemAccessGuard();
  for (let i = 0; i < 8; i++) assert.equal(g.registerHandle(ORIGIN, 'h' + i).ok, true);
  assert.equal(g.registerHandle(ORIGIN, 'h9').ok, false);
  g.revokeHandle(ORIGIN, 'h0');
  assert.equal(g.registerHandle(ORIGIN, 'h9').ok, true);
});

test('未登记句柄写入拒绝', () => {
  const g = new FileSystemAccessGuard();
  assert.equal(g.decideWrite(ORIGIN, 'ghost', 'a.txt', 10, 0).reason, FA_REASON.HANDLE_REVOKED);
});

test('超大写入与目录过深拒绝', () => {
  const g = new FileSystemAccessGuard();
  g.registerHandle(ORIGIN, 'h1');
  assert.equal(g.decideWrite(ORIGIN, 'h1', 'a.bin', 201 * 1024 * 1024, 0).reason, FA_REASON.WRITE_TOO_LARGE);
  assert.equal(g.decideWrite(ORIGIN, 'h1', 'a.bin', 10, 9).reason, FA_REASON.DIRECTORY_TOO_DEEP);
  assert.equal(g.decideWrite(ORIGIN, 'h1', 'a.bin', 10, 8).allowed, true);
});

test('目录条目上限', () => {
  const g = new FileSystemAccessGuard();
  assert.equal(g.decideDirectoryEntry(ORIGIN, 5001).allowed, false);
  assert.equal(g.decideDirectoryEntry(ORIGIN, 5000).allowed, true);
});
