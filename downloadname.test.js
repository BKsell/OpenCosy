'use strict';

const test = require('node:test');
const assert = require('node:assert');
const D = require('./downloadname');

test('sanitizeDownloadName 剥掉路径组件，只留文件名', () => {
  const r = D.sanitizeDownloadName('../../etc/passwd');
  assert.strictEqual(r.name, 'passwd');
  assert.ok(r.reasons.includes('path-component'));
  const w = D.sanitizeDownloadName('C:\\Users\\x\\evil.exe');
  assert.strictEqual(w.name, 'evil.exe');
});

test('sanitizeDownloadName 拒绝空输入并回落到默认名', () => {
  assert.strictEqual(D.sanitizeDownloadName('').name, D.FALLBACK_NAME);
  assert.strictEqual(D.sanitizeDownloadName(null).name, D.FALLBACK_NAME);
  assert.strictEqual(D.sanitizeDownloadName('   ').name, D.FALLBACK_NAME);
  assert.strictEqual(D.sanitizeDownloadName('', 'pkg.jar').name, 'pkg.jar');
});

test('sanitizeDownloadName 剥掉结尾点与空格', () => {
  assert.strictEqual(D.sanitizeDownloadName('setup.exe...').name, 'setup.exe');
  assert.strictEqual(D.sanitizeDownloadName('setup.exe   ').name, 'setup.exe');
  assert.strictEqual(D.sanitizeDownloadName('a. . .').name, 'a');
});

test('sanitizeDownloadName 去掉禁止字符与控制符', () => {
  assert.strictEqual(D.sanitizeDownloadName('a<b>c:d"e|f?g*h.jar').name, 'abcdefgh.jar');
  assert.strictEqual(D.sanitizeDownloadName('a\u0000b.jar').name, 'ab.jar');
  assert.strictEqual(D.sanitizeDownloadName('a\tb.jar').name, 'ab.jar');
});

test('sanitizeDownloadName 去掉双向控制符与零宽字符', () => {
  const rtl = D.sanitizeDownloadName('invoice\u202egnp.exe');
  assert.strictEqual(rtl.name, 'invoicegnp.exe');
  const zero = D.sanitizeDownloadName('mod\u200b.jar');
  assert.strictEqual(zero.name, 'mod.jar');
  const bom = D.sanitizeDownloadName('\ufeffmod.jar');
  assert.strictEqual(bom.name, 'mod.jar');
});

test('sanitizeDownloadName 给 Windows 保留设备名加前缀', () => {
  assert.strictEqual(D.sanitizeDownloadName('CON').name, '_CON');
  assert.strictEqual(D.sanitizeDownloadName('nul.txt').name, '_nul.txt');
  assert.strictEqual(D.sanitizeDownloadName('LPT9.jar').name, '_LPT9.jar');
  assert.strictEqual(D.sanitizeDownloadName('CONSOLE.txt').name, 'CONSOLE.txt');
});

test('sanitizeDownloadName 按 UTF-8 字节截断且保留扩展名', () => {
  const longStem = '文'.repeat(120);
  const r = D.sanitizeDownloadName(longStem + '.jar');
  assert.ok(Buffer.byteLength(r.name, 'utf8') <= D.MAX_NAME_BYTES);
  assert.ok(r.name.endsWith('.jar'));
  assert.ok(r.reasons.includes('too-long'));
});

test('sanitizeDownloadName 把全禁止字符的名字回落为默认名', () => {
  assert.strictEqual(D.sanitizeDownloadName('<>:"|?*').name, D.FALLBACK_NAME);
});

test('parseContentDisposition 解析普通 filename', () => {
  const r = D.parseContentDisposition('attachment; filename="mod-1.2.3.jar"');
  assert.strictEqual(r.filename, 'mod-1.2.3.jar');
  assert.strictEqual(r.extended, false);
});

test('parseContentDisposition 优先 filename* 并解码 UTF-8', () => {
  const r = D.parseContentDisposition("attachment; filename=fb.bin; filename*=UTF-8''%E4%B8%AD%E6%96%87.jar");
  assert.strictEqual(r.filename, '中文.jar');
  assert.strictEqual(r.extended, true);
});

test('parseContentDisposition 拒绝重复参数', () => {
  const r = D.parseContentDisposition('attachment; filename="a.jar"; filename="b.jar"');
  assert.strictEqual(r.filename, '');
  assert.strictEqual(r.reason, 'duplicate-parameter');
});

test('parseContentDisposition 拒绝未闭合引号与畸形参数', () => {
  assert.strictEqual(D.parseContentDisposition('attachment; filename="abc').reason, 'unterminated-quote');
  assert.strictEqual(D.parseContentDisposition('attachment; filename').reason, 'malformed-parameter');
  assert.strictEqual(D.parseContentDisposition('').reason, 'empty');
  assert.strictEqual(D.parseContentDisposition('x'.repeat(5000)).reason, 'too-long-header');
});

test('parseContentDisposition 拒绝非 UTF-8 / 非 Latin-1 的 ext-value', () => {
  const r = D.parseContentDisposition("attachment; filename*=Shift_JIS''%82%A0.jar");
  assert.strictEqual(r.reason, 'unsupported-charset');
  const bad = D.parseContentDisposition("attachment; filename*=UTF-8''%FF.jar");
  assert.strictEqual(bad.reason, 'bad-encoding');
  const malformed = D.parseContentDisposition("attachment; filename*=UTF-8''a%zz.jar");
  assert.strictEqual(malformed.reason, 'bad-encoding');
});

test('parseContentDisposition 支持 Latin-1 ext-value', () => {
  const r = D.parseContentDisposition("attachment; filename*=ISO-8859-1''caf%E9.jar");
  assert.strictEqual(r.filename, 'café.jar');
});

test('parseContentDisposition 无 filename 参数时返回空', () => {
  const r = D.parseContentDisposition('attachment; size=123');
  assert.strictEqual(r.filename, '');
  assert.strictEqual(r.reason, 'no-filename');
});
