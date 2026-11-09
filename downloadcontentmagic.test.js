'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const magicGuard = require('./downloadcontentmagic');

function tempFile(name, bytes) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cosy-magic-'));
  const target = path.join(dir, name);
  fs.writeFileSync(target, bytes);
  return target;
}

test('识别 PE 文件头', () => {
  assert.strictEqual(magicGuard.sniffBuffer(Buffer.from('MZ\x90\x00rest')), magicGuard.MAGIC.PE);
});

test('识别 ZIP 文件头', () => {
  assert.strictEqual(magicGuard.sniffBuffer(Buffer.from('PK\x03\x04rest')), magicGuard.MAGIC.ZIP);
});

test('识别 PDF 文件头', () => {
  assert.strictEqual(magicGuard.sniffBuffer(Buffer.from('%PDF-1.7\n')), magicGuard.MAGIC.PDF);
});

test('识别 PNG 文件头', () => {
  const buf = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  assert.strictEqual(magicGuard.sniffBuffer(buf), magicGuard.MAGIC.PNG);
});

test('识别 HTML 内容', () => {
  assert.strictEqual(magicGuard.sniffBuffer(Buffer.from('  <!DOCTYPE html><html>')), magicGuard.MAGIC.HTML);
});

test('识别 shell 脚本', () => {
  assert.strictEqual(magicGuard.sniffBuffer(Buffer.from('#!/bin/sh\necho hi\n')), magicGuard.MAGIC.SCRIPT);
});

test('未知内容标记 unknown', () => {
  assert.strictEqual(magicGuard.sniffBuffer(Buffer.from('hello world')), magicGuard.MAGIC.UNKNOWN);
});

test('readMagic 读取真实文件', () => {
  const target = tempFile('photo.png', Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  const result = magicGuard.readMagic(target);
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.magic, magicGuard.MAGIC.PNG);
});

test('readMagic 空文件报 too-small', () => {
  const target = tempFile('empty.bin', Buffer.alloc(0));
  const result = magicGuard.readMagic(target);
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.reason, magicGuard.REASON.TOO_SMALL);
});

test('readMagic 不存在文件报 unreadable', () => {
  const result = magicGuard.readMagic(path.join(os.tmpdir(), 'cosy-missing-file.bin'));
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.reason, magicGuard.REASON.UNREADABLE);
});

test('图片扩展名实为 PE 阻断', () => {
  const result = magicGuard.auditDownloadedContent({ name: 'cat.jpg', magic: magicGuard.MAGIC.PE });
  assert.strictEqual(result.action, magicGuard.ACTION.BLOCK);
  assert.strictEqual(result.reason, magicGuard.REASON.EXECUTABLE_DISGUISE);
});

test('PDF 扩展名实为 HTML 阻断', () => {
  const result = magicGuard.auditDownloadedContent({ name: 'invoice.pdf', magic: magicGuard.MAGIC.HTML });
  assert.strictEqual(result.action, magicGuard.ACTION.BLOCK);
  assert.strictEqual(result.reason, magicGuard.REASON.ACTIVE_DISGUISE);
});

test('无扩展名可执行文件阻断', () => {
  const result = magicGuard.auditDownloadedContent({ name: 'blob', magic: magicGuard.MAGIC.ELF });
  assert.strictEqual(result.reason, magicGuard.REASON.EXECUTABLE_DISGUISE);
});

test('声明 image/* 实为脚本阻断', () => {
  const result = magicGuard.auditDownloadedContent({ name: 'a.png', mime: 'image/png', magic: magicGuard.MAGIC.SCRIPT });
  assert.strictEqual(result.reason, magicGuard.REASON.ACTIVE_DISGUISE);
});

test('zip 扩展名但非压缩头告警', () => {
  const result = magicGuard.auditDownloadedContent({ name: 'pack.zip', magic: magicGuard.MAGIC.PNG });
  assert.strictEqual(result.action, magicGuard.ACTION.WARN);
  assert.strictEqual(result.reason, magicGuard.REASON.ARCHIVE_MISMATCH);
});

test('正常 jar 与 zip 文件头放行', () => {
  const result = magicGuard.auditDownloadedContent({ name: 'mod.jar', magic: magicGuard.MAGIC.ZIP });
  assert.strictEqual(result.action, magicGuard.ACTION.OK);
});

test('正常 png 放行', () => {
  const result = magicGuard.auditDownloadedContent({ name: 'logo.png', magic: magicGuard.MAGIC.PNG });
  assert.strictEqual(result.action, magicGuard.ACTION.OK);
});

test('未知类型仅告警', () => {
  const result = magicGuard.auditDownloadedContent({ name: 'notes.txt', magic: magicGuard.MAGIC.UNKNOWN });
  assert.strictEqual(result.action, magicGuard.ACTION.WARN);
  assert.strictEqual(result.reason, magicGuard.REASON.UNKNOWN_TYPE);
});

test('exe 扩展名与 PE 头一致放行', () => {
  const result = magicGuard.auditDownloadedContent({ name: 'setup.exe', magic: magicGuard.MAGIC.PE });
  assert.strictEqual(result.action, magicGuard.ACTION.OK);
});
