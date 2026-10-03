'use strict';

// dloadguard.test.js —— 用 node:test 覆盖下载文件名伪装分析的全部判定分支。

const test = require('node:test');
const assert = require('node:assert/strict');
const dlg = require('./dloadguard');
const { DECISION, analyzeDownloadName, sanitizeName, analyzeMimeMismatch,
  extensionChain, finalExtOf } = dlg;

test('普通文档直接放行', () => {
  const r = analyzeDownloadName('季度报表.pdf');
  assert.equal(r.decision, DECISION.ALLOW);
  assert.equal(r.finalExt, 'pdf');
});

test('exe 必须确认', () => {
  const r = analyzeDownloadName('installer.exe');
  assert.equal(r.decision, DECISION.CONFIRM);
  assert.ok(r.risks.some(x => x.id === 'executable-ext'));
});

test('scr/批处理/脚本类必须确认', () => {
  for (const ext of ['scr', 'bat', 'cmd', 'ps1', 'vbs', 'msi', 'lnk']) {
    assert.equal(analyzeDownloadName(`a.${ext}`).decision, DECISION.CONFIRM, ext);
  }
});

test('危险扩展名夹在中段、末尾挂 pdf 面具 → 双扩展伪装确认', () => {
  const r = analyzeDownloadName('发票.exe.pdf');
  assert.equal(r.decision, DECISION.CONFIRM);
  assert.ok(r.risks.some(x => x.id === 'double-extension-spoof'), '应命中双扩展伪装');
});

test('经典 invoice.pdf.exe 仍按可执行确认', () => {
  const r = analyzeDownloadName('invoice.pdf.exe');
  assert.equal(r.decision, DECISION.CONFIRM);
  assert.ok(r.risks.some(x => x.id === 'executable-ext'));
});

test('RTL 覆盖字符触发确认', () => {
  const r = analyzeDownloadName('file.pdf\u202Eexe.scr');
  assert.equal(r.decision, DECISION.CONFIRM);
  assert.ok(r.risks.some(x => x.id === 'rtl-override'));
  assert.ok(!r.displayName.includes('\u202E'), '净化后不应保留反转符');
});

test('结尾点号与空格被剥除', () => {
  const r1 = sanitizeName('notes.txt.');
  assert.equal(r1.name, 'notes.txt');
  const r2 = sanitizeName('run.exe ');
  assert.equal(r2.name, 'run.exe');
});

test('路径组件被剥离', () => {
  assert.equal(sanitizeName('..\\..\\evil.exe').name, 'evil.exe');
  assert.equal(sanitizeName('/home/user/a.pdf').name, 'a.pdf');
});

test('空名与只有点号拒绝', () => {
  assert.equal(sanitizeName('').rejected, true);
  assert.equal(sanitizeName('...').rejected, true);
  assert.equal(analyzeDownloadName('').decision, DECISION.REJECT);
});

test('Windows 保留设备名加前缀', () => {
  const r = sanitizeName('CON.txt');
  assert.equal(r.name, '_CON.txt');
  assert.ok(analyzeDownloadName('nul').risks.some(x => x.id === 'reserved-name'));
});

test('控制字符触发确认', () => {
  const r = analyzeDownloadName('a\x00.exe');
  assert.equal(r.decision, DECISION.CONFIRM);
  assert.ok(r.risks.some(x => x.id === 'control-char'));
});

test('重复可执行扩展名可疑', () => {
  const r = analyzeDownloadName('x.exe.exe');
  assert.ok(r.risks.some(x => x.id === 'repeated-executable-ext'));
});

test('MIME 可执行但扩展名是 pdf → 伪装确认', () => {
  const risk = analyzeMimeMismatch('application/x-msdownload', '报表.pdf');
  assert.ok(risk);
  assert.equal(risk.severity, DECISION.CONFIRM);
  const r = analyzeDownloadName('报表.pdf', 'application/x-msdownload');
  assert.ok(r.risks.some(x => x.id === 'mime-executable-mask'));
});

test('MIME 与扩展名一致都是可执行 → 不报 MIME 伪装', () => {
  assert.equal(analyzeMimeMismatch('application/x-msdownload', 'a.exe'), null);
});

test('无 MIME 不报错', () => {
  assert.equal(analyzeMimeMismatch('', 'a.pdf'), null);
  assert.equal(analyzeDownloadName('a.pdf').decision, DECISION.ALLOW);
});

test('iso 容器给出 MOTW 警告但不阻断', () => {
  const r = analyzeDownloadName('disk.iso');
  assert.equal(r.decision, DECISION.WARN);
  assert.ok(r.risks.some(x => x.id === 'container-motw'));
});

test('本地 html/svg 警告', () => {
  assert.ok(analyzeDownloadName('page.html').risks.some(x => x.id === 'local-html'));
  assert.ok(analyzeDownloadName('img.svg').risks.some(x => x.id === 'local-html'));
});

test('扩展名链解析正确', () => {
  assert.deepEqual(extensionChain('a.b.c.pdf').chain, ['b', 'c', 'pdf']);
  assert.equal(finalExtOf('photo.JPEG'), 'jpeg');
  assert.equal(finalExtOf('noext'), '');
});

test('hta 必须确认', () => {
  assert.equal(analyzeDownloadName('app.hta').decision, DECISION.CONFIRM);
});

test('净化后零宽字符被移除', () => {
  const r = sanitizeName('a\u200Bb.txt');
  assert.equal(r.name, 'ab.txt');
});

test('普通图片无警告放行', () => {
  const r = analyzeDownloadName('photo.png', 'image/png');
  assert.equal(r.decision, DECISION.ALLOW);
});
