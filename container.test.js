'use strict';

// container.test.js —— 容器风险内核：宏 Office/老式 Office/自解压/归档分类、
// MOTW 不继承提示、解压重打标规划、上限截断、打开决策。

const test = require('node:test');
const assert = require('node:assert/strict');
const ct = require('./container');

test('宏 Office 文档判为 confirm', () => {
  for (const f of ['invoice.docm', 'table.xlsm', 'deck.pptm', 'addin.xlam']) {
    const c = ct.classifyContainer(f);
    assert.equal(c.risk, ct.RISK_CONFIRM, `${f} 应 confirm`);
    assert.ok(c.reasons.includes('macro-enabled-office-document'));
  }
});

test('老式 Office 二进制（可含宏）判为 confirm', () => {
  for (const f of ['a.doc', 'b.xls', 'c.ppt', 'd.pps']) {
    assert.equal(ct.classifyContainer(f).risk, ct.RISK_CONFIRM, f);
  }
});

test('普通新式无宏 Office（docx/xlsx/pptx）不判容器风险', () => {
  for (const f of ['a.docx', 'b.xlsx', 'c.pptx']) {
    assert.equal(ct.classifyContainer(f).kind, ct.KIND_NONE, f);
  }
});

test('自解压 / 安装器判为 confirm', () => {
  assert.equal(ct.classifyContainer('setup.exe').kind, ct.KIND_SELF_EXTRACTING);
  assert.equal(ct.classifyContainer('patch.msi').risk, ct.RISK_CONFIRM);
});

test('普通归档判为 warn 并带 MOTW 不继承原因', () => {
  const c = ct.classifyContainer('photos.zip');
  assert.equal(c.kind, ct.KIND_ARCHIVE);
  assert.equal(c.risk, ct.RISK_WARN);
  assert.ok(c.reasons.includes('archive-mark-of-the-web-not-inherited'));
});

test('磁盘镜像额外带自动挂载原因', () => {
  const c = ct.classifyContainer('game.iso');
  assert.equal(c.kind, ct.KIND_ARCHIVE);
  assert.ok(c.reasons.includes('disk-image-auto-mount'));
});

test('rar/7z/tar/gz/cab 等都识别为归档', () => {
  for (const f of ['a.rar', 'b.7z', 'c.tar.gz', 'd.cab', 'e.img']) {
    assert.equal(ct.isContainerExt(f), true, f);
  }
});

test('非容器文件返回 none / allow', () => {
  assert.equal(ct.classifyContainer('notes.txt').kind, ct.KIND_NONE);
  assert.equal(ct.classifyContainer('image.png').risk, ct.RISK_ALLOW);
  assert.equal(ct.isContainerExt('x.txt'), false);
});

test('扩展名取末段且大小写不敏感，含路径也正确', () => {
  assert.equal(ct.extLower('C:\\DL\\X.DOCM'), '.docm');
  assert.equal(ct.extLower('/tmp/a.7z'), '.7z');
  assert.equal(ct.extLower('.bashrc'), '');
});

test('处置说明覆盖各类容器', () => {
  assert.match(ct.describeContainerRisk(ct.classifyContainer('a.xlsm')), /宏|活动内容/);
  assert.match(ct.describeContainerRisk(ct.classifyContainer('a.zip')), /解压|压缩包/);
  assert.match(ct.describeContainerRisk(ct.classifyContainer('a.exe')), /可执行|安装/);
  assert.equal(ct.describeContainerRisk(ct.classifyContainer('a.txt')), '');
});

test('解压重打标规划：可执行/宏/嵌套容器被收，静态文件不收', () => {
  const plan = ct.planExtractionMotw([
    'readme.txt', 'img/logo.png', 'bin/app.exe', 'scripts/run.bat',
    'macro/budget.xlsm', 'nested/inner.rar', 'old/data.doc',
  ]);
  assert.deepEqual(plan.stamped.sort(), [
    'bin/app.exe', 'macro/budget.xlsm', 'nested/inner.rar',
    'old/data.doc', 'scripts/run.bat',
  ]);
  assert.equal(plan.stampedCount, 5);
  assert.equal(plan.truncated, false);
});

test('解压规划规整反斜杠 / 尾部斜杠目录', () => {
  const plan = ct.planExtractionMotw(['sub\\tool.cmd', 'folder/']);
  assert.deepEqual(plan.stamped, ['sub/tool.cmd']);
});

test('解压规划忽略非字符串 / 空项', () => {
  const plan = ct.planExtractionMotw([null, '', 42, 'ok.exe']);
  assert.deepEqual(plan.stamped, ['ok.exe']);
  assert.equal(plan.scanned, 4);
});

test('解压规划对超量条目截断并标记 truncated', () => {
  const many = [];
  for (let i = 0; i < ct.MAX_EXTRACTION_ENTRIES + 10; i++) many.push(i + '.txt');
  const plan = ct.planExtractionMotw(many);
  assert.equal(plan.truncated, true);
  assert.equal(plan.scanned, ct.MAX_EXTRACTION_ENTRIES);
});

test('打开决策：来自互联网的普通归档也要确认', () => {
  assert.equal(ct.openContainerDecision({ filename: 'a.zip', fromWeb: true }), ct.RISK_CONFIRM);
});

test('打开决策：本地普通归档放行，本地宏文档轻警告', () => {
  assert.equal(ct.openContainerDecision({ filename: 'a.zip', fromWeb: false }), ct.RISK_ALLOW);
  assert.equal(ct.openContainerDecision({ filename: 'a.xlsm', fromWeb: false }), ct.RISK_WARN);
});

test('打开决策：来自互联网的自解压/宏文档确认', () => {
  assert.equal(ct.openContainerDecision({ filename: 'a.exe', fromWeb: true }), ct.RISK_CONFIRM);
  assert.equal(ct.openContainerDecision({ filename: 'a.doc', fromWeb: true }), ct.RISK_CONFIRM);
});

test('打开决策：非容器一律 allow', () => {
  assert.equal(ct.openContainerDecision({ filename: 'a.txt', fromWeb: true }), ct.RISK_ALLOW);
});
