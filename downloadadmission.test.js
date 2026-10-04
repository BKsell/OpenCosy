'use strict';

const test = require('node:test');
const assert = require('node:assert');
const admission = require('./downloadadmission');

// 表驱动测试用的 dloadguard 决策常量（与真实 dloadGuard.DECISION 同形）。
const DECISION = { REJECT: 'reject', CONFIRM: 'confirm', WARN: 'warn', ALLOW: 'allow' };

// makeDeps 构造一组可按需覆写的桩依赖，默认全部安全放行、净化只加前缀。
function makeDeps(overrides) {
  const safeHosts = new Set(['example.com', 'files.example.com', 'cdn.test.org']);
  return Object.assign({
    isSafeUrl(u) {
      try { return safeHosts.has(new URL(u).host); } catch { return false; }
    },
    sanitizeFilename(name) {
      // 模拟真实净化：剥掉目录组件，其余保留；空串由内核兜底。
      const base = String(name == null ? '' : name).split(/[\\/]/).pop();
      return base;
    },
    analyzeName(filename, mime) {
      return { decision: DECISION.ALLOW, displayName: '', finalExt: '', risks: [], _mime: mime };
    },
    DECISION,
  }, overrides || {});
}

test('hostOf 解析主机，非法 URL 返回空串', () => {
  assert.strictEqual(admission.hostOf('https://a.b:8443/x'), 'a.b:8443');
  // WHATWG URL 的 .host 对非 ASCII 域返回 punycode，内核只透传不做 IDN 转换。
  assert.strictEqual(admission.hostOf('http://例子.test/'), 'xn--fsqu00a.test');
  assert.strictEqual(admission.hostOf('not a url'), '');
  assert.strictEqual(admission.hostOf(''), '');
});

test('不安全协议 / 地址 -> block-unsafe-url，且不做文件名分析', () => {
  let analyzed = false;
  const deps = makeDeps({
    isSafeUrl: () => false,
    analyzeName: () => { analyzed = true; return { decision: DECISION.ALLOW }; },
  });
  const out = admission.planDownloadAdmission(deps, {
    url: 'file:///C:/windows/system32/x.exe', rawFilename: 'x.exe', mimeType: '',
  });
  assert.strictEqual(out.action, admission.ACTION_BLOCK_UNSAFE);
  assert.strictEqual(analyzed, false);
  assert.strictEqual(out.finalFilename, '');
  assert.strictEqual(out.analysis, null);
});

test('isSafeUrl 抛异常时按不安全处理（不带着未校验 URL 继续）', () => {
  const deps = makeDeps({ isSafeUrl: () => { throw new Error('boom'); } });
  const out = admission.planDownloadAdmission(deps, { url: 'https://example.com/a', rawFilename: 'a' });
  assert.strictEqual(out.action, admission.ACTION_BLOCK_UNSAFE);
});

test('REJECT 档透传，最终文件名仍给出净化结果', () => {
  const deps = makeDeps({
    analyzeName: () => ({
      decision: DECISION.REJECT, displayName: 'evil.exe', finalExt: '.exe',
      risks: [{ id: 'reserved', severity: 'reject', message: '保留设备名' }],
    }),
  });
  const out = admission.planDownloadAdmission(deps, {
    url: 'https://example.com/d', rawFilename: '../../evil.exe', mimeType: 'application/octet-stream',
  });
  assert.strictEqual(out.action, admission.ACTION_REJECT);
  assert.strictEqual(out.finalFilename, 'evil.exe');
  assert.strictEqual(out.analysis.finalExt, '.exe');
  assert.strictEqual(out.host, 'example.com');
});

test('CONFIRM / WARN / 其它默认 ALLOW 三档正确归类', () => {
  const confirmDeps = makeDeps({
    analyzeName: () => ({ decision: DECISION.CONFIRM, displayName: 'invoice.pdf.exe', finalExt: '.exe', risks: [] }),
  });
  assert.strictEqual(
    admission.planDownloadAdmission(confirmDeps, { url: 'https://example.com/f', rawFilename: 'invoice.pdf.exe' }).action,
    admission.ACTION_CONFIRM,
  );

  const warnDeps = makeDeps({
    analyzeName: () => ({ decision: DECISION.WARN, displayName: 'page.html', finalExt: '.html', risks: [] }),
  });
  assert.strictEqual(
    admission.planDownloadAdmission(warnDeps, { url: 'https://example.com/p', rawFilename: 'page.html' }).action,
    admission.ACTION_WARN,
  );

  const allowDeps = makeDeps({
    analyzeName: () => ({ decision: DECISION.ALLOW, displayName: 'note.txt', finalExt: '.txt', risks: [] }),
  });
  assert.strictEqual(
    admission.planDownloadAdmission(allowDeps, { url: 'https://example.com/n', rawFilename: 'note.txt' }).action,
    admission.ACTION_ALLOW,
  );
});

test('displayName 优先于原始名；无 displayName 时回退净化原始名', () => {
  const withDisplay = makeDeps({
    analyzeName: () => ({ decision: DECISION.ALLOW, displayName: 'clean.zip', finalExt: '.zip', risks: [] }),
  });
  const o1 = admission.planDownloadAdmission(withDisplay, {
    url: 'https://example.com/z', rawFilename: 'weird name.zip',
  });
  assert.strictEqual(o1.finalFilename, 'clean.zip');

  const noDisplay = makeDeps({
    analyzeName: () => ({ decision: DECISION.ALLOW, displayName: '', finalExt: '.zip', risks: [] }),
  });
  const o2 = admission.planDownloadAdmission(noDisplay, {
    url: 'https://example.com/z', rawFilename: 'sub/dir/plain.zip',
  });
  assert.strictEqual(o2.finalFilename, 'plain.zip');
});

test('净化结果为空 / 抛异常时兜底为 download', () => {
  const empty = makeDeps({
    sanitizeFilename: () => '',
    analyzeName: () => ({ decision: DECISION.ALLOW, displayName: '', finalExt: '', risks: [] }),
  });
  assert.strictEqual(
    admission.planDownloadAdmission(empty, { url: 'https://example.com/x', rawFilename: '///' }).finalFilename,
    'download',
  );

  const throwing = makeDeps({
    sanitizeFilename: () => { throw new Error('fs?'); },
    analyzeName: () => ({ decision: DECISION.ALLOW, displayName: 'a', finalExt: '', risks: [] }),
  });
  assert.strictEqual(
    admission.planDownloadAdmission(throwing, { url: 'https://example.com/x', rawFilename: 'a' }).finalFilename,
    'download',
  );
});

test('analyzeName 自身抛异常时按最严 REJECT 处理，绝不带未净化名落盘', () => {
  const deps = makeDeps({ analyzeName: () => { throw new Error('parser'); } });
  const out = admission.planDownloadAdmission(deps, {
    url: 'https://example.com/x', rawFilename: 'a.exe', mimeType: 'application/x-msdownload',
  });
  assert.strictEqual(out.action, admission.ACTION_REJECT);
  assert.ok(out.analysis);
});

test('缺失 / 空输入不抛异常并走安全分支', () => {
  const deps = makeDeps();
  const out = admission.planDownloadAdmission(deps, {});
  assert.strictEqual(out.action, admission.ACTION_BLOCK_UNSAFE);
  assert.strictEqual(out.url, '');
  assert.strictEqual(out.host, '');

  const partial = admission.planDownloadAdmission(deps, { url: 'https://example.com/f' });
  assert.strictEqual(partial.rawFilename, '');
  assert.strictEqual(partial.mimeType, undefined);
});

test('输出对象不共享可变状态（多次调用互不污染）', () => {
  const deps = makeDeps({
    analyzeName(filename) {
      return { decision: DECISION.ALLOW, displayName: String(filename || ''), finalExt: '', risks: [] };
    },
  });
  const a = admission.planDownloadAdmission(deps, { url: 'https://example.com/a', rawFilename: 'a.bin' });
  const b = admission.planDownloadAdmission(deps, { url: 'https://cdn.test.org/b', rawFilename: 'b.bin' });
  assert.strictEqual(a.finalFilename, 'a.bin');
  assert.strictEqual(b.finalFilename, 'b.bin');
  assert.strictEqual(a.host, 'example.com');
  assert.strictEqual(b.host, 'cdn.test.org');
  assert.notStrictEqual(a.analysis, b.analysis);
});
