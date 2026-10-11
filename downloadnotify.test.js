'use strict';

const test = require('node:test');
const assert = require('node:assert');
const notify = require('./downloadnotify');

// makeDeps 构造可覆写的桩依赖：默认平台支持、记录 showNotification 调用。
function makeDeps(overrides) {
  const calls = [];
  const deps = {
    isSupported: () => true,
    showNotification(opts, onClick) {
      calls.push({ opts, onClick });
    },
    openPath(p) {
      calls.push({ opened: p });
    },
    focusWindow() {
      calls.push({ focused: true });
    },
  };
  return { deps: Object.assign(deps, overrides || {}), calls };
}

test('完成通知：标题为下载完成，正文含文件名与大小，silent 为真', () => {
  const note = notify.buildDownloadNotification('complete', {
    filename: 'modpack.zip', sizeBytes: 2048, savePath: 'C:\\x\\modpack.zip',
  });
  assert.strictEqual(note.title, '下载完成');
  assert.strictEqual(note.body, 'modpack.zip · 2.0 KB');
  assert.strictEqual(note.silent, true);
});

test('失败通知：标题为下载失败，正文含文件名与一句话详情，非 silent', () => {
  const note = notify.buildDownloadNotification('error', {
    filename: 'server.jar', errorMessage: '网络超时',
  });
  assert.strictEqual(note.title, '下载失败');
  assert.strictEqual(note.body, 'server.jar · 网络超时');
  assert.strictEqual(note.silent, false);
});

test('控制字符剥除：文件名里的换行与 ESC 序列不会进入通知', () => {
  const evil = 'evil\x1b[31m.jar\n';
  const note = notify.buildDownloadNotification('complete', { filename: evil });
  assert.ok(!note.body.includes('\n'));
  assert.ok(!note.body.includes('\x1b'));
  assert.ok(!note.body.includes('[31m'));
  assert.strictEqual(note.body, 'evil.jar');
});

test('长度截断：超长文件名压到上限且不切断 UTF-8 字符', () => {
  const longName = 'x'.repeat(200) + '相.jar';
  const note = notify.buildDownloadNotification('complete', { filename: longName });
  assert.ok(Buffer.byteLength(note.body, 'utf8') <= 300);
  // 不应出现孤立的高位字节（UTF-8 被切断的特征）。
  for (const ch of note.body) {
    const cp = ch.codePointAt(0);
    assert.ok(cp >= 0x20 && cp !== 0x7f, `出现控制字符 U+${cp.toString(16)}`);
  }
});

test('大小格式化：负数与非法输入返回空串', () => {
  assert.strictEqual(notify.formatSize(0), '0 B');
  assert.strictEqual(notify.formatSize(1024), '1.0 KB');
  assert.strictEqual(notify.formatSize(-1), '');
  assert.strictEqual(notify.formatSize('abc'), '');
});

test('平台不支持时不弹通知且返回 false', () => {
  const { deps } = makeDeps({ isSupported: () => false });
  const ok = notify.notifyDownload('complete', deps, { filename: 'a.bin' });
  assert.strictEqual(ok, false);
});

test('非法 kind 或缺少文件名时不弹通知', () => {
  const { deps, calls } = makeDeps();
  assert.strictEqual(notify.notifyDownload('weird', deps, { filename: 'a.bin' }), false);
  assert.strictEqual(notify.notifyDownload('complete', deps, {}), false);
  assert.strictEqual(calls.length, 0);
});

test('完成通知点击打开文件，失败通知点击聚焦窗口', () => {
  const { deps, calls } = makeDeps();
  const ok = notify.notifyDownload('complete', deps, {
    filename: 'a.zip', savePath: 'C:\\dl\\a.zip',
  });
  assert.strictEqual(ok, true);
  const shown = calls.find(c => c.opts && c.opts.title === '下载完成');
  assert.ok(shown && shown.opts.body.includes('a.zip'));
  assert.ok(typeof shown.onClick === 'function');
  shown.onClick();
  assert.ok(calls.some(c => c.opened === 'C:\\dl\\a.zip'));

  const { deps: d2, calls: c2 } = makeDeps();
  notify.notifyDownload('error', d2, { filename: 'b.jar', errorMessage: '拒绝' });
  const shown2 = c2.find(c => c.opts && c.opts.title === '下载失败');
  assert.ok(shown2 && typeof shown2.onClick === 'function');
  shown2.onClick();
  assert.ok(c2.some(c => c.focused === true));
  // 失败通知不自动重试：没有 openPath 调用。
  assert.ok(!c2.some(c => c.opened));
});

test('完成通知缺 savePath 时仍弹通知但不绑定点击动作', () => {
  const { deps, calls } = makeDeps();
  const ok = notify.notifyDownload('complete', deps, { filename: 'c.bin' });
  assert.strictEqual(ok, true);
  const shown = calls.find(c => c.opts && c.opts.title === '下载完成');
  assert.ok(shown && shown.onClick === null);
});
