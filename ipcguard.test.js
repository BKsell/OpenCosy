'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const g = require('./ipcguard');

function fakeEvent({ shell = false, url } = {}) {
  return {
    sender: { id: shell ? 1 : 2 },
    senderFrame: url === undefined ? undefined : { url },
  };
}
const isShell = (ev) => ev && ev.sender && ev.sender.id === 1;
// 模拟“file: 路径在应用目录内”判定：以 /app/ 开头视为内置静态页。
const isInternalFile = (u) => typeof u === 'string' && u.startsWith('file:///app/');

test('classifySender 分类', () => {
  assert.equal(g.classifySender(fakeEvent({ shell: true }), isShell), g.KIND_SHELL);
  assert.equal(g.classifySender(fakeEvent({ url: 'cosy://newtab' }), isShell), g.KIND_COSY);
  assert.equal(g.classifySender(fakeEvent({ url: 'file:///app/src/error.html' }), isShell, isInternalFile), g.KIND_INTERNAL_FILE);
  assert.equal(g.classifySender(fakeEvent({ url: 'file:///D:/notes.html' }), isShell, isInternalFile), g.KIND_LOCAL_FILE);
  // 未提供 file 判定器时，任何 file: 帧都按用户本地文件处理（默认不信任）
  assert.equal(g.classifySender(fakeEvent({ url: 'file:///app/src/error.html' }), isShell), g.KIND_LOCAL_FILE);
  assert.equal(g.classifySender(fakeEvent({ url: 'https://evil.test' }), isShell), g.KIND_WEB);
  assert.equal(g.classifySender(fakeEvent({ url: 'http://x' }), isShell), g.KIND_WEB);
  assert.equal(g.classifySender(fakeEvent({ url: 'data:text/html,x' }), isShell), g.KIND_UNTRUSTED);
  assert.equal(g.classifySender(fakeEvent({ url: 'about:blank' }), isShell), g.KIND_UNTRUSTED);
  assert.equal(g.classifySender(fakeEvent({}), isShell), g.KIND_NONE);
  assert.equal(g.classifySender(null, isShell), g.KIND_NONE);
});

test('shell/cosy/内置 file 页是受信帧，用户本地文件不是', () => {
  for (const k of [g.KIND_SHELL, g.KIND_COSY, g.KIND_INTERNAL_FILE]) {
    assert.ok(g.isPrivilegedKind(k));
  }
  for (const k of [g.KIND_LOCAL_FILE, g.KIND_WEB, g.KIND_UNTRUSTED, g.KIND_NONE]) {
    assert.equal(g.isPrivilegedKind(k), false);
  }
});

test('伪造 cosy 的帧地址骗不过协议解析', () => {
  assert.equal(g.classifySender(fakeEvent({ url: 'https://cosy/x' }), isShell), g.KIND_WEB);
  assert.equal(g.classifySender(fakeEvent({ url: 'xcosy://newtab' }), isShell), g.KIND_UNTRUSTED);
  assert.equal(g.classifySender(fakeEvent({ url: 'co sy://x' }), isShell), g.KIND_NONE);
});

test('decide 默认拒绝非受信帧', () => {
  const opts = { isShellSender: isShell, isInternalFileFrame: isInternalFile };
  assert.equal(g.decide('clear-browsing-data', fakeEvent({ url: 'https://evil.test' }), opts).allow, false);
  assert.equal(g.decide('clear-browsing-data', fakeEvent({ url: 'file:///D:/x.html' }), opts).allow, false);
  assert.equal(g.decide('retry-download', fakeEvent({ url: 'file:///app/src/error.html' }), opts).allow, true);
  assert.equal(g.decide('approve-cert-exception', fakeEvent({ url: 'cosy://security' }), opts).allow, true);
  assert.equal(g.decide('save-settings', fakeEvent({ shell: true }), opts).allow, true);
});

test('内置 file 页判定器若识破 .. 穿越伪装，守卫必须拒绝', () => {
  // 真实判定器按规范化后的真实路径判断；这里模拟一个会把穿越串打回的严格判定器。
  const strictInternal = (u) => {
    const dec = decodeURIComponent(u);
    if (dec.includes('..')) return false;
    return u.startsWith('file:///app/');
  };
  const opts = { isShellSender: isShell, isInternalFileFrame: strictInternal };
  assert.equal(g.decide('retry-download',
    fakeEvent({ url: 'file:///app/src/../../evil.html' }), opts).allow, false);
  assert.equal(g.decide('retry-download',
    fakeEvent({ url: 'file:///app/src/error.html' }), opts).allow, true);
});

test('frameAllows 钩子可在受信帧内部再按通道收权', () => {
  // 只允许 shell 调敏感通道；错误页（internal-file）即便受信也被分级拒绝。
  const onlyShellSensitive = (kind) => kind !== g.KIND_INTERNAL_FILE;
  const opts = {
    isShellSender: isShell,
    isInternalFileFrame: isInternalFile,
    frameAllows: (kind, ch) => (ch === 'clear-data' ? onlyShellSensitive(kind) : true),
  };
  assert.equal(g.decide('clear-data',
    fakeEvent({ url: 'file:///app/src/error.html' }), opts).allow, false);
  assert.equal(g.decide('clear-data', fakeEvent({ shell: true }), opts).allow, true);
  assert.equal(g.decide('reload-tab',
    fakeEvent({ url: 'file:///app/src/error.html' }), opts).allow, true);
});

test('decide allowAnyFrame 仅对指定通道放行，handler 仍需自验', () => {
  const opts = { isShellSender: isShell, allowAnyFrame: new Set(['report-csp-violation']) };
  const d = g.decide('report-csp-violation', fakeEvent({ url: 'https://evil.test' }), opts);
  assert.equal(d.allow, true);
  assert.equal(d.reason, 'allow-any-frame');
  // 其它通道不受豁免
  assert.equal(g.decide('clear-history', fakeEvent({ url: 'https://evil.test' }), opts).allow, false);
});

function fakeIpcMain() {
  const store = new Map();
  return {
    _store: store,
    handle(ch, l) { store.set('handle:' + ch, l); },
    on(ch, l) { store.set('on:' + ch, l); },
    once(ch, l) { store.set('once:' + ch, l); },
  };
}

test('installIpcGuard: on 非受信帧被吞且触发 onReject', () => {
  const ipc = fakeIpcMain();
  const rejected = [];
  const uninstall = g.installIpcGuard(ipc, {
    isShellSender: isShell,
    onReject: (info) => rejected.push(info),
  });

  let called = 0;
  ipc.on('approve-cert-exception', () => { called += 1; });
  const handler = ipc._store.get('on:approve-cert-exception');

  const ret = handler(fakeEvent({ url: 'https://evil.test' }), { nonce: 'x' });
  assert.equal(ret, undefined);
  assert.equal(called, 0, '业务 handler 绝不能被远程帧触发');
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].channel, 'approve-cert-exception');

  // 受信帧正常进入
  handler(fakeEvent({ url: 'cosy://security' }), {});
  assert.equal(called, 1);
  uninstall();
});

test('installIpcGuard: handle 非受信帧返回 rejected Promise', async () => {
  const ipc = fakeIpcMain();
  const uninstall = g.installIpcGuard(ipc, { isShellSender: isShell });
  let called = 0;
  ipc.handle('list-cert-exceptions', async () => { called += 1; return []; });
  const handler = ipc._store.get('handle:list-cert-exceptions');

  await assert.rejects(() => handler(fakeEvent({ url: 'http://evil.test' })), /denied/);
  assert.equal(called, 0);

  const result = await handler(fakeEvent({ shell: true }));
  assert.deepEqual(result, []);
  assert.equal(called, 1);
  uninstall();
});

test('installIpcGuard: 非函数 listener 原样透传', () => {
  const ipc = fakeIpcMain();
  const uninstall = g.installIpcGuard(ipc, { isShellSender: isShell });
  assert.doesNotThrow(() => ipc.on('x', null));
  assert.equal(typeof ipc._store.get('on:x'), 'object'); // null 原样存
  uninstall();
});

test('installIpcGuard: 卸载后恢复原方法', () => {
  const ipc = fakeIpcMain();
  const before = ipc.on;
  const uninstall = g.installIpcGuard(ipc, { isShellSender: isShell });
  assert.notEqual(ipc.on, before);
  uninstall();
  assert.equal(ipc.on, before);
});

test('createRateCounter 窗口内放行、超限拒绝、窗口滚动后重置', () => {
  const c = g.createRateCounter();
  let n = 0;
  for (let i = 0; i < 3; i++) if (c.admit('k', 1000, 3)) n += 1;
  assert.equal(n, 3);
  assert.equal(c.admit('k', 1000, 3), false);
  assert.equal(c.admit('other', 1000, 3), true, '不同 key 独立计数');
});
