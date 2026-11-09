'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const ipcGuard = require('./ipcguard');
const policy = require('./channelpolicy');

const ROOT = __dirname;
const MAIN_SOURCE = fs.readFileSync(path.join(ROOT, 'main.js'), 'utf8')
  + '\n' + fs.readFileSync(path.join(ROOT, 'permissionhandlers.js'), 'utf8')
  + '\n' + fs.readFileSync(path.join(ROOT, 'cosyipcregister.js'), 'utf8')
  + '\n' + fs.readFileSync(path.join(ROOT, 'cosyipcwire.js'), 'utf8')
  + '\n' + fs.readFileSync(path.join(ROOT, 'cosyipcwire2.js'), 'utf8')
  + '\n' + fs.readFileSync(path.join(ROOT, 'cosyipcwire3.js'), 'utf8')
  + '\n' + fs.readFileSync(path.join(ROOT, 'cosyipcwire4.js'), 'utf8');
const PRELOAD_SOURCE = fs.readFileSync(path.join(ROOT, 'preload.js'), 'utf8');

const ANY_FRAME_CHANNELS = new Set(['report-csp-violation']);
const RENDERER_EVENT_NAMES = new Set(['cert-error-blocked', 'cert-exception-updated']);

function stripComments(src) {
  let out = '';
  let i = 0;
  let quote = '';
  while (i < src.length) {
    const c = src[i];
    if (quote) {
      out += c;
      if (c === '\\' && i + 1 < src.length) {
        out += src[i + 1];
        i += 2;
        continue;
      }
      if (c === quote) quote = '';
      i += 1;
      continue;
    }
    if (c === '\'' || c === '"' || c === '`') {
      quote = c;
      out += c;
      i += 1;
      continue;
    }
    if (c === '/' && src[i + 1] === '/') {
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2);
      i = end < 0 ? src.length : end + 2;
      continue;
    }
    out += c;
    i += 1;
  }
  return out;
}

const MAIN_CODE = stripComments(MAIN_SOURCE);
const PRELOAD_CODE = stripComments(PRELOAD_SOURCE);

function registeredChannels(code) {
  const found = new Set();
  const re = /ipcMain\s*\.\s*(?:handle|handleOnce|on|once)\s*\(\s*'([^']+)'/g;
  let m = re.exec(code);
  while (m) {
    found.add(m[1]);
    m = re.exec(code);
  }
  return found;
}

function preloadSet(code, setName) {
  const start = code.indexOf('const ' + setName + ' = new Set([');
  assert.ok(start >= 0, 'preload 缺少白名单 ' + setName);
  const end = code.indexOf(']);', start);
  assert.ok(end >= 0, 'preload 白名单未闭合 ' + setName);
  const found = new Set();
  const re = /'([^']+)'/g;
  const body = code.slice(start, end);
  let m = re.exec(body);
  while (m) {
    found.add(m[1]);
    m = re.exec(body);
  }
  return found;
}

const REGISTERED = registeredChannels(MAIN_CODE);
const PRELOAD_INVOKE = preloadSet(PRELOAD_CODE, 'allowedInvokeChannels');
const PRELOAD_SEND = preloadSet(PRELOAD_CODE, 'allowedSendChannels');

const TIER_SETS = [
  policy.SHELL_ONLY_CHANNELS,
  policy.CERT_FLOW_CHANNELS,
  policy.COSY_ONLY_CHANNELS,
  policy.GENERAL_CHANNELS,
];

function registryNames() {
  const all = new Set();
  for (const tier of TIER_SETS) {
    for (const name of tier) all.add(name);
  }
  return all;
}

test('main.js 注册的每个通道都在 channelpolicy 显式分级，或属于任意帧白名单', () => {
  const registered = registryNames();
  const missing = [];
  for (const channel of REGISTERED) {
    if (registered.has(channel)) continue;
    if (ANY_FRAME_CHANNELS.has(channel)) continue;
    missing.push(channel);
  }
  assert.deepEqual(missing, [],
    '以下通道未分级，会被默认收敛成 shell-only，cosy 内置页调用一律被拒: ' + missing.join(', '));
});

test('channelpolicy 登记的每个名字都能在 main.js 找到注册（渲染端事件除外）', () => {
  const stale = [];
  for (const name of registryNames()) {
    if (REGISTERED.has(name)) continue;
    if (RENDERER_EVENT_NAMES.has(name)) continue;
    stale.push(name);
  }
  assert.deepEqual(stale, [], '分级表里存在 main.js 没有注册的陈旧通道: ' + stale.join(', '));
});

test('分级表内同一通道不重复归属两个级别', () => {
  const seen = new Map();
  const dup = [];
  for (const tier of TIER_SETS) {
    for (const name of tier) {
      if (seen.has(name)) dup.push(name);
      seen.set(name, true);
    }
  }
  assert.deepEqual(dup, [], '同一通道被登记到多个分级: ' + dup.join(', '));
});

test('preload 的 invoke 白名单与 main.js 注册通道对齐', () => {
  const notRegistered = [];
  for (const channel of PRELOAD_INVOKE) {
    if (!REGISTERED.has(channel)) notRegistered.push(channel);
  }
  assert.deepEqual(notRegistered, [],
    'preload 放行了未注册的 invoke 通道: ' + notRegistered.join(', '));
});

test('preload 的 send 白名单与 main.js 注册通道对齐', () => {
  const notRegistered = [];
  for (const channel of PRELOAD_SEND) {
    if (!REGISTERED.has(channel)) notRegistered.push(channel);
  }
  assert.deepEqual(notRegistered, [],
    'preload 放行了未注册的 send 通道: ' + notRegistered.join(', '));
});

test('内置管理页通道对 cosy 帧放行、对内置错误页拒绝', () => {
  const channels = [
    'history-snapshot',
    'history-delete-entry',
    'bookmarks-snapshot',
    'readinglist-snapshot',
    'tab-overview-snapshot',
    'pages-open',
    'about-snapshot',
    'shortcuts-snapshot',
    'get-security-posture',
    'get-download-journal',
    'clear-download-journal',
  ];
  for (const channel of channels) {
    assert.equal(policy.channelTier(channel), policy.TIER_COSY_ONLY,
      channel + ' 应显式登记为 cosy-only');
    assert.equal(policy.frameAllows(ipcGuard.KIND_SHELL, channel), true,
      channel + ' 应允许外壳调用');
    assert.equal(policy.frameAllows(ipcGuard.KIND_COSY, channel), true,
      channel + ' 应允许 cosy 内置页调用');
    assert.equal(policy.frameAllows(ipcGuard.KIND_INTERNAL_FILE, channel), false,
      channel + ' 不应下放给内置错误页');
  }
});

test('任意帧通道不进入分级表，交由 ipcguard allowAnyFrame 处理', () => {
  for (const channel of ANY_FRAME_CHANNELS) {
    assert.equal(registryNames().has(channel), false);
    assert.equal(policy.channelTier(channel), policy.TIER_SHELL_ONLY);
  }
});
