'use strict';

// ipcchannelguard.js —— 渲染层“原始 IPC 通道”（ipc-message / ipc-message-sync）收口。
//
// 威胁模型：
//   OpenCosy 的渲染层一律通过 contextBridge 暴露的白名单 API 与主进程通信，业务通道
//   由 ipcMain 逐一注册并用 isMainSender 收口。但 Electron 还会在 webContents 上抛出
//   两个更底层的事件：
//     - 'ipc-message'      ：网页用旧版 ipcRenderer.send(channel, ...) 直发；
//     - 'ipc-message-sync'：网页用 ipcRenderer.sendSync(...) 发同步消息。
//   contextIsolation 正常时网页拿不到 ipcRenderer，这两个事件不会触发；可一旦 preload
//   残缺（preload-error）、隔离被绕过、或将来误开 nodeIntegration，网页就能直发任意
//   channel 名尝试撞上内部处理器。尤其 sendSync 会“同步阻塞主进程”，高频 / 巨型同步
//   消息可直接冻住整个浏览器（IPC 拒绝服务）。
//
// 策略（深度防御）：
//   - 维护一个“允许的原始通道”白名单（默认空集，业务都走 contextBridge），不在名单的
//     原始通道一律阻断并留痕；
//   - 同步通道即便在名单内也做更严的频率 / 参数数量限制；
//   - channel 名必须是有限长度、无控制字符的字符串。
// 纯函数，main.js 负责 preventDefault（sync 还需回一个安全 returnValue）。

const IPC_ALLOW = 'allow';
const IPC_BLOCK = 'block';

const IPC_ASYNC = 'async';
const IPC_SYNC = 'sync';

const MAX_CHANNEL_CHARS = 128;
const MAX_SYNC_ARGS = 8;   // 同步消息参数个数上限（同步路径应极简）
const MAX_ASYNC_ARGS = 64;

// 普通原始通道频率：5 秒 40 次、60 秒 200 次。
const ASYNC_BURST_WINDOW_MS = 5000;
const ASYNC_BURST_MAX = 40;
const ASYNC_LONG_WINDOW_MS = 60000;
const ASYNC_LONG_MAX = 200;
// 同步通道从严：5 秒 8 次、60 秒 40 次（任何一次都值得留意）。
const SYNC_BURST_WINDOW_MS = 5000;
const SYNC_BURST_MAX = 8;
const SYNC_LONG_WINDOW_MS = 60000;
const SYNC_LONG_MAX = 40;
const IPC_COOLDOWN_MS = 15000;

function hasControlChar(s) {
  if (typeof s !== 'string') return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f || c === 0x2028 || c === 0x2029 || c === 0xfeff) return true;
  }
  return false;
}

// isValidChannelName 校验原始通道名形态。
function isValidChannelName(channel) {
  if (typeof channel !== 'string' || channel.length === 0) return false;
  if (channel.length > MAX_CHANNEL_CHARS) return false;
  if (hasControlChar(channel)) return false;
  return true;
}

function createIpcChannelState() {
  return {
    asyncBurstStart: -1, asyncBurstCount: 0,
    asyncLongStart: -1, asyncLongCount: 0,
    syncBurstStart: -1, syncBurstCount: 0,
    syncLongStart: -1, syncLongCount: 0,
    cooldownUntil: 0,
    total: 0,
    blocked: 0,
  };
}

function resetForNavigation(st) {
  if (!st) return;
  st.asyncBurstStart = -1; st.asyncBurstCount = 0;
  st.asyncLongStart = -1; st.asyncLongCount = 0;
  st.syncBurstStart = -1; st.syncBurstCount = 0;
  st.syncLongStart = -1; st.syncLongCount = 0;
  st.cooldownUntil = 0;
}

function admitWindow(st, now, kind) {
  const isSync = kind === IPC_SYNC;
  const burstStartKey = isSync ? 'syncBurstStart' : 'asyncBurstStart';
  const burstCountKey = isSync ? 'syncBurstCount' : 'asyncBurstCount';
  const longStartKey = isSync ? 'syncLongStart' : 'asyncLongStart';
  const longCountKey = isSync ? 'syncLongCount' : 'asyncLongCount';
  const burstWin = isSync ? SYNC_BURST_WINDOW_MS : ASYNC_BURST_WINDOW_MS;
  const burstMax = isSync ? SYNC_BURST_MAX : ASYNC_BURST_MAX;
  const longWin = isSync ? SYNC_LONG_WINDOW_MS : ASYNC_LONG_WINDOW_MS;
  const longMax = isSync ? SYNC_LONG_MAX : ASYNC_LONG_MAX;

  if (st[burstStartKey] < 0 || now - st[burstStartKey] > burstWin) {
    st[burstStartKey] = now;
    st[burstCountKey] = 0;
  }
  if (st[longStartKey] < 0 || now - st[longStartKey] > longWin) {
    st[longStartKey] = now;
    st[longCountKey] = 0;
  }
  st[burstCountKey] += 1;
  st[longCountKey] += 1;
  if (st[burstCountKey] > burstMax || st[longCountKey] > longMax) {
    st.cooldownUntil = now + IPC_COOLDOWN_MS;
    return { cooldown: true };
  }
  return { cooldown: false };
}

// evaluateIpcChannel 是 main.js 在 ipc-message(-sync) 里调用的总入口。
//   input: { channel, kind: 'async'|'sync', argsLength }
//   allowed: Set<string>，允许的原始通道白名单（默认空集）。
// 返回 { action, channel, kind, reasons }。
function evaluateIpcChannel(input, allowed, st, now) {
  const info = input || {};
  const kind = info.kind === IPC_SYNC ? IPC_SYNC : IPC_ASYNC;
  const allow = allowed instanceof Set ? allowed : new Set();
  const reasons = [];
  let channel = '';

  if (!isValidChannelName(info.channel)) {
    reasons.push('bad-channel-name');
    if (typeof info.channel === 'string') channel = info.channel.slice(0, 64);
  } else {
    channel = info.channel;
  }

  const argsLength = Number.isSafeInteger(info.argsLength) && info.argsLength >= 0
    ? info.argsLength : 0;
  const argLimit = kind === IPC_SYNC ? MAX_SYNC_ARGS : MAX_ASYNC_ARGS;
  if (argsLength > argLimit) reasons.push(kind === IPC_SYNC ? 'sync-args-overflow' : 'args-overflow');

  const nameOk = isValidChannelName(info.channel);
  const inAllowlist = nameOk && allow.has(info.channel);
  if (!inAllowlist) reasons.push('channel-not-allowlisted');

  let cooldown = false;
  // 仅当通道名形态正常时才计数，畸形名本身直接阻断（不污染频率窗）。
  if (now >= st.cooldownUntil) {
    if (nameOk) {
      const gate = admitWindow(st, now, kind);
      cooldown = gate.cooldown;
    }
  } else {
    cooldown = true;
  }
  if (cooldown) reasons.push('ipc-channel-flood');

  st.total += 1;
  // 默认策略：非白名单一律阻断；白名单通道命中频率洪泛时也阻断。
  const block = !inAllowlist || cooldown || reasons.includes('bad-channel-name')
    || reasons.includes(kind === IPC_SYNC ? 'sync-args-overflow' : 'args-overflow');
  if (block) st.blocked += 1;

  return {
    action: block ? IPC_BLOCK : IPC_ALLOW,
    channel,
    kind,
    reasons,
    state: st,
  };
}

module.exports = {
  IPC_ALLOW,
  IPC_BLOCK,
  IPC_ASYNC,
  IPC_SYNC,
  MAX_CHANNEL_CHARS,
  MAX_SYNC_ARGS,
  MAX_ASYNC_ARGS,
  SYNC_BURST_MAX,
  ASYNC_BURST_MAX,
  SYNC_LONG_MAX,
  ASYNC_LONG_MAX,
  hasControlChar,
  isValidChannelName,
  createIpcChannelState,
  resetForNavigation,
  admitWindow,
  evaluateIpcChannel,
};
