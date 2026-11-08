'use strict';

// remoteguard.js —— @electron/remote 桥事件与 desktopCapturer 枚举的深度防御内核。
//
// 威胁模型：
//   OpenCosy 不启用、也不预加载 @electron/remote，渲染层理论上碰不到主进程对象。
//   但 Electron 仍为“远程桥”保留了一组 webContents 事件，只要将来某次改动误把
//   enableRemoteModule 打开、或某依赖间接引入 remote，网页就能借这些事件反向 require
//   主进程模块 / 取 BrowserWindow / 读全局对象，直接拿到 Node 能力：
//     - 'remote-require'               : 渲染层 require(模块名)
//     - 'remote-get-builtin'           : 取 electron 内置模块
//     - 'remote-get-current-window'    : 取当前 BrowserWindow
//     - 'remote-get-current-web-contents' : 取当前 webContents
//     - 'remote-get-global'            : 读主进程 global 上的任意名字
//   此外 'desktop-capturer-get-sources' 在渲染层调 desktopCapturer.getSources()
//   枚举屏幕 / 窗口列表时触发；该列表含屏幕尺寸、窗口标题等指纹信息，浏览器网页
//   没有正当理由枚举整屏清单（屏幕共享走 setDisplayMediaRequestHandler 已默认拒绝）。
//
// 策略：浏览器场景下这些通道一律拒绝（main.js preventDefault），并把“目标模块名 /
// 全局名”做安全归一化后留痕；正常使用这些事件的次数恒为 0，因此限流给得极严，
// 任何一次触发都按高危记录。纯函数，不触碰 Electron API。

const REMOTE_ALLOW = 'allow';
const REMOTE_BLOCK = 'block';

// 远程桥的固定通道名。
const REMOTE_CHANNELS = Object.freeze({
  REQUIRE: 'remote-require',
  GET_BUILTIN: 'remote-get-builtin',
  GET_CURRENT_WINDOW: 'remote-get-current-window',
  GET_CURRENT_WEB_CONTENTS: 'remote-get-current-web-contents',
  GET_GLOBAL: 'remote-get-global',
  DESKTOP_CAPTURER: 'desktop-capturer-get-sources',
});

const KNOWN_REMOTE_CHANNELS = new Set(Object.values(REMOTE_CHANNELS));

// 这些通道需要带“目标名”（模块名 / 内置名 / 全局名）。
const NAMED_CHANNELS = new Set([
  REMOTE_CHANNELS.REQUIRE,
  REMOTE_CHANNELS.GET_BUILTIN,
  REMOTE_CHANNELS.GET_GLOBAL,
]);

const MAX_TARGET_CHARS = 256;

// 严格限流：5 秒最多 4 次、60 秒最多 16 次，越限冷却 30 秒（正常情况永远是 0）。
const REMOTE_BURST_WINDOW_MS = 5000;
const REMOTE_BURST_MAX = 4;
const REMOTE_LONG_WINDOW_MS = 60000;
const REMOTE_LONG_MAX = 16;
const REMOTE_COOLDOWN_MS = 30000;

function hasControlChar(s) {
  if (typeof s !== 'string') return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f || c === 0x2028 || c === 0x2029 || c === 0xfeff) return true;
  }
  return false;
}

// sanitizeTarget 把事件里的“目标名”归一成可安全写进审计日志的短串：
// 非字符串 / 超长 / 含控制字符时返回固定占位，绝不把脏值直接拼进日志。
function sanitizeTarget(raw) {
  if (typeof raw !== 'string') return { name: '<non-string>', suspicious: true };
  if (raw.length === 0) return { name: '<empty>', suspicious: false };
  if (raw.length > MAX_TARGET_CHARS || hasControlChar(raw)) {
    return { name: '<invalid-target>', suspicious: true };
  }
  return { name: raw, suspicious: false };
}

function createRemoteState() {
  // 时间窗口哨兵用 -1，避免在基准时间 0 上被 falsy 判断反复清零。
  return {
    burstStart: -1,
    burstCount: 0,
    longStart: -1,
    longCount: 0,
    cooldownUntil: 0,
    hits: 0,
    blocked: 0,
  };
}

function resetForNavigation(st) {
  if (!st) return;
  st.burstStart = -1;
  st.burstCount = 0;
  st.longStart = -1;
  st.longCount = 0;
  st.cooldownUntil = 0;
}

function admitHit(st, now) {
  if (now < st.cooldownUntil) return { cooldown: true };
  if (st.burstStart < 0 || now - st.burstStart > REMOTE_BURST_WINDOW_MS) {
    st.burstStart = now;
    st.burstCount = 0;
  }
  if (st.longStart < 0 || now - st.longStart > REMOTE_LONG_WINDOW_MS) {
    st.longStart = now;
    st.longCount = 0;
  }
  st.burstCount += 1;
  st.longCount += 1;
  st.hits += 1;
  if (st.burstCount > REMOTE_BURST_MAX || st.longCount > REMOTE_LONG_MAX) {
    st.cooldownUntil = now + REMOTE_COOLDOWN_MS;
    st.burstStart = -1;
    st.burstCount = 0;
    st.longStart = -1;
    st.longCount = 0;
    return { cooldown: true };
  }
  return { cooldown: false };
}

// classifyChannel 判定通道名是否属于已知远程桥通道。
// 未知通道名（理论上不会出现）同样按阻断处理，单独标记，便于发现 Electron 新增面。
function classifyChannel(channel) {
  if (typeof channel !== 'string' || !channel) return { known: false, channel: '' };
  return { known: KNOWN_REMOTE_CHANNELS.has(channel), channel };
}

// evaluateRemoteBridge 是 main.js 在各远程桥事件里调用的总入口。
//   input: { channel, target }（target 为模块名 / 内置名 / 全局名，可空）
// 返回 { action, channel, target, reasons }。浏览器策略恒为 block。
function evaluateRemoteBridge(input, st, now) {
  const info = input || {};
  const reasons = [];
  const cls = classifyChannel(info.channel);
  if (!cls.known) reasons.push('unknown-remote-channel');
  const channel = cls.channel || String(info.channel || '').slice(0, 64);

  let target = '';
  if (NAMED_CHANNELS.has(info.channel)) {
    const t = sanitizeTarget(info.target);
    target = t.name;
    if (t.suspicious) reasons.push('invalid-target-name');
  }

  const gate = admitHit(st, now);
  if (gate.cooldown) reasons.push('remote-bridge-flood');
  st.blocked += 1;

  return { action: REMOTE_BLOCK, channel, target, reasons, state: st };
}

// isRemoteBridgeChannel 供 main.js 快速判断某个事件名是否应走本内核。
function isRemoteBridgeChannel(channel) {
  return KNOWN_REMOTE_CHANNELS.has(channel);
}

module.exports = {
  REMOTE_ALLOW,
  REMOTE_BLOCK,
  REMOTE_CHANNELS,
  KNOWN_REMOTE_CHANNELS,
  NAMED_CHANNELS,
  MAX_TARGET_CHARS,
  REMOTE_BURST_MAX,
  REMOTE_LONG_MAX,
  REMOTE_COOLDOWN_MS,
  hasControlChar,
  sanitizeTarget,
  createRemoteState,
  resetForNavigation,
  admitHit,
  classifyChannel,
  evaluateRemoteBridge,
  isRemoteBridgeChannel,
};
