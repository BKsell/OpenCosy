'use strict';

// frameguard.js —— frame-created 事件的纯逻辑守卫内核（iframe / 子框架生命周期）。
//
// 威胁模型：
//   Chromium 每创建一个框架（主框架自身、<iframe>、<frame>、portal、fenced frame）
//   都会在 webContents 上触发 'frame-created'。主框架由 will-navigate 系列把关，
//   但“子框架刚被创建”这一刻此前完全没有观测：
//     1) iframe 爆炸（frame flooding）：页面瞬间 new 成百上千个 iframe 做挖矿 /
//        指纹 / 广告轰炸，拖垮渲染进程与网络；
//     2) 子框架首屏地址是 javascript:/data:/file: 等危险协议，在被 will-frame-navigate
//        拦截前可能已完成一轮内部初始化；
//     3) 大量指向 file: / chrome: / 特权协议的嵌套框架是在试探越权；
//     4) 孤儿框架（没有有效父框架却被报成子框架）是内部状态错乱 / 异常嵌入的信号。
//
//   frame-created 无法 preventDefault（框架已创建），本内核的职责是“裁决 + 留痕 +
//   配额”：main.js 拿到 DROP 后记录安全事件，并对命中的子框架用既有导航 / 销毁策略
//   处理（主框架永不销毁，只计数）。所有判定为纯函数，便于单测。

const FRAME_MAIN = 'main-frame';
const FRAME_CHILD = 'child-frame';

const FRAME_PASS = 'pass'; // 正常框架
const FRAME_DROP = 'drop'; // 命中规则，建议拦截 / 留痕

// 子框架首屏不允许出现的协议（主框架由顶层导航策略另管）。
const DANGEROUS_FRAME_SCHEMES = new Set([
  'javascript:', 'vbscript:', 'file:', 'chrome:', 'chrome-untrusted:',
]);

// 子框架数量配额。真实网页的广告 / 支付 / 评论等多 iframe 页面通常几十个以内；
// 给到短窗 5 秒 120 个、长窗 30 秒 400 个，足以容纳重度页面，又能挡住框架爆炸。
const FRAME_BURST_WINDOW_MS = 5000;
const FRAME_BURST_MAX = 120;
const FRAME_LONG_WINDOW_MS = 30000;
const FRAME_LONG_MAX = 400;
const FRAME_COOLDOWN_MS = 10000;

// 单个子框架初始 URL 的长度上限，异常超长通常是数据外带 / 混淆探针。
const FRAME_MAX_URL_CHARS = 8192;

function schemeOf(rawUrl) {
  if (typeof rawUrl !== 'string') return '';
  if (!rawUrl) return '';
  const m = /^([a-z][a-z0-9+.-]*:)/i.exec(rawUrl.trim());
  return m ? m[1].toLowerCase() : '';
}

function originFromUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl) return '';
  try {
    const u = new URL(rawUrl);
    if (u.protocol === 'http:' || u.protocol === 'https:') {
      return u.origin === 'null' ? '' : u.origin;
    }
    return '';
  } catch {
    return '';
  }
}

function containsControlChar(s) {
  if (typeof s !== 'string') return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return true;
    if (c === 0x2028 || c === 0x2029 || c === 0xfeff) return true;
  }
  return false;
}

function createFrameState() {
  // 时间窗口用 -1 表示“尚未开始”，不能用 0：纯函数可能在基准时间 0 上运行，
  // 0 会被当成 falsy 哨兵导致每个事件都误判为窗口起点而反复清零。
  return {
    main: 0,
    child: 0,
    burstStart: -1,
    burstCount: 0,
    longStart: -1,
    longCount: 0,
    cooldownUntil: 0,
    dropped: 0,
  };
}

// resetForNavigation 在顶层导航后调用：主框架换文档，iframe 全部失效，计数归零。
function resetForNavigation(st, now) {
  if (!st) return;
  st.main = 0;
  st.child = 0;
  st.burstStart = -1;
  st.burstCount = 0;
  st.longStart = -1;
  st.longCount = 0;
  st.cooldownUntil = 0;
  st.dropped = 0;
}

// classifyFrame 依据 Electron frame 对象判定主 / 子框架。
// Electron 主框架没有 parent；传入结构异常（非对象 / 无 url 字段类型错误）时报 unknown。
function classifyFrame(frame) {
  if (!frame || typeof frame !== 'object') return 'unknown';
  // 主框架在 Electron 里 parent 为 null/undefined；子框架 parent 是个对象。
  if (frame.parent === null || frame.parent === undefined) return FRAME_MAIN;
  if (typeof frame.parent === 'object') return FRAME_CHILD;
  return 'unknown';
}

// admitFrame 为框架计数（仅子框架参与洪泛判定，主框架不计）。
// 返回 { cooldown }，冷却期内新子框架建议丢弃。
function admitFrame(st, kind, now) {
  if (kind === FRAME_MAIN) {
    st.main += 1;
    return { cooldown: false };
  }
  if (kind === 'unknown') {
    // 结构异常不计数，但调用方应单独留痕。
    return { cooldown: false };
  }
  st.child += 1;
  if (now < st.cooldownUntil) return { cooldown: true };

  if (st.burstStart < 0 || now - st.burstStart > FRAME_BURST_WINDOW_MS) {
    st.burstStart = now;
    st.burstCount = 0;
  }
  if (st.longStart < 0 || now - st.longStart > FRAME_LONG_WINDOW_MS) {
    st.longStart = now;
    st.longCount = 0;
  }
  st.burstCount += 1;
  st.longCount += 1;
  if (st.burstCount > FRAME_BURST_MAX || st.longCount > FRAME_LONG_MAX) {
    st.cooldownUntil = now + FRAME_COOLDOWN_MS;
    st.burstStart = -1;
    st.burstCount = 0;
    st.longStart = -1;
    st.longCount = 0;
    return { cooldown: true };
  }
  return { cooldown: false };
}

// evaluateFrame 是 main.js 在 frame-created 里调用的总入口。
// frame：Electron 给的 frame 对象（取其 url / parent）。
// 返回 { action, kind, reasons: string[], origin, scheme }。
function evaluateFrame(frame, st, now) {
  const kind = classifyFrame(frame);
  const reasons = [];
  if (kind === 'unknown') {
    return { action: FRAME_DROP, kind, reasons: ['malformed-frame'], origin: '', scheme: '' };
  }

  const url = frame && typeof frame.url === 'string' ? frame.url : '';
  const scheme = schemeOf(url);
  const origin = originFromUrl(url);

  // 子框架才做危险协议 / 长度 / 控制字符 / 洪泛判定；主框架恒放行（由导航策略管）。
  if (kind === FRAME_CHILD) {
    if (DANGEROUS_FRAME_SCHEMES.has(scheme)) reasons.push('dangerous-scheme:' + scheme);
    if (url.length > FRAME_MAX_URL_CHARS) reasons.push('frame-url-too-long');
    if (containsControlChar(url)) reasons.push('frame-url-control-char');
    const gate = admitFrame(st, kind, now);
    if (gate.cooldown) reasons.push('frame-flood');
    if (reasons.length > 0) {
      st.dropped += 1;
      return { action: FRAME_DROP, kind, reasons, origin, scheme };
    }
  } else {
    admitFrame(st, kind, now);
  }
  return { action: FRAME_PASS, kind, reasons, origin, scheme };
}

module.exports = {
  FRAME_MAIN,
  FRAME_CHILD,
  FRAME_PASS,
  FRAME_DROP,
  DANGEROUS_FRAME_SCHEMES,
  FRAME_BURST_MAX,
  FRAME_LONG_MAX,
  FRAME_COOLDOWN_MS,
  FRAME_MAX_URL_CHARS,
  schemeOf,
  originFromUrl,
  containsControlChar,
  createFrameState,
  resetForNavigation,
  classifyFrame,
  admitFrame,
  evaluateFrame,
};
