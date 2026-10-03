'use strict';

// childwindowguard.js —— 网页意外创建的“原生子窗口”收口内核（did-create-window）。
//
// 威胁模型：
//   OpenCosy 正常情况下把 window.open / target=_blank 全部改写成自建标签
//   （setWindowOpenHandler 恒为 deny + createNewTab）。但 Electron 仍存在几条会真正
//   new 出一个原生 BrowserWindow 的路径：
//     1) 某个 setWindowOpenHandler 因逻辑分支 / 异常返回了 { action: 'allow' }；
//     2) 第三方代码 / 旧扩展 / DevTools 协议（window.open + noopener、或某些
//        disposition）在个别 Electron 版本上绕过 deny 直接开窗；
//     3) 应用自身将来新增的“弹窗 UI”被网页借道复用。
//   原生子窗口默认会继承一部分创建参数，若 nodeIntegration / webSecurity / sandbox
//   等基线被放宽，或首屏地址是 file: / javascript: / data:，就等于给网页开了一个
//   提权的新渲染进程；子窗口还可能带 window.opener 反向操纵原页（tabnabbing）。
//
//   'did-create-window' 在窗口“已经创建出来之后”触发，无法阻止创建，但可以：
//     - 立即核对实际 webPreferences 是否满足安全基线，不满足直接销毁窗口；
//     - 审核首屏 URL，危险协议直接销毁；
//     - 给幸存窗口补挂 will-navigate / will-attach-webview 限制（由 main.js 接线）；
//     - 用独立的计数状态防止网页用“开窗→被销毁”循环刷窗口。
//
// 本模块只产出纯判定，不触碰 Electron API，main.js 拿到 decision 后执行 close / 加固。

// 子窗口决策。
const CHILD_CLOSE = 'close';     // 直接销毁：基线被破坏或首屏地址危险
const CHILD_ISOLATE = 'isolate'; // 允许保留，但必须按隔离基线补挂限制
const CHILD_ALLOW = 'allow';     // 完全满足基线、地址可信

// 子窗口首屏绝不允许出现的协议。
const DANGEROUS_CHILD_SCHEMES = new Set([
  'javascript:', 'vbscript:', 'data:', 'file:', 'blob:',
]);

// 必须满足的 webPreferences 安全基线（与主窗口一致的最小权限）。
// 任一项不符合预期都视为提权窗口，直接销毁。
const REQUIRED_PREF_BASELINE = Object.freeze({
  nodeIntegration: false,
  nodeIntegrationInWorker: false,
  nodeIntegrationInSubFrames: false,
  webSecurity: true,
  allowRunningInsecureContent: false,
  sandbox: true,
  contextIsolation: true,
  webviewTag: false,
  // 新窗口没有理由带这些调试 / 提权通道。
  devTools: false,
});

function schemeOf(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl) return '';
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

// evaluateWebPreferences 把“实际创建出来的窗口”的 webPreferences 与基线比对。
// 返回 { ok, violations: string[] }；prefs 缺字段时按 Electron 默认的安全值处理，
// 但显式被设成危险值的项一定计入 violations。
function evaluateWebPreferences(prefs) {
  const p = prefs && typeof prefs === 'object' ? prefs : {};
  const violations = [];

  const boolMustBe = (key, expected) => {
    if (!(key in p)) return; // 未显式设置：沿用调用方 / 全局默认，不在此判负。
    if (p[key] !== expected) violations.push(key);
  };

  boolMustBe('nodeIntegration', false);
  boolMustBe('nodeIntegrationInWorker', false);
  boolMustBe('nodeIntegrationInSubFrames', false);
  boolMustBe('webSecurity', true);
  boolMustBe('allowRunningInsecureContent', false);
  boolMustBe('sandbox', true);
  boolMustBe('contextIsolation', true);
  boolMustBe('webviewTag', false);

  // preload 只允许是字符串绝对路径且不得是远程 URL；这里只做形态校验，真实路径
  // 归属（必须在应用目录内）由 main.js 再用既有容器判定核一遍。
  if ('preload' in p && p.preload != null) {
    if (typeof p.preload !== 'string' || p.preload.length === 0) {
      violations.push('preload');
    } else if (/^[a-z][a-z0-9+.-]*:\/\//i.test(p.preload.trim())) {
      violations.push('preload-remote');
    }
  }

  // 额外的高危额外开关：一旦显式打开即视为提权（不在基线表里但同样致命）。
  if (p.webSecurity === false) {
    if (!violations.includes('webSecurity')) violations.push('webSecurity');
  }
  if (p.enableRemoteModule === true) violations.push('enableRemoteModule');
  if (p.allowpopups === true) violations.push('allowpopups');

  return { ok: violations.length === 0, violations };
}

// evaluateChildUrl 审核子窗口首屏地址。
//   - 危险协议：close；
//   - http/https：isolate（补挂导航限制）；
//   - about:blank（继承 opener 源）：isolate；
//   - 空 / 无法解析：isolate，但标记 unknown，交由 main.js 拒绝其后续导航。
function evaluateChildUrl(rawUrl) {
  const url = typeof rawUrl === 'string' ? rawUrl : '';
  const scheme = schemeOf(url);
  if (DANGEROUS_CHILD_SCHEMES.has(scheme)) {
    return { grade: CHILD_CLOSE, scheme, origin: '', reasons: ['dangerous-scheme:' + scheme] };
  }
  const origin = originFromUrl(url);
  if (origin) return { grade: CHILD_ISOLATE, scheme, origin, reasons: ['web-origin'] };
  const trimmed = url.trim().toLowerCase();
  if (trimmed === 'about:blank' || trimmed === '') {
    return { grade: CHILD_ISOLATE, scheme, origin: '', reasons: [trimmed === '' ? 'empty-url' : 'about-blank'] };
  }
  return { grade: CHILD_ISOLATE, scheme, origin: '', reasons: ['non-web-url'] };
}

// 开窗频率阈值。正常浏览几乎不会真正 new 原生窗口（都被改成标签），因此阈值从严：
// 短窗 5 秒最多 6 个、长窗 60 秒最多 24 个；越限后 20 秒内新子窗口一律直接关闭，
// 防止“开窗→被销毁”循环无限占用资源。
const CHILD_BURST_WINDOW_MS = 5000;
const CHILD_BURST_MAX = 6;
const CHILD_LONG_WINDOW_MS = 60000;
const CHILD_LONG_MAX = 24;
const CHILD_COOLDOWN_MS = 20000;

function createChildWindowState() {
  // 窗口哨兵用 -1，避免在基准时间 0 上被 falsy 判断反复清零（见 frameguard 说明）。
  return {
    burstStart: -1,
    burstCount: 0,
    longStart: -1,
    longCount: 0,
    cooldownUntil: 0,
    total: 0,
    closed: 0,
  };
}

// resetForNavigation 在顶层导航后调用：开窗洪泛属于页面行为，换文档后配额归零。
function resetForNavigation(st) {
  if (!st) return;
  st.burstStart = -1;
  st.burstCount = 0;
  st.longStart = -1;
  st.longCount = 0;
  st.cooldownUntil = 0;
}

// admitChildWindow 为一次“子窗口已创建”事件计数，返回当前是否处于冷却（true 表示
// 应当直接关闭该窗口）。冷却结束后窗口计数清零重新开始。
function admitChildWindow(st, now) {
  const s = st || createChildWindowState(now);
  if (now >= s.cooldownUntil) s.cooldownUntil = 0;
  if (now < s.cooldownUntil) return { cooldown: true, state: s };

  if (s.burstStart < 0 || now - s.burstStart > CHILD_BURST_WINDOW_MS) {
    s.burstStart = now;
    s.burstCount = 0;
  }
  if (s.longStart < 0 || now - s.longStart > CHILD_LONG_WINDOW_MS) {
    s.longStart = now;
    s.longCount = 0;
  }
  s.burstCount += 1;
  s.longCount += 1;
  s.total += 1;
  if (s.burstCount > CHILD_BURST_MAX || s.longCount > CHILD_LONG_MAX) {
    s.cooldownUntil = now + CHILD_COOLDOWN_MS;
    s.burstStart = -1;
    s.burstCount = 0;
    s.longStart = -1;
    s.longCount = 0;
    return { cooldown: true, state: s };
  }
  return { cooldown: false, state: s };
}

// evaluateChildWindow 是 main.js 在 did-create-window 里调用的总入口。
// 输入 { url, prefs, openerPresent }，以及共享的 per-opener 计数状态。
// 返回 { action, reasons, violations, origin, scheme }。
function evaluateChildWindow(input, st, now) {
  const info = input || {};
  const urlVerdict = evaluateChildUrl(info.url);
  const prefsVerdict = evaluateWebPreferences(info.prefs);
  const reasons = urlVerdict.reasons.slice();
  let action = urlVerdict.grade;

  if (!prefsVerdict.ok) {
    action = CHILD_CLOSE;
    for (const v of prefsVerdict.violations) reasons.push('pref:' + v);
  }
  if (info.openerPresent === false && action === CHILD_ALLOW) {
    // 没有 opener 仍走到这里属于异常开窗路径，降级为隔离。
    action = CHILD_ISOLATE;
    reasons.push('no-opener');
  }

  const gate = admitChildWindow(st, now);
  if (gate.cooldown) {
    action = CHILD_CLOSE;
    reasons.push('child-window-flood');
  }
  if (action === CHILD_CLOSE) {
    st = gate.state;
    st.closed += 1;
  }
  return {
    action,
    reasons,
    violations: prefsVerdict.violations,
    origin: urlVerdict.origin,
    scheme: urlVerdict.scheme,
    state: gate.state,
  };
}

module.exports = {
  CHILD_CLOSE,
  CHILD_ISOLATE,
  CHILD_ALLOW,
  DANGEROUS_CHILD_SCHEMES,
  REQUIRED_PREF_BASELINE,
  CHILD_BURST_MAX,
  CHILD_LONG_MAX,
  CHILD_COOLDOWN_MS,
  schemeOf,
  originFromUrl,
  evaluateWebPreferences,
  evaluateChildUrl,
  createChildWindowState,
  resetForNavigation,
  admitChildWindow,
  evaluateChildWindow,
};
