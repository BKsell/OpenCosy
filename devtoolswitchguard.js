'use strict';

// devtoolswitchguard.js —— devtools-opened / devtools-closed 事件的纯逻辑守卫内核。
//
// 与 devtoolsguard.js 的分工：devtoolsguard 管“DevTools 面板内点击链接转跳”
// （devtools-open-url）；本模块管“DevTools 这个调试通道本身被打开 / 关闭”。
//
// 威胁模型：
//   Electron 在某个 webContents 打开 / 关闭开发者工具时触发这两个事件。OpenCosy
//   此前完全没接线：
//     1) did-create-window 里我们要求所有网页意外创建的原生子窗口 devTools:false；
//        若这类“隔离子窗口”仍然打开了 DevTools，说明窗口基线被绕过 / 配置失效，
//        DevTools 控制台等于在该进程里放开任意代码执行，必须立即留痕并关闭；
//     2) 社工攻击的经典套路就是诱导普通用户按 F12 往控制台粘贴“自助修复代码”，
//        浏览器应在 DevTools 打开于“正在浏览的真实网页”时留下可审计记录（安全页
//        可展示），便于事后排查，但不阻断开发者自己调试；
//     3) 自动化 / 攻击探针会高频 open/close DevTools（驱动协议、检测环境），需要
//        折叠事件风暴，避免刷爆审计。
//
// 决策分级：
//   close —— 隔离子窗口等“按基线根本不该有 DevTools”的 contents 打开了，立即关闭；
//   audit —— 普通标签 / 主 UI 打开 DevTools，放行但留痕（开发者需要，不阻断）；
//   allow —— 关闭事件、幂等重复事件，直接放行不计数。

const DEVTOOLS_CLOSE = 'close';
const DEVTOOLS_AUDIT = 'audit';
const DEVTOOLS_ALLOW = 'allow';

// 同一 contents 的开关频率：5 秒最多 8 次、60 秒最多 20 次，超过即折叠留痕并冷却。
const DEVTOOLS_BURST_WINDOW_MS = 5000;
const DEVTOOLS_BURST_MAX = 8;
const DEVTOOLS_LONG_WINDOW_MS = 60000;
const DEVTOOLS_LONG_MAX = 20;
const DEVTOOLS_COOLDOWN_MS = 15000;

function createDevtoolsState() {
  // 窗口哨兵用 -1，避免在基准时间 0 上被 falsy 判断反复清零。
  return {
    isOpen: false,
    openedCount: 0,
    burstStart: -1,
    burstCount: 0,
    longStart: -1,
    longCount: 0,
    cooldownUntil: 0,
  };
}

function resetForNavigation(st) {
  if (!st) return;
  // 导航后“是否打开”状态以实际 DevTools 生命周期为准，这里只清频率计数，
  // 不强制 isOpen=false（DevTools 可以跨导航保持打开）。
  st.burstStart = -1;
  st.burstCount = 0;
  st.longStart = -1;
  st.longCount = 0;
  st.cooldownUntil = 0;
}

function admitToggle(st, now) {
  if (now < st.cooldownUntil) return { cooldown: true };
  if (st.burstStart < 0 || now - st.burstStart > DEVTOOLS_BURST_WINDOW_MS) {
    st.burstStart = now;
    st.burstCount = 0;
  }
  if (st.longStart < 0 || now - st.longStart > DEVTOOLS_LONG_WINDOW_MS) {
    st.longStart = now;
    st.longCount = 0;
  }
  st.burstCount += 1;
  st.longCount += 1;
  if (st.burstCount > DEVTOOLS_BURST_MAX || st.longCount > DEVTOOLS_LONG_MAX) {
    st.cooldownUntil = now + DEVTOOLS_COOLDOWN_MS;
    st.burstStart = -1;
    st.burstCount = 0;
    st.longStart = -1;
    st.longCount = 0;
    return { cooldown: true };
  }
  return { cooldown: false };
}

// classifyDevtoolsOpen 判定一次“DevTools 已打开”。
// meta: { isIsolatedChild, isMainUI }
//   isIsolatedChild=true 的窗口按基线不该存在 DevTools → close；
//   其余（普通标签、主 UI）→ audit（放行留痕）。
function classifyDevtoolsOpen(meta) {
  const m = meta || {};
  if (m.isIsolatedChild === true) {
    return { decision: DEVTOOLS_CLOSE, reason: 'devtools-on-isolated-child' };
  }
  if (m.isMainUI === true) {
    return { decision: DEVTOOLS_AUDIT, reason: 'devtools-main-ui' };
  }
  return { decision: DEVTOOLS_AUDIT, reason: 'devtools-opened' };
}

// evaluateDevtoolsToggle 是 main.js 在两个事件里调用的总入口。
//   phase: 'opened' | 'closed'；meta 见 classifyDevtoolsOpen。
// 返回 { action, reason, cooldown, state }。
function evaluateDevtoolsToggle(st, phase, meta, now) {
  const s = st || createDevtoolsState(now);
  if (phase === 'closed') {
    s.isOpen = false;
    return { action: DEVTOOLS_ALLOW, reason: '', cooldown: false, state: s };
  }
  if (phase !== 'opened') {
    return { action: DEVTOOLS_ALLOW, reason: '', cooldown: false, state: s };
  }
  // 幂等：已经处于打开态又收到 opened（不同版本可能重复上报），不重复计数。
  if (s.isOpen) {
    return { action: DEVTOOLS_ALLOW, reason: '', cooldown: false, state: s };
  }
  const gate = admitToggle(s, now);
  s.isOpen = true;
  s.openedCount += 1;
  if (gate.cooldown) {
    // 风暴期：隔离窗仍要关，普通标签折叠为静默（不再逐条留痕）。
    const base = classifyDevtoolsOpen(meta);
    return {
      action: base.decision === DEVTOOLS_CLOSE ? DEVTOOLS_CLOSE : DEVTOOLS_ALLOW,
      reason: base.decision === DEVTOOLS_CLOSE ? base.reason : 'devtools-flood',
      cooldown: true,
      state: s,
    };
  }
  const verdict = classifyDevtoolsOpen(meta);
  return { action: verdict.decision, reason: verdict.reason, cooldown: false, state: s };
}

module.exports = {
  DEVTOOLS_CLOSE,
  DEVTOOLS_AUDIT,
  DEVTOOLS_ALLOW,
  DEVTOOLS_BURST_MAX,
  DEVTOOLS_LONG_MAX,
  DEVTOOLS_COOLDOWN_MS,
  createDevtoolsState,
  resetForNavigation,
  admitToggle,
  classifyDevtoolsOpen,
  evaluateDevtoolsToggle,
};
