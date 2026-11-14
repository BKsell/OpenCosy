'use strict';

const {
  CHILD_ALLOW,
  CHILD_BURST_MAX,
  CHILD_BURST_WINDOW_MS,
  CHILD_CLOSE,
  CHILD_ISOLATE,
  CHILD_LONG_WINDOW_MS,
  evaluateChildUrl,
  evaluateWebPreferences
} = require('./childwindowguard_rules_core');

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

function resetForNavigation(st) {
  if (!st) return createChildWindowState();
  st.burstStart = -1;
  st.burstCount = 0;
  st.longStart = -1;
  st.longCount = 0;
  st.cooldownUntil = 0;
  return st;
}

// resetForNavigation 在顶层导航后调用：开窗洪泛属于页面行为，换文档后配额归零。
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
  CHILD_ALLOW,
  CHILD_CLOSE,
  CHILD_ISOLATE,
  admitChildWindow,
  createChildWindowState,
  evaluateChildWindow,
  resetForNavigation,
};
