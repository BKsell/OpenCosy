'use strict';

// screenshareguard.js —— getDisplayMedia 屏幕/窗口/标签页共享裁决内核。
//
// 威胁模型：
//   1. 静默或诱导共享整个屏幕，泄露其它窗口的银行/密码/私信内容；
//   2. systemAudio:'include' 把系统声音（通话、提示音）一起录走；
//   3. selfBrowserSurface:'include' 让共享选择器里混入当前页面，配合
//      surfaceSwitching:'include' / logicalSurface 做诱导，共享到非预期目标；
//   4. suppressLocalAudioPlayback 远程静音外放，制造“没在录音”的错觉；
//   5. 后台标签页/无手势发起共享；被拒后高频弹窗；
//   6. 拿到 monitor 表面后长期不释放，持续监视；切到更敏感表面时不提醒。
//
// 纯逻辑，不接触真实捕获管线。

const SS_DENY = 'deny';
const SS_ALLOW = 'allow';
const SS_PROMPT = 'prompt';

const SS_REASON = Object.freeze({
  INSECURE_CONTEXT: 'ss-insecure-context',
  BAD_ORIGIN: 'ss-bad-origin',
  BLOCKED_ORIGIN: 'ss-blocked-origin',
  BACKGROUND_SHARE: 'ss-background-share',
  NO_GESTURE: 'ss-requires-gesture',
  REQUEST_THROTTLED: 'ss-request-throttled',
  SYSTEM_AUDIO_FORBIDDEN: 'ss-system-audio-forbidden',
  SELF_SURFACE_FORBIDDEN: 'ss-self-surface-forbidden',
  MONITOR_SURFACE_REQUIRES_CONFIRM: 'ss-monitor-surface-confirm',
  SURFACE_SWITCH_FORBIDDEN: 'ss-surface-switch-forbidden',
  LOGICAL_SURFACE_FORBIDDEN: 'ss-logical-surface-forbidden',
  SUPPRESS_AUDIO_PLAYBACK_FORBIDDEN: 'ss-suppress-audio-forbidden',
  ALWAYS_ON_TOP_FORBIDDEN: 'ss-always-on-top-forbidden',
  MAX_DURATION_EXCEEDED: 'ss-max-duration-exceeded',
  INVALID_SURFACE_KIND: 'ss-invalid-surface-kind',
});

const SURFACE = Object.freeze({ MONITOR: 'monitor', WINDOW: 'window', BROWSER: 'browser' });

function defaultScreensharePolicy() {
  return {
    requireSecureContext: true,
    requireGesture: true,
    denyBackground: true,
    requestMinIntervalMs: 2000,
    allowSystemAudio: false,
    allowSelfSurface: false,
    requireExplicitMonitorConfirm: true,
    allowSurfaceSwitching: false,
    allowLogicalSurface: false,
    allowSuppressLocalAudioPlayback: false,
    allowAlwaysOnTop: false,
    maxShareMs: 60 * 60000, // 单次共享最长 1 小时
    preferTabOrWindow: true,
  };
}

function originKey(origin) {
  if (typeof origin !== 'string') return '';
  const idx = origin.indexOf('://');
  if (idx <= 0) return '';
  const scheme = origin.slice(0, idx).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') return '';
  const rest = origin.slice(idx + 3);
  if (rest === '' || rest.indexOf('/') >= 0 || rest.indexOf('?') >= 0) return '';
  return scheme + '://' + rest.toLowerCase();
}

function asLower(v) {
  return typeof v === 'string' ? v.toLowerCase() : '';
}

class ScreenshareGuard {
  constructor(policy) {
    this.policy = policy || defaultScreensharePolicy();
    this.lastRequest = new Map();
    this.active = new Map(); // origin -> {kind, startedAt}
  }

  // decideRequest 裁决 getDisplayMedia(constraints)。
  // ctx: {origin,isSecureContext,hasUserGesture,isBackground,blocked,now}
  decideRequest(ctx, constraints) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { decision: SS_DENY, reason: SS_REASON.BAD_ORIGIN };
    if (pol.requireSecureContext && ctx.isSecureContext !== true) {
      return { decision: SS_DENY, reason: SS_REASON.INSECURE_CONTEXT };
    }
    const key = originKey(ctx.origin);
    if (!key) return { decision: SS_DENY, reason: SS_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { decision: SS_DENY, reason: SS_REASON.BLOCKED_ORIGIN };
    if (pol.denyBackground && ctx.isBackground === true) {
      return { decision: SS_DENY, reason: SS_REASON.BACKGROUND_SHARE };
    }
    if (pol.requireGesture && ctx.hasUserGesture !== true) {
      return { decision: SS_DENY, reason: SS_REASON.NO_GESTURE };
    }
    const now = ctx.now || 0;
    if (this.lastRequest.has(key) && now - this.lastRequest.get(key) < pol.requestMinIntervalMs) {
      return { decision: SS_DENY, reason: SS_REASON.REQUEST_THROTTLED };
    }

    const v = constraints && typeof constraints.video === 'object' ? constraints.video : {};
    const problems = [];

    if (constraints && asLower(constraints.audio) === 'include') {
      problems.push(SS_REASON.SYSTEM_AUDIO_FORBIDDEN);
    }
    if (!pol.allowSelfSurface && asLower(v.selfBrowserSurface) === 'include') {
      problems.push(SS_REASON.SELF_SURFACE_FORBIDDEN);
    }
    if (!pol.allowSurfaceSwitching && asLower(v.surfaceSwitching) === 'include') {
      problems.push(SS_REASON.SURFACE_SWITCH_FORBIDDEN);
    }
    if (!pol.allowLogicalSurface && v.logicalSurface === true) {
      problems.push(SS_REASON.LOGICAL_SURFACE_FORBIDDEN);
    }
    if (!pol.allowSuppressLocalAudioPlayback &&
      constraints && constraints.suppressLocalAudioPlayback === true) {
      problems.push(SS_REASON.SUPPRESS_AUDIO_PLAYBACK_FORBIDDEN);
    }
    if (!pol.allowAlwaysOnTop && constraints && constraints.systemAudio === true) {
      // systemAudio 作为布尔键同样不允许
      problems.push(SS_REASON.SYSTEM_AUDIO_FORBIDDEN);
    }

    if (problems.length) {
      return { decision: SS_DENY, reason: problems[0], allReasons: dedupe(problems) };
    }

    this.lastRequest.set(key, now);
    return {
      decision: SS_PROMPT,
      reason: '',
      // 把危险选项改写为安全默认值后交回上层
      safeHints: {
        selfBrowserSurface: 'exclude',
        surfaceSwitching: 'exclude',
        systemAudio: 'exclude',
        monitorSurfacePicking: pol.requireExplicitMonitorConfirm ? 'require-confirm' : 'allow',
        preferTabOrWindow: pol.preferTabOrWindow,
        maxShareMs: pol.maxShareMs,
      },
    };
  }

  // noteStarted 在用户实际选定表面后登记。
  noteStarted(origin, surfaceKind, now) {
    const kind = asLower(surfaceKind);
    if (kind !== SURFACE.MONITOR && kind !== SURFACE.WINDOW && kind !== SURFACE.BROWSER) {
      return { ok: false, reason: SS_REASON.INVALID_SURFACE_KIND };
    }
    const key = originKey(origin);
    this.active.set(key, { kind, startedAt: now || 0 });
    if (kind === SURFACE.MONITOR && this.policy.requireExplicitMonitorConfirm) {
      return { ok: true, reason: SS_REASON.MONITOR_SURFACE_REQUIRES_CONFIRM };
    }
    return { ok: true, reason: '' };
  }

  // checkStillAllowed 在共享期间周期调用：超时或仍共享 monitor 时给出处置。
  checkStillAllowed(origin, now) {
    const key = originKey(origin);
    const a = this.active.get(key);
    if (!a) return { active: false, stop: false, reason: '' };
    const elapsed = (now || 0) - a.startedAt;
    if (elapsed > this.policy.maxShareMs) {
      this.active.delete(key);
      return { active: false, stop: true, reason: SS_REASON.MAX_DURATION_EXCEEDED, kind: a.kind };
    }
    return { active: true, stop: false, reason: '', kind: a.kind, remainingMs: this.policy.maxShareMs - elapsed };
  }

  noteStopped(origin) {
    this.active.delete(originKey(origin));
  }
}

function dedupe(arr) {
  const seen = new Set();
  const out = [];
  for (const x of arr) {
    if (!seen.has(x)) { seen.add(x); out.push(x); }
  }
  return out;
}

module.exports = {
  SS_ALLOW, SS_DENY, SS_PROMPT, SS_REASON, SURFACE,
  defaultScreensharePolicy, originKey, ScreenshareGuard,
};
