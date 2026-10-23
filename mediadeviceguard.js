'use strict';

// mediadeviceguard.js —— mediaDevices 枚举与采集裁决内核。
//
// 威胁模型：
//   1. enumerateDevices() 在未授权时若返回带 label 的完整设备清单，可指纹追踪
//      （摄像头/麦克风/耳机型号组合是稳定硬件指纹），并泄露外设隐私；
//   2. deviceId 在清除浏览数据后仍稳定（groupIds 关联），形成长期追踪标识；
//   3. getUserMedia 约束可强制开启高清/宽动态/多摄像头，绕过用户对“最小采集”的预期；
//   4. 非安全上下文、无手势、后台标签页静默开麦/开摄像头；
//   5. 音频 channelCount/echoCancellation/noiseSuppression 组合、exact 约束被用于
//      探测具体设备能力做指纹；
//   6. 被拒后高频 enumerate/request 轮询骚扰授权弹窗。
//
// 纯逻辑模块，不接触真实媒体栈。

const MD_DENY = 'deny';
const MD_ALLOW = 'allow';
const MD_PROMPT = 'prompt';

const MD_REASON = Object.freeze({
  INSECURE_CONTEXT: 'md-insecure-context',
  BAD_ORIGIN: 'md-bad-origin',
  BLOCKED_ORIGIN: 'md-blocked-origin',
  BACKGROUND_CAPTURE: 'md-background-capture',
  NO_GESTURE: 'md-requires-gesture',
  PERMISSION_DENIED: 'md-permission-denied',
  ENUM_THROTTLED: 'md-enumerate-throttled',
  REQUEST_THROTTLED: 'md-request-throttled',
  UNKNOWN_KIND: 'md-unknown-device-kind',
  EXACT_CONSTRAINT_FORBIDDEN: 'md-exact-constraint-forbidden',
  EXCESSIVE_RESOLUTION: 'md-excessive-resolution',
  EXCESSIVE_FPS: 'md-excessive-fps',
  TOO_MANY_DEVICES: 'md-too-many-devices',
  TORCH_NOT_ALLOWED: 'md-torch-not-allowed',
  BACKGROUND_BLUR_FINGERPRINT: 'md-background-blur-fingerprint',
});

function defaultMediaPolicy() {
  return {
    requireSecureContext: true,
    requireGestureForRequest: true,
    denyBackground: true,
    labelsRequireGrant: true, // 未授予对应权限时不暴露 label/groupId
    enumerateMinIntervalMs: 250,
    requestMinIntervalMs: 1500,
    maxVideoWidth: 1280,
    maxVideoHeight: 720,
    maxFrameRate: 30,
    maxConcurrentTracks: 4,
    allowExactOnResolution: false,
    allowTorch: false,
    allowBackgroundBlurProbe: false,
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

const KINDS = Object.freeze({ audioinput: true, videoinput: true, audiooutput: true });

// numConstraint 取 ideal/exact/min/max 里出现的数值上限（纯字段读取）。
function numConstraint(obj) {
  if (typeof obj === 'number') return { value: obj, exact: false };
  if (obj && typeof obj === 'object') {
    if (typeof obj.exact === 'number') return { value: obj.exact, exact: true };
    if (typeof obj.ideal === 'number') return { value: obj.ideal, exact: false };
    if (typeof obj.max === 'number') return { value: obj.max, exact: false };
    if (typeof obj.min === 'number') return { value: obj.min, exact: true };
  }
  return null;
}

// redactDevices 按授权状态脱敏枚举结果：未授权时清空 label 与 groupId，
// deviceId 置为统一空串，仅保留 kind 与数量（数量本身也可能指纹，由调用方决定是否裁剪）。
function redactDevices(devices, grantedKinds, policy) {
  const granted = grantedKinds || {};
  const out = [];
  for (const d of devices || []) {
    if (!d || !KINDS[d.kind]) continue;
    if (policy.labelsRequireGrant && granted[d.kind] !== true) {
      out.push({ deviceId: '', kind: d.kind, label: '', groupId: '' });
    } else {
      out.push({
        deviceId: d.deviceId || '',
        kind: d.kind,
        label: d.label || '',
        groupId: d.groupId || '',
      });
    }
  }
  return out;
}

class MediaDeviceGuard {
  constructor(policy) {
    this.policy = policy || defaultMediaPolicy();
    this.lastEnum = new Map();
    this.lastRequest = new Map();
    this.permission = new Map(); // origin -> {audio,video}
    this.trackCount = new Map();
  }

  setPermission(origin, kind, granted) {
    const key = originKey(origin);
    const cur = this.permission.get(key) || {};
    cur[kind] = granted === true;
    this.permission.set(key, cur);
  }

  // decideEnumerate 裁决 enumerateDevices 调用（主要做频控）。
  decideEnumerate(ctx) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { decision: MD_DENY, reason: MD_REASON.BAD_ORIGIN };
    if (pol.requireSecureContext && ctx.isSecureContext !== true) {
      return { decision: MD_DENY, reason: MD_REASON.INSECURE_CONTEXT };
    }
    const key = originKey(ctx.origin);
    if (!key) return { decision: MD_DENY, reason: MD_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { decision: MD_DENY, reason: MD_REASON.BLOCKED_ORIGIN };
    const now = ctx.now || 0;
    if (this.lastEnum.has(key) && now - this.lastEnum.get(key) < pol.enumerateMinIntervalMs) {
      return { decision: MD_DENY, reason: MD_REASON.ENUM_THROTTLED };
    }
    this.lastEnum.set(key, now);
    return { decision: MD_ALLOW, reason: '' };
  }

  _checkVideo(constraints, problems) {
    const pol = this.policy;
    const v = constraints.video;
    if (v === true || v === undefined || v === null) return;
    if (typeof v !== 'object') return;
    for (const field of ['width', 'height']) {
      const n = numConstraint(v[field]);
      if (n) {
        if (n.exact && !pol.allowExactOnResolution) problems.push(MD_REASON.EXACT_CONSTRAINT_FORBIDDEN);
        const limit = field === 'width' ? pol.maxVideoWidth : pol.maxVideoHeight;
        if (n.value > limit) problems.push(field === 'width' ? MD_REASON.EXCESSIVE_RESOLUTION : MD_REASON.EXCESSIVE_RESOLUTION);
      }
    }
    const fps = numConstraint(v.frameRate);
    if (fps) {
      if (fps.exact && !pol.allowExactOnResolution) problems.push(MD_REASON.EXACT_CONSTRAINT_FORBIDDEN);
      if (fps.value > pol.maxFrameRate) problems.push(MD_REASON.EXCESSIVE_FPS);
    }
    if (v.torch === true && !pol.allowTorch) problems.push(MD_REASON.TORCH_NOT_ALLOWED);
    if ((v.backgroundBlur !== undefined || v.pan !== undefined || v.tilt !== undefined || v.zoom !== undefined)
      && !pol.allowBackgroundBlurProbe) {
      problems.push(MD_REASON.BACKGROUND_BLUR_FINGERPRINT);
    }
  }

  // decideRequest 裁决 getUserMedia 约束。
  decideRequest(ctx, constraints) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { decision: MD_DENY, reason: MD_REASON.BAD_ORIGIN };
    if (pol.requireSecureContext && ctx.isSecureContext !== true) {
      return { decision: MD_DENY, reason: MD_REASON.INSECURE_CONTEXT };
    }
    const key = originKey(ctx.origin);
    if (!key) return { decision: MD_DENY, reason: MD_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { decision: MD_DENY, reason: MD_REASON.BLOCKED_ORIGIN };
    if (pol.denyBackground && ctx.isBackground === true) {
      return { decision: MD_DENY, reason: MD_REASON.BACKGROUND_CAPTURE };
    }
    if (pol.requireGestureForRequest && ctx.hasUserGesture !== true) {
      return { decision: MD_DENY, reason: MD_REASON.NO_GESTURE };
    }
    const now = ctx.now || 0;
    if (this.lastRequest.has(key) && now - this.lastRequest.get(key) < pol.requestMinIntervalMs) {
      return { decision: MD_DENY, reason: MD_REASON.REQUEST_THROTTLED };
    }

    const wantsAudio = constraints && (constraints.audio === true || (constraints.audio && typeof constraints.audio === 'object'));
    const wantsVideo = constraints && (constraints.video === true || (constraints.video && typeof constraints.video === 'object'));
    if (!wantsAudio && !wantsVideo) return { decision: MD_DENY, reason: MD_REASON.UNKNOWN_KIND };

    const problems = [];
    if (constraints && typeof constraints === 'object') {
      if (constraints.audio && typeof constraints.audio === 'object') {
        if (constraints.audio.deviceId && typeof constraints.audio.deviceId === 'object' &&
          constraints.audio.deviceId.exact && !pol.allowExactOnResolution) {
          problems.push(MD_REASON.EXACT_CONSTRAINT_FORBIDDEN);
        }
      }
      this._checkVideo(constraints, problems);
    }

    const cur = this.trackCount.get(key) || 0;
    const addTracks = (wantsAudio ? 1 : 0) + (wantsVideo ? 1 : 0);
    if (cur + addTracks > pol.maxConcurrentTracks) problems.push(MD_REASON.TOO_MANY_DEVICES);

    if (problems.length) {
      return { decision: MD_DENY, reason: problems[0], allReasons: dedupe(problems) };
    }
    this.lastRequest.set(key, now);
    return {
      decision: MD_PROMPT,
      reason: '',
      wantsAudio: !!wantsAudio,
      wantsVideo: !!wantsVideo,
      clamped: clampConstraints(constraints, pol),
    };
  }

  noteTracksStarted(origin, n) {
    const key = originKey(origin);
    this.trackCount.set(key, (this.trackCount.get(key) || 0) + (n || 0));
  }
  noteTracksStopped(origin, n) {
    const key = originKey(origin);
    this.trackCount.set(key, Math.max(0, (this.trackCount.get(key) || 0) - (n || 0)));
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

// clampConstraints 把分辨率/帧率上限收敛到策略值，保留 ideal 语义、去掉 exact。
function clampConstraints(constraints, pol) {
  if (!constraints || typeof constraints !== 'object') return constraints;
  const out = { audio: constraints.audio, video: undefined };
  const v = constraints.video;
  if (v === true) {
    out.video = { width: { ideal: pol.maxVideoWidth }, height: { ideal: pol.maxVideoHeight }, frameRate: { ideal: pol.maxFrameRate } };
  } else if (v && typeof v === 'object') {
    const nv = {};
    const w = numConstraint(v.width);
    const h = numConstraint(v.height);
    const f = numConstraint(v.frameRate);
    if (w) nv.width = { ideal: Math.min(w.value, pol.maxVideoWidth) };
    if (h) nv.height = { ideal: Math.min(h.value, pol.maxVideoHeight) };
    if (f) nv.frameRate = { ideal: Math.min(f.value, pol.maxFrameRate) };
    if (v.deviceId && typeof v.deviceId === 'string') nv.deviceId = { ideal: v.deviceId };
    if (v.facingMode) nv.facingMode = typeof v.facingMode === 'object' && v.facingMode.exact ? { ideal: v.facingMode.exact } : v.facingMode;
    out.video = nv;
  }
  return out;
}

module.exports = {
  MD_ALLOW, MD_DENY, MD_PROMPT, MD_REASON,
  defaultMediaPolicy, originKey, redactDevices, numConstraint, clampConstraints,
  MediaDeviceGuard,
};
