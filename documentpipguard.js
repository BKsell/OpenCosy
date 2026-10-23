'use strict';

// documentpipguard.js —— Document Picture-in-Picture（documentPictureInPicture.requestWindow）
// 悬浮窗钓鱼与越权裁决内核。
//
// 威胁模型：
//   1. Document PiP 允许页面在始终置顶的小窗里渲染任意 DOM：可伪造系统/银行确认弹窗、
//      密码输入框、扫码登录，且窗口脱离原标签视觉边界，用户难以判断归属；
//   2. 初始宽高被设成接近全屏，把"小窗"做成覆盖式钓鱼层；
//   3. 页面不可见/失去焦点/无手势仍弹 PiP，属于后台强提醒与点击劫持；
//   4. PiP 窗里再申请 getUserMedia/全屏等高敏能力，或用 copyVideo 把主文档内容镜像过去；
//   5. 同一标签反复 requestWindow 制造多个置顶窗。
//
// 纯逻辑。

const DP_ALLOW = 'allow';
const DP_DENY = 'deny';

const DP_REASON = Object.freeze({
  BAD_CONTEXT: 'dp-bad-context',
  NO_GESTURE: 'dp-no-gesture',
  INSECURE_ORIGIN: 'dp-insecure-origin',
  OPEN_WHEN_HIDDEN: 'dp-open-when-hidden',
  WINDOW_TOO_LARGE: 'dp-window-too-large',
  DIMENSION_BAD: 'dp-dimension-bad',
  SENSITIVE_FEATURE_IN_PIP: 'dp-sensitive-feature-in-pip',
  COPY_VIDEO_DISABLED: 'dp-copy-video-disabled',
  TOO_MANY_WINDOWS: 'dp-too-many-windows',
});

function defaultDocumentPipPolicy() {
  return {
    requireHttps: false,
    requireUserGesture: true,
    requireVisible: true,
    maxWidth: 520,
    maxHeight: 360,
    maxWidthRatio: 0.5, // 相对屏幕
    maxHeightRatio: 0.5,
    blockSensitiveFeatures: ['camera', 'microphone', 'display-capture', 'fullscreen', 'payment', 'credentials'],
    blockCopyVideo: true,
    maxWindowsPerTab: 1,
  };
}

class DocumentPipGuard {
  constructor(policy) {
    this.policy = policy || defaultDocumentPipPolicy();
    this.openByTab = new Map();
  }

  // decideOpen 裁决 requestWindow(options)。
  // ctx: {origin, userGesture, visible, tabKey, screenWidth, screenHeight}
  // options: {width, height, copyStyleSheets, copyVideo, requestedFeatures:[...]}
  decideOpen(ctx, options) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return { decision: DP_DENY, reason: DP_REASON.BAD_CONTEXT };
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return { decision: DP_DENY, reason: DP_REASON.INSECURE_ORIGIN };
    if (pol.requireUserGesture && ctx.userGesture !== true) return { decision: DP_DENY, reason: DP_REASON.NO_GESTURE };
    if (pol.requireVisible && ctx.visible === false) return { decision: DP_DENY, reason: DP_REASON.OPEN_WHEN_HIDDEN };

    const tab = ctx.tabKey || ctx.origin;
    if ((this.openByTab.get(tab) || 0) >= pol.maxWindowsPerTab) {
      return { decision: DP_DENY, reason: DP_REASON.TOO_MANY_WINDOWS };
    }

    const o = options && typeof options === 'object' ? options : {};
    const w = o.width;
    const h = o.height;
    if (w !== undefined && (typeof w !== 'number' || w <= 0)) return { decision: DP_DENY, reason: DP_REASON.DIMENSION_BAD, field: 'width' };
    if (h !== undefined && (typeof h !== 'number' || h <= 0)) return { decision: DP_DENY, reason: DP_REASON.DIMENSION_BAD, field: 'height' };
    if (typeof w === 'number' && w > pol.maxWidth) return { decision: DP_DENY, reason: DP_REASON.WINDOW_TOO_LARGE, field: 'width', value: w };
    if (typeof h === 'number' && h > pol.maxHeight) return { decision: DP_DENY, reason: DP_REASON.WINDOW_TOO_LARGE, field: 'height', value: h };
    if (typeof ctx.screenWidth === 'number' && typeof w === 'number' && w > ctx.screenWidth * pol.maxWidthRatio) {
      return { decision: DP_DENY, reason: DP_REASON.WINDOW_TOO_LARGE, field: 'widthRatio' };
    }
    if (typeof ctx.screenHeight === 'number' && typeof h === 'number' && h > ctx.screenHeight * pol.maxHeightRatio) {
      return { decision: DP_DENY, reason: DP_REASON.WINDOW_TOO_LARGE, field: 'heightRatio' };
    }

    if (pol.blockCopyVideo && o.copyVideo === true) return { decision: DP_DENY, reason: DP_REASON.COPY_VIDEO_DISABLED };

    const feats = Array.isArray(o.requestedFeatures) ? o.requestedFeatures : [];
    for (const feat of feats) {
      if (pol.blockSensitiveFeatures.indexOf(feat) >= 0) {
        return { decision: DP_DENY, reason: DP_REASON.SENSITIVE_FEATURE_IN_PIP, feature: feat };
      }
    }

    this.openByTab.set(tab, (this.openByTab.get(tab) || 0) + 1);
    return { decision: DP_ALLOW, reason: '' };
  }

  close(ctx) {
    const tab = ctx && ctx.tabKey ? ctx.tabKey : (ctx && ctx.origin);
    const n = this.openByTab.get(tab) || 0;
    if (n > 0) this.openByTab.set(tab, n - 1);
  }
}

module.exports = {
  DP_ALLOW, DP_DENY, DP_REASON,
  defaultDocumentPipPolicy, DocumentPipGuard,
};
