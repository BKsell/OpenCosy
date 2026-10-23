'use strict';

// windowmanagementguard.js —— Window Management API（getScreenDetails / requestFullscreen({screen})）
// 多屏枚举与跨屏定位裁决内核。
//
// 威胁模型：
//   1. getScreenDetails() 返回用户所有显示器的数量、分辨率、排列、缩放、isInternal、label：
//      多屏布局（尤其 label 含厂商/型号）是稳定指纹，还能推断工位环境（外接显示器=办公）；
//   2. 拿到多屏后可 requestFullscreen({screen}) 在用户未注视的第二屏全屏弹出钓鱼/恐吓内容；
//   3. Window.open 时用窗口管理能力把窗口精确放到另一块屏幕或屏外，配合点击劫持；
//   4. 无手势枚举、三方/不可见页面订阅 screenschange 持续监听插拔（设备在场节律）；
//   5. 非安全上下文。
//
// 纯逻辑。

const WM_ALLOW = 'allow';
const WM_DENY = 'deny';

const WM_REASON = Object.freeze({
  BAD_CONTEXT: 'wm-bad-context',
  INSECURE_ORIGIN: 'wm-insecure-origin',
  NO_GESTURE: 'wm-no-gesture',
  THIRD_PARTY: 'wm-third-party',
  PERMISSION_DENIED: 'wm-permission-denied',
  LABEL_FINGERPRINT: 'wm-label-fingerprint',
  TOO_MANY_SCREENS: 'wm-too-many-screens',
  FULLSCREEN_OTHER_SCREEN: 'wm-fullscreen-other-screen',
  PLACE_OFFSCREEN: 'wm-place-offscreen',
  WATCH_IN_BACKGROUND: 'wm-watch-in-background',
});

function defaultWindowManagementPolicy() {
  return {
    requireHttps: true,
    requireUserGesture: true,
    blockThirdParty: true,
    permissionGranted: true,
    exposeLabels: false, // 不返回屏幕 label（型号指纹）
    maxScreensReport: 4,
    allowFullscreenOtherScreen: false,
    requireVisibleForWatch: true,
  };
}

function hasControlChar(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return true;
  }
  return false;
}

class WindowManagementGuard {
  constructor(policy) {
    this.policy = policy || defaultWindowManagementPolicy();
  }

  _gate(ctx, needGesture) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return WM_REASON.BAD_CONTEXT;
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return WM_REASON.INSECURE_ORIGIN;
    if (needGesture && pol.requireUserGesture && ctx.userGesture !== true) return WM_REASON.NO_GESTURE;
    if (pol.blockThirdParty && ctx.isTopFrame === false) return WM_REASON.THIRD_PARTY;
    return '';
  }

  // decideGetDetails 裁决 getScreenDetails()。screens 为物理屏信息数组。
  decideGetDetails(ctx, screens) {
    const bad = this._gate(ctx, true);
    if (bad) return { decision: WM_DENY, reason: bad };
    if (!this.policy.permissionGranted) return { decision: WM_DENY, reason: WM_REASON.PERMISSION_DENIED };
    if (!Array.isArray(screens)) return { decision: WM_DENY, reason: WM_REASON.BAD_CONTEXT };
    if (screens.length > this.policy.maxScreensReport) {
      return { decision: WM_DENY, reason: WM_REASON.TOO_MANY_SCREENS, count: screens.length };
    }
    // label 指纹面：默认不允许读取非空 label。
    if (!this.policy.exposeLabels) {
      for (const sc of screens) {
        if (sc && typeof sc.label === 'string' && sc.label.length > 0) {
          return { decision: WM_DENY, reason: WM_REASON.LABEL_FINGERPRINT };
        }
      }
    }
    return { decision: WM_ALLOW, reason: '' };
  }

  // decideFullscreen 裁决 requestFullscreen({screen})。targetScreenInternal=false 即投到别的屏。
  decideFullscreen(ctx, targetScreen) {
    const bad = this._gate(ctx, true);
    if (bad) return { decision: WM_DENY, reason: bad };
    if (!this.policy.permissionGranted) return { decision: WM_DENY, reason: WM_REASON.PERMISSION_DENIED };
    if (targetScreen && targetScreen.isInternal === false && !this.policy.allowFullscreenOtherScreen) {
      return { decision: WM_DENY, reason: WM_REASON.FULLSCREEN_OTHER_SCREEN };
    }
    return { decision: WM_ALLOW, reason: '' };
  }

  // decidePlaceWindow 裁决把新窗口放到指定屏幕/坐标。bounds:{screenIndex,x,y,withinVisible}
  decidePlaceWindow(ctx, bounds, screenCount) {
    const bad = this._gate(ctx, true);
    if (bad) return { decision: WM_DENY, reason: bad };
    if (bounds && bounds.withinVisible === false) return { decision: WM_DENY, reason: WM_REASON.PLACE_OFFSCREEN };
    if (typeof bounds.screenIndex === 'number' && typeof screenCount === 'number' &&
        (bounds.screenIndex < 0 || bounds.screenIndex >= screenCount)) {
      return { decision: WM_DENY, reason: WM_REASON.PLACE_OFFSCREEN, screenIndex: bounds.screenIndex };
    }
    return { decision: WM_ALLOW, reason: '' };
  }

  // decideWatch 裁决订阅 screenschange。
  decideWatch(ctx) {
    const bad = this._gate(ctx, false);
    if (bad) return { decision: WM_DENY, reason: bad };
    if (this.policy.requireVisibleForWatch && ctx.visible === false) {
      return { decision: WM_DENY, reason: WM_REASON.WATCH_IN_BACKGROUND };
    }
    return { decision: WM_ALLOW, reason: '' };
  }
}

module.exports = {
  WM_ALLOW, WM_DENY, WM_REASON,
  defaultWindowManagementPolicy, hasControlChar, WindowManagementGuard,
};
