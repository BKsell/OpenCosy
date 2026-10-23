'use strict';

// notificationguard.js —— Notification 权限申请、弹窗频控、内容伪造与点击导航裁决内核。
//
// 威胁模型：
//   1. 系统通知带“操作系统级”可信度，恶意页面用它发伪造银行/安全告警，诱导点击进钓鱼站；
//   2. 无手势、后台或被拒后反复 requestPermission() 弹窗骚扰；
//   3. 高频通知轰炸，或在静默时段（深夜）弹窗；
//   4. 通知图标 URL 被当追踪信标，每次展示即向第三方上报 IP；
//   5. 标题/正文塞入伪造来源域名或控制字符，冒充系统/浏览器；
//   6. onclick 里跳到 javascript:/data: 或跨站钓鱼地址，且不带 noopener。
//
// 纯逻辑，不碰 DOM/系统 API。所有字符串处理均用字符操作，不用正则。

const N_ALLOW = 'allow';
const N_DENY = 'deny';
const N_PROMPT = 'prompt';

const N_REASON = Object.freeze({
  INSECURE_CONTEXT: 'n-insecure-context',
  BAD_ORIGIN: 'n-bad-origin',
  PERMISSION_DENIED: 'n-permission-denied',
  NO_GESTURE_PERMISSION: 'n-permission-requires-gesture',
  PERMISSION_THROTTLED: 'n-permission-throttled',
  PERMISSION_BLOCKED_ORIGIN: 'n-permission-origin-blocked',
  BACKGROUND_REQUEST: 'n-permission-background',
  FREQUENCY_EXCEEDED: 'n-frequency-exceeded',
  QUIET_HOURS: 'n-quiet-hours',
  ICON_DISALLOWED_SCHEME: 'n-icon-disallowed-scheme',
  ICON_THIRD_PARTY_TRACKER: 'n-icon-third-party-tracker',
  SPOOFED_SOURCE: 'n-spoofed-source-in-text',
  CONTROL_CHAR_IN_TEXT: 'n-control-char-in-text',
  CLICK_BAD_SCHEME: 'n-click-bad-scheme',
  CLICK_CROSS_ORIGIN: 'n-click-cross-origin',
});

function defaultNotificationPolicy() {
  return {
    requireSecureContext: true,
    permissionRequireGesture: true,
    denyBackgroundPermission: true,
    permissionMinIntervalMs: 60000,
    denyCooldownMs: 7 * 24 * 3600000,
    maxPerMinute: 6,
    maxPerHour: 30,
    quietHours: { startHour: 22, endHour: 8, forceBlock: true },
    allowHttpIcon: false,
    iconAllowSameOriginOnly: false,
    blockKnownTrackerHosts: [],
  };
}

// originKey 归一化 origin：仅接受 http/https，小写主机，拒绝带路径/查询。
function originKey(origin) {
  if (typeof origin !== 'string') return '';
  const idx = origin.indexOf('://');
  if (idx <= 0) return '';
  const scheme = origin.slice(0, idx).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') return '';
  const rest = origin.slice(idx + 3);
  if (rest === '' || rest.indexOf('/') >= 0 || rest.indexOf('?') >= 0 || rest.indexOf('#') >= 0) return '';
  return scheme + '://' + rest.toLowerCase();
}

function hostOf(origin) {
  const key = originKey(origin);
  if (!key) return '';
  return key.slice(key.indexOf('://') + 3);
}

// parseUrlScheme 返回小写 scheme；非法/无 scheme 返回空，纯字符判定。
function parseUrlScheme(url) {
  if (typeof url !== 'string') return '';
  const colon = url.indexOf(':');
  if (colon <= 0) return '';
  const pre = url.slice(0, colon);
  for (let i = 0; i < pre.length; i++) {
    const c = pre.charCodeAt(i);
    const alpha = (c >= 97 && c <= 122) || (c >= 65 && c <= 90);
    const digit = c >= 48 && c <= 57;
    const sym = c === 43 || c === 45 || c === 46;
    if (i === 0) {
      if (!alpha) return '';
    } else if (!alpha && !digit && !sym) {
      return '';
    }
  }
  return pre.toLowerCase();
}

function isControlChar(c) {
  return (c < 32 && c !== 9 && c !== 10) || c === 127;
}

function containsControlChar(s) {
  if (typeof s !== 'string') return false;
  for (let i = 0; i < s.length; i++) {
    if (isControlChar(s.charCodeAt(i))) return true;
  }
  return false;
}

function stripControlChars(s) {
  if (typeof s !== 'string') return '';
  let out = '';
  for (let i = 0; i < s.length; i++) {
    if (!isControlChar(s.charCodeAt(i))) out += s[i];
  }
  return out;
}

// textClaimsForeignDomain 检测文案是否用文字冒充其它品牌域，纯字符包含匹配。
function textClaimsForeignDomain(text, ownOrigin, spoofTokens) {
  if (typeof text !== 'string') return '';
  const lower = text.toLowerCase();
  const ownHost = hostOf(ownOrigin);
  const list = Array.isArray(spoofTokens) ? spoofTokens : [];
  for (const raw of list) {
    const t = String(raw).toLowerCase();
    if (t !== '' && lower.indexOf(t) >= 0 && !ownHost.endsWith(t)) return t;
  }
  return '';
}

class NotificationGuard {
  constructor(policy) {
    this.policy = policy || defaultNotificationPolicy();
    this.permissionLastAsk = new Map();
    this.denyUntil = new Map();
    this.permissionState = new Map();
    this.minuteEvents = new Map();
    this.hourEvents = new Map();
  }

  stateFor(origin) {
    return this.permissionState.get(originKey(origin)) || 'default';
  }

  markGranted(origin) {
    this.permissionState.set(originKey(origin), 'granted');
  }

  markDenied(origin, now) {
    const key = originKey(origin);
    this.permissionState.set(key, 'denied');
    this.denyUntil.set(key, (now || 0) + this.policy.denyCooldownMs);
  }

  _prune(list, now, windowMs) {
    let i = 0;
    while (i < list.length && now - list[i] > windowMs) i++;
    return list.slice(i);
  }

  // decidePermission 裁决一次 requestPermission。
  decidePermission(ctx) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { decision: N_DENY, reason: N_REASON.BAD_ORIGIN };
    if (pol.requireSecureContext && ctx.isSecureContext !== true) {
      return { decision: N_DENY, reason: N_REASON.INSECURE_CONTEXT };
    }
    const key = originKey(ctx.origin);
    if (!key) return { decision: N_DENY, reason: N_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { decision: N_DENY, reason: N_REASON.PERMISSION_BLOCKED_ORIGIN };

    const now = ctx.now || 0;
    const state = this.permissionState.get(key) || 'default';
    if (state === 'denied' && now < (this.denyUntil.get(key) || 0)) {
      return { decision: N_DENY, reason: N_REASON.PERMISSION_DENIED };
    }
    if (pol.denyBackgroundPermission && ctx.isBackground === true) {
      return { decision: N_DENY, reason: N_REASON.BACKGROUND_REQUEST };
    }
    if (pol.permissionRequireGesture && ctx.hasUserGesture !== true) {
      return { decision: N_DENY, reason: N_REASON.NO_GESTURE_PERMISSION };
    }
    if (this.permissionLastAsk.has(key) &&
      now - this.permissionLastAsk.get(key) < pol.permissionMinIntervalMs) {
      return { decision: N_DENY, reason: N_REASON.PERMISSION_THROTTLED };
    }
    this.permissionLastAsk.set(key, now);
    return { decision: N_PROMPT, reason: '' };
  }

  _inQuietHours(hourOfDay) {
    const q = this.policy.quietHours;
    if (!q || hourOfDay === undefined || hourOfDay === null) return false;
    if (q.startHour <= q.endHour) return hourOfDay >= q.startHour && hourOfDay < q.endHour;
    return hourOfDay >= q.startHour || hourOfDay < q.endHour;
  }

  // decideNotification 裁决是否允许弹出一条通知。
  decideNotification(ctx, n, spoofTokens) {
    const pol = this.policy;
    const key = originKey(ctx && ctx.origin);
    if (!key) return { allowed: false, reason: N_REASON.BAD_ORIGIN };
    if (this.stateFor(ctx.origin) !== 'granted') {
      return { allowed: false, reason: N_REASON.PERMISSION_DENIED };
    }
    const now = ctx.now || 0;
    if (pol.quietHours && pol.quietHours.forceBlock && this._inQuietHours(ctx.hourOfDay)) {
      return { allowed: false, reason: N_REASON.QUIET_HOURS };
    }

    const min = this._prune(this.minuteEvents.get(key) || [], now, 60000);
    const hour = this._prune(this.hourEvents.get(key) || [], now, 3600000);
    if (min.length >= pol.maxPerMinute || hour.length >= pol.maxPerHour) {
      return { allowed: false, reason: N_REASON.FREQUENCY_EXCEEDED };
    }

    const title = n && typeof n.title === 'string' ? n.title : '';
    const body = n && typeof n.body === 'string' ? n.body : '';
    if (containsControlChar(title) || containsControlChar(body)) {
      return { allowed: false, reason: N_REASON.CONTROL_CHAR_IN_TEXT };
    }
    const spoof = textClaimsForeignDomain(title + '\n' + body, ctx.origin, spoofTokens);
    if (spoof) return { allowed: false, reason: N_REASON.SPOOFED_SOURCE, token: spoof };

    if (n && typeof n.iconUrl === 'string' && n.iconUrl !== '') {
      const sch = parseUrlScheme(n.iconUrl);
      if (sch !== 'https' && !(sch === 'http' && pol.allowHttpIcon)) {
        return { allowed: false, reason: N_REASON.ICON_DISALLOWED_SCHEME };
      }
      const afterScheme = n.iconUrl.slice(sch.length + 3);
      const slash = afterScheme.indexOf('/');
      const iconHost = (slash >= 0 ? afterScheme.slice(0, slash) : afterScheme).toLowerCase();
      const ownHost = hostOf(ctx.origin);
      if (pol.iconAllowSameOriginOnly && iconHost !== '' && !ownHost.endsWith(iconHost)) {
        return { allowed: false, reason: N_REASON.ICON_THIRD_PARTY_TRACKER };
      }
      for (const bad of pol.blockKnownTrackerHosts) {
        if (iconHost.endsWith(String(bad).toLowerCase())) {
          return { allowed: false, reason: N_REASON.ICON_THIRD_PARTY_TRACKER };
        }
      }
    }

    min.push(now);
    hour.push(now);
    this.minuteEvents.set(key, min);
    this.hourEvents.set(key, hour);
    return { allowed: true, reason: '', safeTitle: stripControlChars(title), safeBody: stripControlChars(body) };
  }

  // decideClickNavigation 裁决通知点击后的导航。
  decideClickNavigation(origin, targetUrl) {
    const sch = parseUrlScheme(targetUrl);
    if (sch !== 'https' && sch !== 'http') {
      return { allowed: false, reason: N_REASON.CLICK_BAD_SCHEME };
    }
    const afterScheme = targetUrl.slice(sch.length + 3);
    const slash = afterScheme.indexOf('/');
    const targetHost = (slash >= 0 ? afterScheme.slice(0, slash) : afterScheme).toLowerCase();
    const ownHost = hostOf(origin);
    const same = targetHost === ownHost || ownHost.endsWith('.' + targetHost) || targetHost.endsWith('.' + ownHost);
    if (!same) {
      return { allowed: true, crossOrigin: true, noopener: true, reason: N_REASON.CLICK_CROSS_ORIGIN };
    }
    return { allowed: true, crossOrigin: false, noopener: true, reason: '' };
  }
}

module.exports = {
  N_ALLOW, N_DENY, N_PROMPT, N_REASON,
  defaultNotificationPolicy, originKey, hostOf, parseUrlScheme,
  containsControlChar, stripControlChars, textClaimsForeignDomain,
  NotificationGuard,
};
