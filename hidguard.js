'use strict';

// hidguard.js —— WebHID（navigator.hid.requestDevice）授权裁决内核。
//
// 威胁模型：
//   1. HID 是裸报文通道：拿到键盘/鼠标类设备（Generic Desktop usagePage 0x07）的页面可以
//      收发原始报文，等同于 keylogger / 按键注入，浏览器同源策略与表单保护全部失效；
//   2. FIDO/安全密钥类（usagePage 0xF1D0）被 claim 后可与认证设备交换报文，劫持第二因素；
//   3. 空 filter 或只给 vendorId 会把该厂商所有设备（含复合设备的键盘/密钥接口）暴露；
//   4. collections 可无限嵌套，过深或过宽的集合约束是脏数据，且可能让上层递归爆栈；
//   5. 越界 usagePage/usage/vendorId 是非法输入。
//
// 纯逻辑，对 collections 做有界深度递归。

const HID_ALLOW = 'allow';
const HID_DENY = 'deny';

const HID_REASON = Object.freeze({
  BAD_CONTEXT: 'hid-bad-context',
  NO_GESTURE: 'hid-no-gesture',
  CROSS_ORIGIN_SUBFRAME: 'hid-cross-origin-subframe',
  INSECURE_ORIGIN: 'hid-insecure-origin',
  NO_FILTER: 'hid-no-filter',
  EMPTY_FILTER: 'hid-empty-filter',
  BAD_ID_RANGE: 'hid-bad-id-range',
  BAD_USAGE_RANGE: 'hid-bad-usage-range',
  VENDOR_NOT_ALLOWED: 'hid-vendor-not-allowed',
  BLOCKED_USAGE_PAGE: 'hid-blocked-usage-page',
  COLLECTION_TOO_DEEP: 'hid-collection-too-deep',
  TOO_MANY_COLLECTIONS: 'hid-too-many-collections',
  TOO_MANY_FILTERS: 'hid-too-many-filters',
});

// 高敏 HID Usage Page。
const HID_PAGE_GENERIC_DESKTOP = 0x01; // 键盘(0x06)/鼠标(0x02) 在该页
const HID_PAGE_KEYBOARD_KEYPAD = 0x07;
const HID_PAGE_FIDO = 0xf1d0;
const HID_BLOCKED_PAGES = Object.freeze([HID_PAGE_GENERIC_DESKTOP, HID_PAGE_KEYBOARD_KEYPAD, HID_PAGE_FIDO]);
// Generic Desktop 内需要单独点杀的 usage。
const HID_GD_KEYBOARD = 0x06;
const HID_GD_KEYPAD = 0x07;

function defaultHidPolicy() {
  return {
    requireHttps: true,
    requireUserGesture: true,
    blockCrossOriginSubframe: true,
    requireNonEmptyFilter: true,
    allowedVendorIds: [],
    blockedUsagePages: HID_BLOCKED_PAGES.slice(),
    maxCollectionDepth: 4,
    maxCollectionsPerFilter: 32,
    maxFilters: 8,
  };
}

function isUint16(v) {
  return typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 0xffff;
}

// usageBlocked 判定单个 usagePage/usage 是否命中黑名单。
function usageBlocked(page, usage, policy) {
  if (page === undefined) return false;
  if (policy.blockedUsagePages.indexOf(page) >= 0) {
    // Generic Desktop 只点杀键盘/小键盘 usage；其余两页整页拦截。
    if (page === HID_PAGE_GENERIC_DESKTOP && usage !== undefined &&
        usage !== HID_GD_KEYBOARD && usage !== HID_GD_KEYPAD) {
      return false;
    }
    return true;
  }
  return false;
}

// scanCollection 有界递归检查集合树，返回 {ok, reason, depth, count}。
function scanCollection(col, depth, stats, policy) {
  if (depth > policy.maxCollectionDepth) return { ok: false, reason: HID_REASON.COLLECTION_TOO_DEEP };
  stats.count++;
  if (stats.count > policy.maxCollectionsPerFilter) {
    return { ok: false, reason: HID_REASON.TOO_MANY_COLLECTIONS };
  }
  if (!col || typeof col !== 'object') return { ok: true };

  if (col.usagePage !== undefined) {
    if (!isUint16(col.usagePage)) return { ok: false, reason: HID_REASON.BAD_USAGE_RANGE, field: 'usagePage' };
    if (usageBlocked(col.usagePage, col.usage, policy)) {
      return { ok: false, reason: HID_REASON.BLOCKED_USAGE_PAGE, usagePage: col.usagePage };
    }
  }
  if (col.usage !== undefined && !isUint16(col.usage)) {
    return { ok: false, reason: HID_REASON.BAD_USAGE_RANGE, field: 'usage' };
  }

  const children = Array.isArray(col.children) ? col.children : [];
  for (const child of children) {
    const r = scanCollection(child, depth + 1, stats, policy);
    if (!r.ok) return r;
  }
  return { ok: true };
}

class HidGuard {
  constructor(policy) {
    this.policy = policy || defaultHidPolicy();
  }

  // decideRequest 裁决 requestDevice({filters})。
  decideRequest(ctx, options) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') {
      return { decision: HID_DENY, reason: HID_REASON.BAD_CONTEXT };
    }
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) {
      return { decision: HID_DENY, reason: HID_REASON.INSECURE_ORIGIN };
    }
    if (pol.requireUserGesture && ctx.userGesture !== true) {
      return { decision: HID_DENY, reason: HID_REASON.NO_GESTURE };
    }
    if (pol.blockCrossOriginSubframe && ctx.isTopFrame === false) {
      return { decision: HID_DENY, reason: HID_REASON.CROSS_ORIGIN_SUBFRAME };
    }

    const opt = options && typeof options === 'object' ? options : {};
    const filters = Array.isArray(opt.filters) ? opt.filters : null;
    if (filters === null || filters.length === 0) {
      return { decision: HID_DENY, reason: HID_REASON.NO_FILTER };
    }
    if (filters.length > pol.maxFilters) {
      return { decision: HID_DENY, reason: HID_REASON.TOO_MANY_FILTERS, count: filters.length };
    }

    for (let i = 0; i < filters.length; i++) {
      const f = filters[i];
      const hasTopConstraint = f && typeof f === 'object' &&
        (f.vendorId !== undefined || f.productId !== undefined ||
         f.usagePage !== undefined || f.usage !== undefined ||
         (Array.isArray(f.collections) && f.collections.length > 0));
      if (pol.requireNonEmptyFilter && !hasTopConstraint) {
        return { decision: HID_DENY, reason: HID_REASON.EMPTY_FILTER, index: i };
      }
      if (!f || typeof f !== 'object') continue; // 已在上面处理空约束

      if (f.vendorId !== undefined) {
        if (!isUint16(f.vendorId)) return { decision: HID_DENY, reason: HID_REASON.BAD_ID_RANGE, index: i, field: 'vendorId' };
        if (pol.allowedVendorIds.length > 0 && pol.allowedVendorIds.indexOf(f.vendorId) < 0) {
          return { decision: HID_DENY, reason: HID_REASON.VENDOR_NOT_ALLOWED, index: i, vendorId: f.vendorId };
        }
      }
      if (f.productId !== undefined && !isUint16(f.productId)) {
        return { decision: HID_DENY, reason: HID_REASON.BAD_ID_RANGE, index: i, field: 'productId' };
      }
      if (f.usagePage !== undefined) {
        if (!isUint16(f.usagePage)) return { decision: HID_DENY, reason: HID_REASON.BAD_USAGE_RANGE, index: i, field: 'usagePage' };
        if (usageBlocked(f.usagePage, f.usage, pol)) {
          return { decision: HID_DENY, reason: HID_REASON.BLOCKED_USAGE_PAGE, index: i, usagePage: f.usagePage };
        }
      }
      if (f.usage !== undefined && !isUint16(f.usage)) {
        return { decision: HID_DENY, reason: HID_REASON.BAD_USAGE_RANGE, index: i, field: 'usage' };
      }

      const collections = Array.isArray(f.collections) ? f.collections : [];
      const stats = { count: 0 };
      for (const col of collections) {
        const r = scanCollection(col, 1, stats, pol);
        if (!r.ok) return Object.assign({ decision: HID_DENY, index: i }, r);
      }
    }
    return { decision: HID_ALLOW, reason: '' };
  }
}

module.exports = {
  HID_ALLOW, HID_DENY, HID_REASON,
  HID_PAGE_GENERIC_DESKTOP, HID_PAGE_KEYBOARD_KEYPAD, HID_PAGE_FIDO,
  HID_GD_KEYBOARD, HID_GD_KEYPAD, HID_BLOCKED_PAGES,
  defaultHidPolicy, isUint16, usageBlocked, scanCollection, HidGuard,
};
