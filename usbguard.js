'use strict';

// usbguard.js —— WebUSB（navigator.usb.requestDevice）授权裁决内核。
//
// 威胁模型：
//   1. 空 filter（{}）匹配任意设备，页面可枚举全部 USB 设备的 idVendor/idProduct/序列号，
//      形成跨站硬件指纹，并据此识别公司内网环境、安全令牌、调试器是否在线；
//   2. 大容量存储（class 0x08）、智能卡（0x0b）、厂商自定义（0xff，常见于调试器/烧录器/
//      加密狗）一旦被页面 claimInterface，可被读写固件、劫持升级通道或窃取卡内数据；
//   3. serialNumber 精确过滤用于把特定物理设备/个人长期绑定到画像；
//   4. 越界的 vendorId/productId/class 字段是调用方构造的脏数据，下游可能越界索引；
//   5. 后台标签或无手势弹窗构成设备选择器点击劫持。
//
// 纯逻辑。

const USB_ALLOW = 'allow';
const USB_DENY = 'deny';

const USB_REASON = Object.freeze({
  BAD_CONTEXT: 'usb-bad-context',
  NO_GESTURE: 'usb-no-gesture',
  CROSS_ORIGIN_SUBFRAME: 'usb-cross-origin-subframe',
  INSECURE_ORIGIN: 'usb-insecure-origin',
  EMPTY_FILTER_MATCHES_ALL: 'usb-empty-filter-matches-all',
  NO_FILTER: 'usb-no-filter',
  BAD_ID_RANGE: 'usb-bad-id-range',
  BAD_CLASS_RANGE: 'usb-class-range',
  CLASS_BLOCKED: 'usb-class-blocked',
  VENDOR_NOT_ALLOWED: 'usb-vendor-not-allowed',
  SERIAL_FINGERPRINT: 'usb-serial-fingerprint',
  TOO_MANY_FILTERS: 'usb-too-many-filters',
});

// 高风险 USB 接口/设备类（bDeviceClass / bInterfaceClass）。
const USB_BLOCKED_CLASSES = Object.freeze([
  0x02, // 通信与 CDC 控制（调制解调器、网卡控制面）
  0x08, // 大容量存储
  0x0b, // 智能卡 / 芯片卡（CCID）
  0x0e, // 视频（UVC 摄像头）
  0x10, // 音视频控制
  0xef, // 杂项（含 Billboard、设备身份）
  0xff, // 厂商自定义（调试器/烧录器/加密狗高发区）
]);

function defaultUsbPolicy() {
  return {
    requireHttps: true,
    requireUserGesture: true,
    blockCrossOriginSubframe: true,
    requireNonEmptyFilter: true,
    allowedVendorIds: [], // 空数组=不按厂商限制，仍受 class 黑名单约束
    blockedClasses: USB_BLOCKED_CLASSES.slice(),
    blockSerialNumberFilter: true,
    maxFilters: 8,
  };
}

function isUint16(v) {
  return typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 0xffff;
}

function isUint8(v) {
  return typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 0xff;
}

// filterHasConstraint 判断过滤器是否至少含一个真实约束。
function filterHasConstraint(f) {
  if (!f || typeof f !== 'object') return false;
  const keys = ['vendorId', 'productId', 'classCode', 'subclassCode', 'protocolCode', 'serialNumber'];
  for (const k of keys) {
    if (f[k] !== undefined && f[k] !== null) return true;
  }
  return false;
}

class UsbGuard {
  constructor(policy) {
    this.policy = policy || defaultUsbPolicy();
  }

  // decideRequest 裁决 requestDevice({filters})。
  // ctx: {origin, isTopFrame, userGesture}
  decideRequest(ctx, options) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') {
      return { decision: USB_DENY, reason: USB_REASON.BAD_CONTEXT };
    }
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) {
      return { decision: USB_DENY, reason: USB_REASON.INSECURE_ORIGIN };
    }
    if (pol.requireUserGesture && ctx.userGesture !== true) {
      return { decision: USB_DENY, reason: USB_REASON.NO_GESTURE };
    }
    if (pol.blockCrossOriginSubframe && ctx.isTopFrame === false) {
      return { decision: USB_DENY, reason: USB_REASON.CROSS_ORIGIN_SUBFRAME };
    }

    const opt = options && typeof options === 'object' ? options : {};
    const filters = Array.isArray(opt.filters) ? opt.filters : null;
    if (filters === null || filters.length === 0) {
      return { decision: USB_DENY, reason: USB_REASON.NO_FILTER };
    }
    if (filters.length > pol.maxFilters) {
      return { decision: USB_DENY, reason: USB_REASON.TOO_MANY_FILTERS, count: filters.length };
    }

    for (let i = 0; i < filters.length; i++) {
      const f = filters[i];
      if (pol.requireNonEmptyFilter && !filterHasConstraint(f)) {
        return { decision: USB_DENY, reason: USB_REASON.EMPTY_FILTER_MATCHES_ALL, index: i };
      }

      if (f.vendorId !== undefined) {
        if (!isUint16(f.vendorId)) return { decision: USB_DENY, reason: USB_REASON.BAD_ID_RANGE, index: i, field: 'vendorId' };
        if (pol.allowedVendorIds.length > 0 && pol.allowedVendorIds.indexOf(f.vendorId) < 0) {
          return { decision: USB_DENY, reason: USB_REASON.VENDOR_NOT_ALLOWED, index: i, vendorId: f.vendorId };
        }
      }
      if (f.productId !== undefined && !isUint16(f.productId)) {
        return { decision: USB_DENY, reason: USB_REASON.BAD_ID_RANGE, index: i, field: 'productId' };
      }

      const classFields = ['classCode', 'subclassCode', 'protocolCode'];
      for (const cf of classFields) {
        if (f[cf] !== undefined && !isUint8(f[cf])) {
          return { decision: USB_DENY, reason: USB_REASON.BAD_CLASS_RANGE, index: i, field: cf };
        }
      }
      if (f.classCode !== undefined && pol.blockedClasses.indexOf(f.classCode) >= 0) {
        return { decision: USB_DENY, reason: USB_REASON.CLASS_BLOCKED, index: i, classCode: f.classCode };
      }

      if (pol.blockSerialNumberFilter && typeof f.serialNumber === 'string' && f.serialNumber.length > 0) {
        return { decision: USB_DENY, reason: USB_REASON.SERIAL_FINGERPRINT, index: i };
      }
    }

    return { decision: USB_ALLOW, reason: '' };
  }

  // claimInterface 在页面要独占某接口前再按接口类拦一道（设备类可能为 0 而接口类非 0）。
  claimInterface(interfaceClass) {
    if (!isUint8(interfaceClass)) return { decision: USB_DENY, reason: USB_REASON.BAD_CLASS_RANGE };
    if (this.policy.blockedClasses.indexOf(interfaceClass) >= 0) {
      return { decision: USB_DENY, reason: USB_REASON.CLASS_BLOCKED, classCode: interfaceClass };
    }
    return { decision: USB_ALLOW, reason: '' };
  }
}

module.exports = {
  USB_ALLOW, USB_DENY, USB_REASON, USB_BLOCKED_CLASSES,
  defaultUsbPolicy, isUint16, isUint8, filterHasConstraint, UsbGuard,
};
