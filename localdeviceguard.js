'use strict';

// localdeviceguard.js —— WebUSB / WebHID / Web Serial / Web Bluetooth 权限裁决内核。
//
// 威胁模型：
//   1. requestDevice/requestPort 在无手势、失焦、后台时弹设备选择器做点击劫持；
//   2. acceptAllDevices/空 filters + 无 optionalServices 限制 = “枚举并接管所有外设”；
//   3. 敏感 USB 类（0x08 大容量存储、0x03 HID 键盘、0xFF vendor 专用）可被用于
//      BadUSB 击键注入、读写 U 盘、刷写固件；
//   4. 蓝牙 GATT 敏感服务（0x1812 HID over GATT、0x180F 电池、0x180A 设备信息）
//      暴露设备指纹与控制能力；
//   5. 设备 vendorId/productId 集合形成硬件指纹；串口波特率/缓冲区异常；
//   6. 拿到句柄后长期不断开，后台持续读写。
//
// 纯逻辑；vid/pid/UUID 比较全用字符与数字运算。

const LD_DENY = 'deny';
const LD_PROMPT = 'prompt';

const LD_REASON = Object.freeze({
  INSECURE_CONTEXT: 'ld-insecure-context',
  BAD_ORIGIN: 'ld-bad-origin',
  BLOCKED_ORIGIN: 'ld-blocked-origin',
  NO_GESTURE: 'ld-requires-gesture',
  NOT_FOCUSED: 'ld-not-focused',
  BACKGROUND: 'ld-background',
  PICKER_THROTTLED: 'ld-picker-throttled',
  ACCEPT_ALL_FORBIDDEN: 'ld-accept-all-forbidden',
  EMPTY_FILTERS: 'ld-empty-filters',
  SENSITIVE_USB_CLASS: 'ld-sensitive-usb-class',
  SENSITIVE_HID_USAGE: 'ld-sensitive-hid-usage',
  SENSITIVE_BT_SERVICE: 'ld-sensitive-bt-service',
  VENDOR_NOT_ALLOWED: 'ld-vendor-not-allowed',
  TOO_MANY_HANDLES: 'ld-too-many-handles',
  HANDLE_SESSION_TOO_LONG: 'ld-handle-session-too-long',
  BAD_BAUD_RATE: 'ld-bad-baud-rate',
  UNKNOWN_API: 'ld-unknown-api',
});

const API = Object.freeze({ USB: 'usb', HID: 'hid', SERIAL: 'serial', BLUETOOTH: 'bluetooth' });

// 敏感 USB 类（bInterfaceClass）。
const SENSITIVE_USB_CLASS = Object.freeze({
  3: 'HID（键盘/鼠标，可 BadUSB 注入）',
  8: 'Mass Storage（可直接读写存储）',
  11: 'CCID 智能卡',
  255: 'Vendor Specific（固件/专用协议）',
});

// 敏感蓝牙 GATT 服务（16-bit UUID 分配号，转成 0x18xx 形式比较）。
const SENSITIVE_BT_SERVICE = Object.freeze(new Set([
  '0000180f', // Battery
  '0000180a', // Device Information
  '00001812', // Human Interface Device
  '00001803', // Link Loss
  '00001802', // Immediate Alert
]));

// 敏感 HID usage page（Generic Desktop Keyboard/Mouse 等）。
const SENSITIVE_HID_USAGE_PAGE = Object.freeze(new Set([1, 7]));

function defaultLocalDevicePolicy() {
  return {
    requireSecureContext: true,
    requireGesture: true,
    requireFocus: true,
    denyBackground: true,
    pickerMinIntervalMs: 2000,
    maxHandlesPerOrigin: 6,
    maxSessionMs: 30 * 60000,
    allowAcceptAll: false,
    allowedVendorIds: [], // 空表示不按厂商限制（仍受敏感类限制）
    serialBaudWhitelist: [9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600],
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

function isNum(v) {
  return typeof v === 'number' && isFinite(v) && v >= 0 && Math.floor(v) === v;
}

// isHexToken 判断整串是否为十六进制字符。
function isHexToken(s) {
  if (s.length === 0) return false;
  for (const ch of s) {
    const ok = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    if (!ok) return false;
  }
  return true;
}

// normalizeBtUuid 把短 16 位号/完整 UUID 统一为 8 位十六进制小写前缀；
// 'battery_service' 这类具名别名不转换，返回空。
function normalizeBtUuid(uuid) {
  if (typeof uuid !== 'string') return '';
  let s = uuid.toLowerCase();
  if (s.indexOf('0x') === 0) s = s.slice(2);
  if (s.indexOf('-') >= 0) s = s.split('-')[0];
  if (s.length <= 4) {
    let n = '';
    for (const ch of s) {
      const ok = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
      if (!ok) return '';
      n += ch;
    }
    while (n.length < 4) n = '0' + n;
    return '0000' + n;
  }
  const head = s.slice(0, 8);
  return isHexToken(head) ? head : '';
}

// filterClaimsAcceptAll 判断 filters 是否实际上“接受所有设备”。
function usbAcceptAll(options) {
  if (options && options.exclusionFilters) return false;
  if (options && options.acceptAllDevices === true) return true;
  const f = options && options.filters;
  return !Array.isArray(f) || f.length === 0;
}

function hasSensitiveUsbClass(filters) {
  for (const f of filters || []) {
    if (isNum(f.classCode) && Object.prototype.hasOwnProperty.call(SENSITIVE_USB_CLASS, String(f.classCode))) {
      return f.classCode;
    }
  }
  return -1;
}

function hasSensitiveHidUsage(filters) {
  for (const f of filters || []) {
    if (isNum(f.usagePage) && SENSITIVE_HID_USAGE_PAGE.has(f.usagePage)) return f.usagePage;
  }
  return -1;
}

function hasSensitiveBtService(services) {
  for (const s of services || []) {
    if (SENSITIVE_BT_SERVICE.has(normalizeBtUuid(s))) return normalizeBtUuid(s);
  }
  return '';
}

class LocalDeviceGuard {
  constructor(policy) {
    this.policy = policy || defaultLocalDevicePolicy();
    this.lastPicker = new Map();
    this.handles = new Map(); // origin -> count
    this.handleOpenedAt = new Map();
  }

  _common(ctx) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { ok: false, reason: LD_REASON.BAD_ORIGIN };
    if (pol.requireSecureContext && ctx.isSecureContext !== true) {
      return { ok: false, reason: LD_REASON.INSECURE_CONTEXT };
    }
    const key = originKey(ctx.origin);
    if (!key) return { ok: false, reason: LD_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { ok: false, reason: LD_REASON.BLOCKED_ORIGIN };
    if (pol.denyBackground && ctx.isBackground === true) return { ok: false, reason: LD_REASON.BACKGROUND };
    if (pol.requireGesture && ctx.hasUserGesture !== true) return { ok: false, reason: LD_REASON.NO_GESTURE };
    if (pol.requireFocus && ctx.hasFocus !== true) return { ok: false, reason: LD_REASON.NOT_FOCUSED };
    const now = ctx.now || 0;
    if (this.lastPicker.has(key) && now - this.lastPicker.get(key) < pol.pickerMinIntervalMs) {
      return { ok: false, reason: LD_REASON.PICKER_THROTTLED };
    }
    return { ok: true, key, now };
  }

  _vendorOk(vendorId) {
    const allow = this.policy.allowedVendorIds;
    if (!allow || allow.length === 0) return true;
    return allow.indexOf(vendorId) >= 0;
  }

  // decideRequest 按 api 类型裁决 requestDevice/requestPort。
  decideRequest(api, ctx, options) {
    const g = this._common(ctx);
    if (!g.ok) return { decision: LD_DENY, reason: g.reason };
    if ((this.handles.get(g.key) || 0) >= this.policy.maxHandlesPerOrigin) {
      return { decision: LD_DENY, reason: LD_REASON.TOO_MANY_HANDLES };
    }

    if (api === API.USB) {
      if (usbAcceptAll(options) && !this.policy.allowAcceptAll) {
        return { decision: LD_DENY, reason: LD_REASON.ACCEPT_ALL_FORBIDDEN };
      }
      const cls = hasSensitiveUsbClass(options && options.filters);
      if (cls >= 0) return { decision: LD_DENY, reason: LD_REASON.SENSITIVE_USB_CLASS, classCode: cls };
      for (const f of (options && options.filters) || []) {
        if (isNum(f.vendorId) && !this._vendorOk(f.vendorId)) {
          return { decision: LD_DENY, reason: LD_REASON.VENDOR_NOT_ALLOWED, vendorId: f.vendorId };
        }
      }
    } else if (api === API.HID) {
      const f = options && options.filters;
      if (!Array.isArray(f) || f.length === 0) return { decision: LD_DENY, reason: LD_REASON.EMPTY_FILTERS };
      const up = hasSensitiveHidUsage(f);
      if (up >= 0) return { decision: LD_DENY, reason: LD_REASON.SENSITIVE_HID_USAGE, usagePage: up };
    } else if (api === API.BLUETOOTH) {
      if (options && options.acceptAllDevices === true && !this.policy.allowAcceptAll) {
        return { decision: LD_DENY, reason: LD_REASON.ACCEPT_ALL_FORBIDDEN };
      }
      const svc = hasSensitiveBtService(options && options.optionalServices) ||
        hasSensitiveBtService(options && options.filters && options.filters[0] && options.filters[0].services);
      if (svc) return { decision: LD_DENY, reason: LD_REASON.SENSITIVE_BT_SERVICE, service: svc };
    } else if (api === API.SERIAL) {
      const f = options && options.filters;
      if (f !== undefined && (!Array.isArray(f) || f.length === 0)) {
        return { decision: LD_DENY, reason: LD_REASON.EMPTY_FILTERS };
      }
    } else {
      return { decision: LD_DENY, reason: LD_REASON.UNKNOWN_API };
    }

    this.lastPicker.set(g.key, g.now);
    return { decision: LD_PROMPT, reason: '' };
  }

  noteHandleOpened(origin, now) {
    const key = originKey(origin);
    this.handles.set(key, (this.handles.get(key) || 0) + 1);
    this.handleOpenedAt.set(key, now || 0);
  }

  noteHandleClosed(origin) {
    const key = originKey(origin);
    this.handles.set(key, Math.max(0, (this.handles.get(key) || 1) - 1));
  }

  // checkSession 周期调用，超过最长会话时长要求断开。
  checkSession(origin, now) {
    const key = originKey(origin);
    const opened = this.handleOpenedAt.get(key);
    if (opened === undefined || (this.handles.get(key) || 0) === 0) {
      return { active: false, mustClose: false, reason: '' };
    }
    if ((now || 0) - opened > this.policy.maxSessionMs) {
      return { active: true, mustClose: true, reason: LD_REASON.HANDLE_SESSION_TOO_LONG };
    }
    return { active: true, mustClose: false, reason: '' };
  }

  // decideSerialOptions 裁决串口打开参数（波特率白名单）。
  decideSerialOptions(opts) {
    const baud = opts && opts.baudRate;
    if (!isNum(baud) || this.policy.serialBaudWhitelist.indexOf(baud) < 0) {
      return { allowed: false, reason: LD_REASON.BAD_BAUD_RATE };
    }
    return { allowed: true, reason: '' };
  }
}

module.exports = {
  LD_DENY, LD_PROMPT, LD_REASON, API,
  SENSITIVE_USB_CLASS, SENSITIVE_BT_SERVICE, SENSITIVE_HID_USAGE_PAGE,
  defaultLocalDevicePolicy, originKey, normalizeBtUuid,
  usbAcceptAll, hasSensitiveUsbClass, hasSensitiveHidUsage, hasSensitiveBtService,
  LocalDeviceGuard,
};
