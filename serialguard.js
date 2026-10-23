'use strict';

// serialguard.js —— Web Serial（navigator.serial.requestPort / port.open）授权与打开参数裁决。
//
// 威胁模型：
//   1. requestPort 不传 filters 时浏览器列出全部串口，页面可枚举外设（POS、调试口、
//      工业控制器、烧录器）做环境指纹并尝试默认连接；
//   2. port.open 的 baudRate / bufferSize 由页面控制：超大 bufferSize 直接占用内存，
//      非整数/越界值会在底层触发异常或绕过上层校验，奇怪波特率可能打到调试固件；
//   3. dataBits/stopBits/parity 组合虽然多数硬件拒绝，但脏值可能触发驱动缺陷；
//   4. 蓝牙通通信道（rfcomm）被用来绕过 USB 过滤直接持有串口；
//   5. 无手势/跨源 iframe 弹窗劫持端口授权。
//
// 纯逻辑。

const SER_ALLOW = 'allow';
const SER_DENY = 'deny';

const SER_REASON = Object.freeze({
  BAD_CONTEXT: 'ser-bad-context',
  NO_GESTURE: 'ser-no-gesture',
  CROSS_ORIGIN_SUBFRAME: 'ser-cross-origin-subframe',
  INSECURE_ORIGIN: 'ser-insecure-origin',
  NO_FILTER: 'ser-no-filter',
  EMPTY_FILTER: 'ser-empty-filter',
  BAD_VENDOR_RANGE: 'ser-bad-vendor-range',
  VENDOR_NOT_ALLOWED: 'ser-vendor-not-allowed',
  TOO_MANY_FILTERS: 'ser-too-many-filters',
  BLUETOOTH_CHANNEL: 'ser-bluetooth-channel',
  BAD_BAUD: 'ser-bad-baud',
  BAUD_UNUSUAL: 'ser-baud-unusual',
  BAD_DATA_BITS: 'ser-bad-data-bits',
  BAD_STOP_BITS: 'ser-bad-stop-bits',
  BAD_PARITY: 'ser-bad-parity',
  BAD_FLOW_CONTROL: 'ser-bad-flow-control',
  BUFFER_TOO_LARGE: 'ser-buffer-too-large',
  BAD_BUFFER: 'ser-bad-buffer',
});

// 常见/合法波特率白名单（纯字符/数值匹配）。
const SER_COMMON_BAUD = Object.freeze([300, 1200, 2400, 4800, 9600, 14400, 19200, 28800, 31250, 38400, 57600, 74880, 115200, 128000, 230400, 250000, 460800, 500000, 921600, 1000000, 2000000]);
const SER_VALID_DATA_BITS = Object.freeze([7, 8]);
const SER_VALID_STOP_BITS = Object.freeze([1, 2]);
const SER_VALID_PARITY = Object.freeze(['none', 'even', 'odd']);
const SER_VALID_FLOW = Object.freeze(['none', 'hardware']);

function defaultSerialPolicy() {
  return {
    requireHttps: true,
    requireUserGesture: true,
    blockCrossOriginSubframe: true,
    requireNonEmptyFilter: true,
    allowedVendorIds: [],
    blockBluetoothChannel: true,
    maxFilters: 8,
    allowUnusualBaud: false,
    maxBaudRate: 3000000,
    maxBufferSize: 1024 * 1024, // 1 MiB
  };
}

function isUint16(v) {
  return typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 0xffff;
}

class SerialGuard {
  constructor(policy) {
    this.policy = policy || defaultSerialPolicy();
  }

  // decideRequest 裁决 requestPort({filters, allowAllDevices})。
  decideRequest(ctx, options) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') {
      return { decision: SER_DENY, reason: SER_REASON.BAD_CONTEXT };
    }
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) {
      return { decision: SER_DENY, reason: SER_REASON.INSECURE_ORIGIN };
    }
    if (pol.requireUserGesture && ctx.userGesture !== true) {
      return { decision: SER_DENY, reason: SER_REASON.NO_GESTURE };
    }
    if (pol.blockCrossOriginSubframe && ctx.isTopFrame === false) {
      return { decision: SER_DENY, reason: SER_REASON.CROSS_ORIGIN_SUBFRAME };
    }

    const opt = options && typeof options === 'object' ? options : {};

    // Web Serial 暴露蓝牙通信用口；除非显式放开，否则不允许走蓝牙信道。
    if (pol.blockBluetoothChannel && opt.allowedBluetoothServiceClassIds !== undefined) {
      return { decision: SER_DENY, reason: SER_REASON.BLUETOOTH_CHANNEL };
    }

    if (opt.allowAllDevices === true) {
      return { decision: SER_DENY, reason: SER_REASON.NO_FILTER };
    }

    const filters = Array.isArray(opt.filters) ? opt.filters : null;
    if (filters === null || filters.length === 0) {
      return { decision: SER_DENY, reason: SER_REASON.NO_FILTER };
    }
    if (filters.length > pol.maxFilters) {
      return { decision: SER_DENY, reason: SER_REASON.TOO_MANY_FILTERS, count: filters.length };
    }

    for (let i = 0; i < filters.length; i++) {
      const f = filters[i];
      if (pol.requireNonEmptyFilter && (!f || typeof f !== 'object' ||
          (f.usbVendorId === undefined && f.usbProductId === undefined))) {
        return { decision: SER_DENY, reason: SER_REASON.EMPTY_FILTER, index: i };
      }
      if (f) {
        if (f.usbVendorId !== undefined) {
          if (!isUint16(f.usbVendorId)) return { decision: SER_DENY, reason: SER_REASON.BAD_VENDOR_RANGE, index: i };
          if (pol.allowedVendorIds.length > 0 && pol.allowedVendorIds.indexOf(f.usbVendorId) < 0) {
            return { decision: SER_DENY, reason: SER_REASON.VENDOR_NOT_ALLOWED, index: i, vendorId: f.usbVendorId };
          }
        }
        if (f.usbProductId !== undefined && !isUint16(f.usbProductId)) {
          return { decision: SER_DENY, reason: SER_REASON.BAD_VENDOR_RANGE, index: i, field: 'usbProductId' };
        }
      }
    }
    return { decision: SER_ALLOW, reason: '' };
  }

  // decideOpen 裁决 port.open(options)。
  decideOpen(openOptions) {
    const pol = this.policy;
    const o = openOptions && typeof openOptions === 'object' ? openOptions : {};

    const baud = o.baudRate;
    if (typeof baud !== 'number' || !Number.isInteger(baud) || baud <= 0) {
      return { decision: SER_DENY, reason: SER_REASON.BAD_BAUD };
    }
    if (baud > pol.maxBaudRate) return { decision: SER_DENY, reason: SER_REASON.BAD_BAUD, baudRate: baud };
    if (!pol.allowUnusualBaud && SER_COMMON_BAUD.indexOf(baud) < 0) {
      return { decision: SER_DENY, reason: SER_REASON.BAUD_UNUSUAL, baudRate: baud };
    }

    if (o.dataBits !== undefined && SER_VALID_DATA_BITS.indexOf(o.dataBits) < 0) {
      return { decision: SER_DENY, reason: SER_REASON.BAD_DATA_BITS, dataBits: o.dataBits };
    }
    if (o.stopBits !== undefined && SER_VALID_STOP_BITS.indexOf(o.stopBits) < 0) {
      return { decision: SER_DENY, reason: SER_REASON.BAD_STOP_BITS, stopBits: o.stopBits };
    }
    if (o.parity !== undefined && SER_VALID_PARITY.indexOf(o.parity) < 0) {
      return { decision: SER_DENY, reason: SER_REASON.BAD_PARITY, parity: o.parity };
    }
    if (o.flowControl !== undefined && SER_VALID_FLOW.indexOf(o.flowControl) < 0) {
      return { decision: SER_DENY, reason: SER_REASON.BAD_FLOW_CONTROL, flowControl: o.flowControl };
    }

    if (o.bufferSize !== undefined) {
      if (typeof o.bufferSize !== 'number' || !Number.isInteger(o.bufferSize) || o.bufferSize <= 0) {
        return { decision: SER_DENY, reason: SER_REASON.BAD_BUFFER };
      }
      if (o.bufferSize > pol.maxBufferSize) {
        return { decision: SER_DENY, reason: SER_REASON.BUFFER_TOO_LARGE, bufferSize: o.bufferSize };
      }
    }
    return { decision: SER_ALLOW, reason: '' };
  }
}

module.exports = {
  SER_ALLOW, SER_DENY, SER_REASON,
  SER_COMMON_BAUD, SER_VALID_DATA_BITS, SER_VALID_STOP_BITS, SER_VALID_PARITY, SER_VALID_FLOW,
  defaultSerialPolicy, isUint16, SerialGuard,
};
