'use strict';

// bluetoothguard.js —— Web Bluetooth（navigator.bluetooth.requestDevice）授权裁决内核。
//
// 威胁模型：
//   1. acceptAllDevices:true 让页面拿到对周边所有 BLE 设备的引用，可枚举 MAC/名称做
//      物理邻近指纹，并连接未声明用途的设备（体温计、门锁、车钥匙、可穿戴设备）；
//   2. optionalServices 一旦包含通用属性（generic_access、device_information 或厂商私有
//      128-bit UUID），页面连上后可读取序列号/固件版本做长期追踪，甚至写入特征值；
//   3. namePrefix 过短（如 ""/"B"）等价于全量枚举，且可携带控制字符伪造系统设备名；
//   4. 无用户手势时弹设备选择器，可被后台标签/iframe 用来做手势劫持或诱导点击；
//   5. manufacturerData / serviceData 过滤器被用来扫描特定厂商人群。
//
// 纯逻辑，不触碰真实蓝牙栈。

const BT_ALLOW = 'allow';
const BT_DENY = 'deny';

const BT_REASON = Object.freeze({
  BAD_CONTEXT: 'bt-bad-context',
  NO_GESTURE: 'bt-no-gesture',
  CROSS_ORIGIN_SUBFRAME: 'bt-cross-origin-subframe',
  INSECURE_ORIGIN: 'bt-insecure-origin',
  ACCEPT_ALL_DEVICES: 'bt-accept-all-devices',
  NO_FILTER: 'bt-no-filter',
  NAME_PREFIX_TOO_SHORT: 'bt-name-prefix-too-short',
  NAME_PREFIX_CONTROL_CHAR: 'bt-name-prefix-control-char',
  NAME_PREFIX_TOO_LONG: 'bt-name-prefix-too-long',
  SERVICE_UUID_NOT_ALLOWED: 'bt-service-uuid-not-allowed',
  OPTIONAL_SERVICE_TOO_BROAD: 'bt-optional-service-too-broad',
  OPTIONAL_SERVICE_OVERFLOW: 'bt-optional-service-overflow',
  BAD_UUID: 'bt-bad-uuid',
  MANUFACTURER_SCAN: 'bt-manufacturer-scan',
});

// 标准化 GATT assigned-number 别名（仅小写短名）。
const BT_KNOWN_SERVICES = Object.freeze({
  generic_access: 0x1800,
  generic_attribute: 0x1801,
  immediate_alert: 0x1802,
  link_loss: 0x1803,
  tx_power: 0x1804,
  current_time: 0x1805,
  device_information: 0x180a,
  heart_rate: 0x180d,
  battery_service: 0x180f,
  blood_pressure: 0x1810,
  cycling_power: 0x1818,
  environmental_sensing: 0x181a,
  fitness_machine: 0x1826,
});

// 即便在白名单内，也不允许通过 optionalServices 静默索取的高敏服务。
const BT_SENSITIVE_SHORT = Object.freeze(['generic_access', 'generic_attribute', 'device_information']);

function defaultBluetoothPolicy() {
  return {
    requireHttps: true,
    requireUserGesture: true,
    blockCrossOriginSubframe: true,
    allowAcceptAllDevices: false,
    requireAtLeastOneFilter: true,
    minNamePrefixLength: 3,
    maxNamePrefixLength: 29, // BLE 名称上限
    maxOptionalServices: 2,
    // 允许的服务白名单：空数组表示不限制已声明必需服务，optional 仍受限。
    allowedServiceUuids: [],
    blockManufacturerDataScan: true,
  };
}

// isHexToken 判断 s 是否为恰好 len 个十六进制字符（纯字符，无正则）。
function isHexToken(s, len) {
  if (typeof s !== 'string' || s.length !== len) return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const isDigit = c >= 48 && c <= 57;
    const isLower = c >= 97 && c <= 102;
    const isUpper = c >= 65 && c <= 70;
    if (!isDigit && !isLower && !isUpper) return false;
  }
  return true;
}

// canonicalServiceUuid 把 16-bit/32-bit 别名或 128-bit 字符串归一为可比较的 token。
// 返回 {ok, token, bits}。
function canonicalServiceUuid(input) {
  if (typeof input === 'number') {
    if (!Number.isInteger(input) || input < 0 || input > 0xffffffff) return { ok: false };
    if (input <= 0xffff) return { ok: true, token: '16:' + input.toString(16), bits: 16 };
    return { ok: true, token: '32:' + input.toString(16), bits: 32 };
  }
  if (typeof input !== 'string') return { ok: false };
  const s = input.toLowerCase();
  const named = BT_KNOWN_SERVICES[s];
  if (named !== undefined) return { ok: true, token: '16:' + named.toString(16), bits: 16, named: s };

  // 0x 前缀的 16/32 位。
  if (s.indexOf('0x') === 0) {
    const hex = s.slice(2);
    if (isHexToken(hex, 4)) return { ok: true, token: '16:' + hex, bits: 16 };
    if (isHexToken(hex, 8)) return { ok: true, token: '32:' + hex, bits: 32 };
    return { ok: false };
  }
  // 裸 16 位十六进制（如 "180d"）。
  if (isHexToken(s, 4)) return { ok: true, token: '16:' + s, bits: 16 };
  if (isHexToken(s, 8)) return { ok: true, token: '32:' + s, bits: 32 };

  // 128-bit：8-4-4-4-12。
  const parts = s.split('-');
  if (parts.length === 5 && isHexToken(parts[0], 8) && isHexToken(parts[1], 4) &&
      isHexToken(parts[2], 4) && isHexToken(parts[3], 4) && isHexToken(parts[4], 12)) {
    return { ok: true, token: '128:' + s, bits: 128 };
  }
  return { ok: false };
}

function containsControlChar(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return true;
  }
  return false;
}

class BluetoothGuard {
  constructor(policy) {
    this.policy = policy || defaultBluetoothPolicy();
  }

  // decideRequest 裁决一次 requestDevice。
  // ctx: {origin, isTopFrame, userGesture}
  // options: {filters, optionalServices, acceptAllDevices}
  decideRequest(ctx, options) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') {
      return { decision: BT_DENY, reason: BT_REASON.BAD_CONTEXT };
    }
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) {
      return { decision: BT_DENY, reason: BT_REASON.INSECURE_ORIGIN };
    }
    if (pol.requireUserGesture && ctx.userGesture !== true) {
      return { decision: BT_DENY, reason: BT_REASON.NO_GESTURE };
    }
    if (pol.blockCrossOriginSubframe && ctx.isTopFrame === false) {
      return { decision: BT_DENY, reason: BT_REASON.CROSS_ORIGIN_SUBFRAME };
    }

    const opt = options && typeof options === 'object' ? options : {};
    const filters = Array.isArray(opt.filters) ? opt.filters : [];

    if (opt.acceptAllDevices === true) {
      if (!pol.allowAcceptAllDevices) {
        return { decision: BT_DENY, reason: BT_REASON.ACCEPT_ALL_DEVICES };
      }
    } else if (pol.requireAtLeastOneFilter && filters.length === 0) {
      return { decision: BT_DENY, reason: BT_REASON.NO_FILTER };
    }

    for (let i = 0; i < filters.length; i++) {
      const f = filters[i];
      if (!f || typeof f !== 'object') return { decision: BT_DENY, reason: BT_REASON.NO_FILTER, index: i };

      if (typeof f.namePrefix === 'string') {
        if (f.namePrefix.length < pol.minNamePrefixLength) {
          return { decision: BT_DENY, reason: BT_REASON.NAME_PREFIX_TOO_SHORT, index: i };
        }
        if (f.namePrefix.length > pol.maxNamePrefixLength) {
          return { decision: BT_DENY, reason: BT_REASON.NAME_PREFIX_TOO_LONG, index: i };
        }
        if (containsControlChar(f.namePrefix)) {
          return { decision: BT_DENY, reason: BT_REASON.NAME_PREFIX_CONTROL_CHAR, index: i };
        }
      }

      const declared = Array.isArray(f.services) ? f.services : [];
      for (let j = 0; j < declared.length; j++) {
        const canon = canonicalServiceUuid(declared[j]);
        if (!canon.ok) return { decision: BT_DENY, reason: BT_REASON.BAD_UUID, index: i, service: declared[j] };
        if (pol.allowedServiceUuids.length > 0 &&
            pol.allowedServiceUuids.every((u) => canonicalServiceUuid(u).token !== canon.token)) {
          return { decision: BT_DENY, reason: BT_REASON.SERVICE_UUID_NOT_ALLOWED, service: declared[j] };
        }
      }

      if (pol.blockManufacturerDataScan &&
          (Array.isArray(f.manufacturerData) && f.manufacturerData.length > 0)) {
        return { decision: BT_DENY, reason: BT_REASON.MANUFACTURER_SCAN, index: i };
      }
    }

    const optional = Array.isArray(opt.optionalServices) ? opt.optionalServices : [];
    if (optional.length > pol.maxOptionalServices) {
      return { decision: BT_DENY, reason: BT_REASON.OPTIONAL_SERVICE_OVERFLOW, count: optional.length };
    }
    for (let k = 0; k < optional.length; k++) {
      const canon = canonicalServiceUuid(optional[k]);
      if (!canon.ok) return { decision: BT_DENY, reason: BT_REASON.BAD_UUID, service: optional[k] };
      // 128-bit 厂商私有服务走 optional 通道风险过高；短名敏感服务也不允许。
      if (canon.bits === 128 || (canon.named && BT_SENSITIVE_SHORT.indexOf(canon.named) >= 0)) {
        return { decision: BT_DENY, reason: BT_REASON.OPTIONAL_SERVICE_TOO_BROAD, service: optional[k] };
      }
    }

    return { decision: BT_ALLOW, reason: '' };
  }
}

module.exports = {
  BT_ALLOW, BT_DENY, BT_REASON,
  defaultBluetoothPolicy, canonicalServiceUuid, isHexToken, containsControlChar,
  BT_KNOWN_SERVICES, BluetoothGuard,
};
