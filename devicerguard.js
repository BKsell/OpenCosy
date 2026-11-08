'use strict';

// devicerguard.js —— 串口 / HID / USB 设备“选择器”回调的统一收口内核。
//
// 威胁模型：
//   session.setDevicePermissionHandler 只回答“这个源能不能用这一类设备”，但
//   navigator.serial.requestPort() / navigator.hid.requestDevice() /
//   navigator.usb.requestDevice() 在真正枚举到设备后，还会触发 webContents 上的
//   设备“选择”事件：
//     - select-serial-port(event, portList, webContents, callback)
//     - select-hid-device(event, details, callback)        （设备在 details.deviceList）
//     - select-usb-device(event, details, callback)        （设备在 details.deviceList）
//   这些事件若无人监听，不同平台/Electron 版本行为不一致：部分版本会“自动选中枚举到
//   的第一个设备”并把句柄交给网页。浏览器场景下网页没有正当理由独占本机串口/HID/USB
//   设备（键盘、U 盾、烧录器、串口调试设备都可能在其列），因此这里与蓝牙一致，统一
//   “显式取消选择”，绝不依赖“不监听时的默认行为”。
//
//   本模块只做纯判定与入参归一，main.js 负责调 callback('') 并留痕。

const KIND_SERIAL = 'serial';
const KIND_HID = 'hid';
const KIND_USB = 'usb';
const DECISION_CANCEL = 'cancel';

const KNOWN_KINDS = new Set([KIND_SERIAL, KIND_HID, KIND_USB]);

function originFromUrl(rawUrl) {
  try {
    return new URL(rawUrl || '').origin;
  } catch {
    return '';
  }
}

// extractDeviceList 屏蔽三种事件回调形态差异，返回统一的设备数组。
//   serial: 直接把 portList 作为第二参传入
//   hid/usb: 设备在 details.deviceList / details.devices
function extractDeviceList(kind, details, portList) {
  if (kind === KIND_SERIAL) {
    return Array.isArray(portList) ? portList
      : Array.isArray(details && details.portList) ? details.portList : [];
  }
  const d = details || {};
  if (Array.isArray(d.deviceList)) return d.deviceList;
  if (Array.isArray(d.devices)) return d.devices;
  return [];
}

// summarizeDevice 在不泄露设备敏感描述符的前提下，给出可计数的安全摘要。
// 只统计数量与厂商/产品标识是否存在，不回传完整序列号/名称到判定结果。
function summarizeDevice(kind, device) {
  const d = device || {};
  const summary = { hasVendor: false, hasProduct: false };
  if (kind === KIND_SERIAL) {
    summary.hasVendor = !!(d.vendorId !== undefined || d.usbVendorId !== undefined);
    summary.hasProduct = !!(d.productId !== undefined || d.usbProductId !== undefined);
  } else {
    summary.hasVendor = d.vendorId !== undefined && d.vendorId !== null;
    summary.hasProduct = d.productId !== undefined && d.productId !== null;
  }
  return summary;
}

// decideDeviceChooser 判定一次设备选择。恒为 cancel；返回稳定结构供 main.js 留痕：
//   { decision, kind, reason, origin, deviceCount, identified }
// input: { kind, originUrl, details, portList }
function decideDeviceChooser(input) {
  const inp = input || {};
  const kind = KNOWN_KINDS.has(inp.kind) ? inp.kind : 'unknown';
  const origin = originFromUrl(inp.originUrl);
  const devices = extractDeviceList(kind, inp.details, inp.portList);

  let identified = 0;
  for (const dev of devices) {
    const s = summarizeDevice(kind, dev);
    if (s.hasVendor || s.hasProduct) identified++;
  }

  return {
    decision: DECISION_CANCEL,
    kind,
    reason: `${kind}-auto-select`,
    origin,
    deviceCount: devices.length,
    identified,
  };
}

// describeKind 给出设备类别中文名，用于安全事件文案。
function describeKind(kind) {
  switch (kind) {
    case KIND_SERIAL: return '串口';
    case KIND_HID: return 'HID';
    case KIND_USB: return 'USB';
    default: return '未知设备';
  }
}

module.exports = {
  KIND_SERIAL,
  KIND_HID,
  KIND_USB,
  DECISION_CANCEL,
  originFromUrl,
  extractDeviceList,
  summarizeDevice,
  decideDeviceChooser,
  describeKind,
};
