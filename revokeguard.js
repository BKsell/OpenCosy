'use strict';

// revokeguard.js —— 设备授权“撤销（revoked）”事件的统一收口内核。
//
// 威胁模型：
//   select-*-device（devicerguard）回答的是“这一次要不要把设备句柄交给网页”。
//   但 WebHID / WebSerial / WebBluetooth 在授权之后还有一类方向相反的事件：
//     - webContents 'hid-device-revoked'      (event, device)
//     - webContents 'serial-port-revoked'    (event, port)
//     - webContents 'bluetooth-device-revoked' (event, deviceId)
//   当用户在浏览器/系统层面收回授权，或设备被物理拔出、被其他进程独占时触发。
//   这类事件此前完全无人监听（0 接线），带来两个问题：
//     1. 无留痕：授权被撤销是一条重要的安全状态变化（可能意味着用户在主动收回
//        对可疑页面的设备授权，或页面在异常地反复申请/掉线），不观测就无法发现；
//     2. 事件可被高频触发：恶意页面可制造“申请—掉线—再申请”的抖动，若每次撤销
//        都向渲染层广播 / 落审计，会形成日志洪泛与持久写入放大（资源耗尽）。
//
// 本内核只做纯判定：归一三类事件、提取不泄露完整描述符的稳定键、按“同类 + 同源 +
// 同设备”做时间窗去重。main.js 负责实际 recordSecurityEvent / 通知渲染层。
// 时间窗判定约定 now < 0 表示“调用方未提供时间”，此时不做节流、逐条放行，
// 便于在基准时间 0 附近做确定性单测（不要用 0 / falsy 当哨兵）。

const KIND_HID = 'hid';
const KIND_SERIAL = 'serial';
const KIND_BLUETOOTH = 'bluetooth';

const ACTION_RECORD = 'record';   // 本次撤销应留痕 / 通知
const ACTION_SUPPRESS = 'suppress'; // 落在冷却窗内，合并，不再重复落审计

// 同一“源 + 设备 + 类别”撤销事件的默认冷却窗：30 秒。正常用户收回授权是低频
// 动作；30 秒内重复的同键事件视为抖动，只计数不落审计，足以挡住洪泛又不漏首次。
const DEFAULT_REVOKE_COOLDOWN_MS = 30 * 1000;

// 单条来源描述的长度上限，防止撤销回调里夹带超长字符串灌入审计 / 渲染层。
const MAX_REVOKE_DETAIL_CHARS = 200;

const KNOWN_KINDS = new Set([KIND_HID, KIND_SERIAL, KIND_BLUETOOTH]);

// originFromUrl 从任意 URL 安全取源，非法时返回空串（与其他内核一致）。
function originFromUrl(rawUrl) {
  try {
    return new URL(rawUrl || '').origin;
  } catch {
    return '';
  }
}

// describeKind 给出设备类别中文名，用于安全事件文案。
function describeKind(kind) {
  switch (kind) {
    case KIND_HID: return 'HID';
    case KIND_SERIAL: return '串口';
    case KIND_BLUETOOTH: return '蓝牙';
    default: return '未知设备';
  }
}

// normalizeKind 把外部事件名 / 入参归一到受支持的类别，无法识别返回空串。
function normalizeKind(kind) {
  return KNOWN_KINDS.has(kind) ? kind : '';
}

// clampString 把任意描述裁到上限并去掉 CR/LF（审计行不允许折行伪造）。
function clampString(value, max) {
  if (value === null || value === undefined) return '';
  let s = String(value);
  s = s.replace(/[\r\n]+/g, ' ');
  if (s.length > max) s = s.slice(0, max) + '…';
  return s;
}

// summarizeDevice 在不回传完整序列号 / 设备名的前提下，给出“有没有可识别硬件身份”
// 的安全摘要，用于判断这次撤销是否对应一台真实设备（而非空回调）。
function summarizeDevice(kind, device) {
  const d = device || {};
  const summary = { identifiable: false, vendorId: null, productId: null };
  if (kind === KIND_BLUETOOTH) {
    // 蓝牙撤销回调给的是 deviceId 字符串，只记录其是否存在与长度，不外泄原值。
    summary.identifiable = typeof d.deviceId === 'string' && d.deviceId.length > 0;
    return summary;
  }
  const vid = d.vendorId !== undefined && d.vendorId !== null ? d.vendorId
    : (d.usbVendorId !== undefined && d.usbVendorId !== null ? d.usbVendorId : null);
  const pid = d.productId !== undefined && d.productId !== null ? d.productId
    : (d.usbProductId !== undefined && d.usbProductId !== null ? d.usbProductId : null);
  summary.vendorId = vid;
  summary.productId = pid;
  summary.identifiable = vid !== null || pid !== null
    || !!(d.portName && String(d.portName).length > 0);
  return summary;
}

// deviceKey 提取“同类别 + 同源 + 同设备”去重所用的稳定键。只用硬件标识 / 端口名，
// 不使用可能变化的展示名。任何缺失都退化为 'unknown'，仍可按类别 / 源合并。
function deviceKey(kind, device) {
  const d = device || {};
  if (kind === KIND_BLUETOOTH) {
    const id = typeof d.deviceId === 'string' ? d.deviceId : '';
    return `bt:${id ? id.length + ':' + id.slice(0, 24) : 'unknown'}`;
  }
  const vid = d.vendorId ?? d.usbVendorId;
  const pid = d.productId ?? d.usbProductId;
  if (vid !== undefined && vid !== null && pid !== undefined && pid !== null) {
    return `${kind}:${vid}:${pid}`;
  }
  if (d.portName) {
    return `${kind}:port:${clampString(d.portName, 48)}`;
  }
  return `${kind}:unknown`;
}

// dedupeKey 组装完整去重键（含源）。
function dedupeKey(kind, origin, device) {
  return `${origin || 'no-origin'}|${deviceKey(kind, device)}`;
}

// createRevokeState 创建一份去重状态（main.js 每个 webContents 持有一份，
// contents 销毁时随 Map 一起丢弃）。
function createRevokeState() {
  return { lastSeen: new Map(), suppressed: 0, total: 0 };
}

// decideRevocation 裁决一次撤销事件。
//   input: { kind, originUrl, device }
//   now:   当前毫秒时间戳；now < 0 表示不节流（逐条记录，用于确定性测试）。
// 返回 { action, kind, origin, key, detail, cooldownMs, suppressed }。
function decideRevocation(state, input, now, cooldownMs) {
  const st = state || createRevokeState();
  const inp = input || {};
  const kind = normalizeKind(inp.kind);
  const origin = originFromUrl(inp.originUrl);
  const cool = (typeof cooldownMs === 'number' && cooldownMs > 0)
    ? cooldownMs : DEFAULT_REVOKE_COOLDOWN_MS;

  st.total++;

  if (!kind) {
    // 未知类别不做设备级去重，统一落到 '*' 键，仍然节流，避免脏事件洪泛。
    const key = `${origin || 'no-origin'}|unknown-kind`;
    const last = st.lastSeen.get(key);
    if (now >= 0 && typeof last === 'number' && now - last < cool) {
      st.suppressed++;
      return { action: ACTION_SUPPRESS, kind: '', origin, key, detail: '', cooldownMs: cool, suppressed: st.suppressed };
    }
    st.lastSeen.set(key, now >= 0 ? now : -1);
    return { action: ACTION_RECORD, kind: '', origin, key, detail: '未知类别设备授权撤销', cooldownMs: cool, suppressed: st.suppressed };
  }

  const key = dedupeKey(kind, origin, inp.device);
  const summary = summarizeDevice(kind, inp.device);
  const last = st.lastSeen.get(key);
  const inWindow = now >= 0 && typeof last === 'number' && last >= 0 && (now - last) < cool;

  if (inWindow) {
    st.suppressed++;
    return { action: ACTION_SUPPRESS, kind, origin, key, detail: '', cooldownMs: cool, suppressed: st.suppressed };
  }

  st.lastSeen.set(key, now >= 0 ? now : -1);
  const idPart = summary.identifiable ? '（可识别设备）' : '（无硬件标识）';
  const detail = clampString(`${describeKind(kind)}设备授权被撤销${idPart}`, MAX_REVOKE_DETAIL_CHARS);
  return { action: ACTION_RECORD, kind, origin, key, detail, cooldownMs: cool, suppressed: st.suppressed };
}

module.exports = {
  KIND_HID,
  KIND_SERIAL,
  KIND_BLUETOOTH,
  ACTION_RECORD,
  ACTION_SUPPRESS,
  DEFAULT_REVOKE_COOLDOWN_MS,
  MAX_REVOKE_DETAIL_CHARS,
  originFromUrl,
  describeKind,
  normalizeKind,
  clampString,
  summarizeDevice,
  deviceKey,
  dedupeKey,
  createRevokeState,
  decideRevocation,
};
