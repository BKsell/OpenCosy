'use strict';

// sessionguard.js —— 会话（session）分区分类与“是否需要安全加固”的统一裁决内核。
//
// 威胁模型：
//   Electron 除默认会话 session.defaultSession 外，还可以用
//   session.fromPartition(partition) 创建额外会话：以 'persist:' 开头的会落盘，
//   其余是进程内临时会话。隔离窗口 / 多身份标签 / 访客模式都可能引入新会话。
//   历史上 OpenCosy 只在 defaultSession 上挂了权限处理器、设备处理器与 webRequest
//   安全策略，而 app 'session-created' 事件 0 接线。一旦出现额外会话，它将：
//     - 没有 setPermissionRequestHandler / setPermissionCheckHandler（权限回落为
//       Electron 默认策略，摄像头 / 通知 / 剪贴板等可能被网页获取）；
//     - 没有 setDevicePermissionHandler（串口 / HID / USB / 蓝牙选择回落默认）；
//     - 不经过出向请求头隐私策略（DNT / GPC 等）。
//   这是典型的“只加固默认实例、漏了后续新建实例”的纵深防御缺口。
//
// 本模块只做纯判定：
//   - classifyPartition 归一分区串，识别默认 / 持久 / 临时，并做字符白名单与长度校验；
//   - hardeningPlan 给出该会话必须套用的策略清单（任何合法会话都不放松）；
//   - decideSessionHarden 按分区去重（同一 session 生命周期内只加固一次，避免重复
//     setHandler 覆盖、重复注册 webRequest 监听器造成叠加泄漏）。
// 不触碰 Electron API，便于穷举单测；main.js 在 session-created 回调里据此执行加固。

const PERSIST_PREFIX = 'persist:';

// 分区名（去掉 persist: 前缀后）允许字符：字母数字、连字符、下划线、点。
// 刻意收窄，挡住空白、分隔符、路径穿越（../）、冒号与控制字符。
const PARTITION_NAME_MAX = 64;

// 策略 id 清单（main.js 据此把对应处理器 / webRequest 监听器挂到新会话上）。
const POLICY_PERMISSION_DENY = 'permission-default-deny';
const POLICY_DEVICE_CANCEL = 'device-default-cancel';
const POLICY_OUTGOING_HEADERS = 'outgoing-privacy-headers';

const ALL_POLICIES = Object.freeze([
  POLICY_PERMISSION_DENY,
  POLICY_DEVICE_CANCEL,
  POLICY_OUTGOING_HEADERS,
]);

// 拒绝原因码。
const REJECT_NONE = '';
const REJECT_LENGTH = 'partition-too-long';
const REJECT_CHAR = 'partition-bad-char';
const REJECT_EMPTY_PERSIST = 'persist-name-empty';

// isValidPartitionNameChar 校验分区名单个字符。
function isValidPartitionNameChar(c) {
  return (c >= 'a' && c <= 'z')
    || (c >= 'A' && c <= 'Z')
    || (c >= '0' && c <= '9')
    || c === '-' || c === '_' || c === '.';
}

// classifyPartition 归一一个分区字符串。
// 返回 { partition, isDefault, persist, name, valid, reason }。
//   - 默认会话 partition 为 ''（Electron 亦可能给 undefined）；
//   - 'persist:xxx' 为持久会话，xxx 必须非空且符合字符白名单；
//   - 其余非空串视为临时内存会话，整体须符合字符白名单（不允许冒号）。
function classifyPartition(partition) {
  const p = (partition === undefined || partition === null) ? '' : String(partition);

  if (p === '') {
    return { partition: '', isDefault: true, persist: false, name: '', valid: true, reason: REJECT_NONE };
  }
  if (p.length > PARTITION_NAME_MAX) {
    return { partition: p, isDefault: false, persist: false, name: '', valid: false, reason: REJECT_LENGTH };
  }
  // 任何空白 / 控制字符直接拒。
  for (let i = 0; i < p.length; i++) {
    const code = p.charCodeAt(i);
    if (code <= 0x20 || code === 0x7f) {
      return { partition: p, isDefault: false, persist: false, name: '', valid: false, reason: REJECT_CHAR };
    }
  }

  if (p.startsWith(PERSIST_PREFIX)) {
    const name = p.slice(PERSIST_PREFIX.length);
    if (name === '') {
      return { partition: p, isDefault: false, persist: true, name: '', valid: false, reason: REJECT_EMPTY_PERSIST };
    }
    for (let i = 0; i < name.length; i++) {
      if (!isValidPartitionNameChar(name[i])) {
        return { partition: p, isDefault: false, persist: true, name, valid: false, reason: REJECT_CHAR };
      }
    }
    return { partition: p, isDefault: false, persist: true, name, valid: true, reason: REJECT_NONE };
  }

  // 临时分区：不允许再带冒号（冒号是 persist: 的保留前缀位），也不允许其它非法字符。
  for (let i = 0; i < p.length; i++) {
    if (!isValidPartitionNameChar(p[i])) {
      return { partition: p, isDefault: false, persist: false, name: p, valid: false, reason: REJECT_CHAR };
    }
  }
  return { partition: p, isDefault: false, persist: false, name: p, valid: true, reason: REJECT_NONE };
}

// hardeningPlan 返回必须套用到该会话的策略 id 列表。合法会话（默认 / 临时 / 持久）
// 一律全套策略——绝不因为是“临时”分区就放松。非法分区返回空列表（应在更上层拒绝）。
function hardeningPlan(classification) {
  const c = classification || {};
  if (!c.valid) return [];
  return ALL_POLICIES.slice();
}

// createSessionGuardState 创建去重状态（进程级单份即可）。
function createSessionGuardState() {
  return { hardened: new Set(), rejected: [], total: 0 };
}

// decideSessionHarden 裁决某个会话是否需要此刻加固。
//   sessionLike: { partition }（Electron 回调给 session 对象，测试可直接传分区）。
// 返回 { shouldHarden, alreadyHardened, classification, policies, reason }。
function decideSessionHarden(state, sessionLike) {
  const st = state || createSessionGuardState();
  st.total++;

  let rawPartition = '';
  if (sessionLike && typeof sessionLike === 'object' && typeof sessionLike.partition === 'string') {
    rawPartition = sessionLike.partition;
  }
  const classification = classifyPartition(rawPartition);

  if (!classification.valid) {
    // 有界记录被拒分区，防止异常风暴撑爆内存。
    st.rejected.push({ partition: classification.partition, reason: classification.reason });
    if (st.rejected.length > 256) st.rejected.shift();
    return {
      shouldHarden: false, alreadyHardened: false, classification,
      policies: [], reason: classification.reason,
    };
  }

  const key = classification.isDefault ? '__default__' : classification.partition;
  if (st.hardened.has(key)) {
    return {
      shouldHarden: false, alreadyHardened: true, classification,
      policies: [], reason: REJECT_NONE,
    };
  }
  st.hardened.add(key);
  return {
    shouldHarden: true, alreadyHardened: false, classification,
    policies: hardeningPlan(classification), reason: REJECT_NONE,
  };
}

// isHardened 查询某分区是否已加固（只读，不改变状态）。
function isHardened(state, partition) {
  const st = state || createSessionGuardState();
  const c = classifyPartition(partition);
  const key = c.isDefault ? '__default__' : c.partition;
  return st.hardened.has(key);
}

module.exports = {
  PERSIST_PREFIX,
  PARTITION_NAME_MAX,
  POLICY_PERMISSION_DENY,
  POLICY_DEVICE_CANCEL,
  POLICY_OUTGOING_HEADERS,
  ALL_POLICIES,
  REJECT_NONE,
  REJECT_LENGTH,
  REJECT_CHAR,
  REJECT_EMPTY_PERSIST,
  isValidPartitionNameChar,
  classifyPartition,
  hardeningPlan,
  createSessionGuardState,
  decideSessionHarden,
  isHardened,
};
