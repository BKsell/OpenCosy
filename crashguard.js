'use strict';

// crashguard.js —— 插件/进程崩溃事件（webContents 'plugin-crashed'）收口内核。
//
// 威胁模型：
//   当内嵌插件（如 PDF/PPAPI 类组件）崩溃时，Chromium 抛 'plugin-crashed'，
//   参数为插件 name/version，主进程通常要弹提示并写日志。风险：
//     1) 日志注入：name/version 是随插件元数据来的字符串，若夹带 \r\n 与控制字符，
//        写进行式日志时可伪造记录行、盖掉前一条，多行终端里还可插 ANSI 转义；
//     2) 崩溃循环洪泛：让插件在页面里反复崩溃重启，每秒弹一堆崩溃框、刷一批日志，
//        打爆磁盘（这是真实的 DoS，而不是正常“偶尔崩溃”），并诱导用户点错按钮；
//     3) 超长字段撑爆对话框布局。
//   策略：先净化字段（白名字符、限长），再做“同键崩溃合并”——同一插件的连续崩溃
//   只通知首次，后续折叠计数，跨窗口输出一次汇总；不同插件分别计数。纯函数。

const CRASH_NOTIFY = 'notify';   // 首次/距上次很久，允许弹一次
const CRASH_SUPPRESS = 'suppress'; // 崩溃循环中的重复事件，折叠计数
const CRASH_DROP = 'drop';       // 字段非法，直接丢弃

const SUPPRESS_LOOP = 'crash-repeat-suppressed';
const DROP_BAD_FIELD = 'crash-bad-field';

const CRASH_MAX_NAME_CHARS = 128;
const CRASH_MAX_VERSION_CHARS = 64;
// 同一插件在该窗口内的重复崩溃折叠为一次汇总，不逐次弹窗/写多行日志。
const CRASH_NOTIFY_GAP_MS = 30_000;
// 单次连续崩溃序列最多折叠多少条（含），超过后即使未到时间窗也强制再汇总一次，
// 防止计数器无界增长（宁可多一条汇总日志，也不让计数在内存里无限累加）。
const CRASH_MAX_SUPPRESSED = 1_000;

// 名称白名单：字母数字、空格、点、连字符、下划线，覆盖 Flash/PDF/常见插件名。
const NAME_ALLOWED_RE = /^[A-Za-z0-9 ._-]+$/;
// 版本白名单：数字与点/连字符/下划线/字母（beta、rc 等），拒绝空白与控制符。
const VERSION_ALLOWED_RE = /^[A-Za-z0-9._-]+$/;

const C0_CONTROL_RE = /[\x00-\x1f\x7f]/g;
const C0_DETECT_RE = /[\x00-\x1f\x7f]/;

function cleanField(input, maxLen, allowRe) {
  if (typeof input !== 'string') return '';
  // 一旦携带任何 C0 控制字符（含换行、回车、ESC/ANSI 转义）直接拒绝，不做“剥除后放行”，
  // 避免把被注入伪造过的来源字符串洗白进日志/UI。
  if (C0_DETECT_RE.test(input)) return '';
  const s = input.replace(C0_CONTROL_RE, '').trim();
  if (s.length === 0 || s.length > maxLen) return '';
  return allowRe.test(s) ? s : '';
}

// sanitizePluginCrash 返回 { ok, name, version }。任一关键字段非法即 ok:false，
// 调用方不应弹窗（避免把脏字符串渲染到 UI/日志），只记一条“字段非法的崩溃事件”。
function sanitizePluginCrash(name, version) {
  const cleanName = cleanField(name, CRASH_MAX_NAME_CHARS, NAME_ALLOWED_RE);
  const cleanVersion = cleanField(version, CRASH_MAX_VERSION_CHARS, VERSION_ALLOWED_RE);
  if (!cleanName || !cleanVersion) return { ok: false, name: cleanName, version: cleanVersion };
  return { ok: true, name: cleanName, version: cleanVersion };
}

function crashKey(name, version) {
  return name + '@' + version;
}

function createCrashState(now) {
  return {
    // key -> { firstAt, lastAt, suppressed }
    plugins: new Map(),
    notified: 0,
    suppressed: 0,
    dropped: 0,
    createdAt: now || 0,
  };
}

function resetForNavigation(state) {
  if (!state) return;
  state.plugins.clear();
}

// decidePluginCrash 裁决一次 plugin-crashed。
// 返回 action 与 suppressedSinceLastNotify（自上次通知起折叠的次数，notify 时为 0）。
function decidePluginCrash(state, name, version, now) {
  if (!state) throw new TypeError('crashguard: state required');
  const parsed = sanitizePluginCrash(name, version);
  if (!parsed.ok) {
    state.dropped += 1;
    return { action: CRASH_DROP, reason: DROP_BAD_FIELD, name: parsed.name, version: parsed.version };
  }

  const key = crashKey(parsed.name, parsed.version);
  let rec = state.plugins.get(key);
  if (!rec) {
    rec = { firstAt: now, lastAt: now, notifiedAt: now, suppressed: 0 };
    state.plugins.set(key, rec);
    state.notified += 1;
    return {
      action: CRASH_NOTIFY, reason: '',
      name: parsed.name, version: parsed.version, key,
      suppressedSinceLastNotify: 0, distinctPlugins: state.plugins.size,
    };
  }

  const withinGap = now - rec.notifiedAt < CRASH_NOTIFY_GAP_MS;
  const underCap = rec.suppressed < CRASH_MAX_SUPPRESSED;
  if (withinGap && underCap) {
    rec.suppressed += 1;
    rec.lastAt = now;
    state.suppressed += 1;
    return {
      action: CRASH_SUPPRESS, reason: SUPPRESS_LOOP,
      name: parsed.name, version: parsed.version, key,
      suppressedSinceLastNotify: rec.suppressed, distinctPlugins: state.plugins.size,
    };
  }

  // 超过时间窗或折叠上限：再通知一次（汇总），并清零该插件的折叠计数。
  const flushed = rec.suppressed;
  rec.suppressed = 0;
  rec.notifiedAt = now;
  rec.lastAt = now;
  state.notified += 1;
  return {
    action: CRASH_NOTIFY, reason: '',
    name: parsed.name, version: parsed.version, key,
    suppressedSinceLastNotify: flushed, distinctPlugins: state.plugins.size,
  };
}

function describeCrashReason(reason) {
  switch (reason) {
    case SUPPRESS_LOOP:
      return '同一插件在短时间内反复崩溃，重复崩溃提示已折叠';
    case DROP_BAD_FIELD:
      return '崩溃事件携带了非法的插件名称或版本字段，已忽略';
    default:
      return '插件崩溃';
  }
}

module.exports = {
  CRASH_NOTIFY,
  CRASH_SUPPRESS,
  CRASH_DROP,
  SUPPRESS_LOOP,
  DROP_BAD_FIELD,
  CRASH_MAX_NAME_CHARS,
  CRASH_MAX_VERSION_CHARS,
  CRASH_NOTIFY_GAP_MS,
  CRASH_MAX_SUPPRESSED,
  sanitizePluginCrash,
  crashKey,
  createCrashState,
  resetForNavigation,
  decidePluginCrash,
  describeCrashReason,
};
