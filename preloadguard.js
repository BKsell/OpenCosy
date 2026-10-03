'use strict';

// preloadguard.js —— 预加载脚本（preload）异常与渲染侧致命信号的收口判定内核。
//
// 威胁模型 / 背景：
//   OpenCosy 的安全边界高度依赖 preload.js：它是渲染层唯一能接触 Node/IPC 的地方，
//   IPC 白名单（ipcguard 那套）、contextBridge 暴露的 electronAPI、参数消毒都在 preload
//   里建立。Electron 提供 webContents 的 'preload-error' 事件，在 preload 脚本：
//     - 加载/求值阶段直接抛错（文件缺失、语法错误、require 失败）；
//     - 运行期存在未捕获的异常；
//     - 存在未处理的 Promise rejection；
//   时回调。preload 一旦半途失败，contextBridge 暴露的 API 可能是“残缺”的：安全包装器
//   没有挂上、或某个通道的消毒没执行。这通常表现为功能坏掉，但也可能让本该被 preload
//   拦的参数以非预期形态进入主进程。因此主进程不能对 preload-error 无动于衷，必须：
//     1. 记录为高优先级安全/可靠性事件（preload 是可信代码，出错即异常基线）；
//     2. 对同一 (preloadPath, 错误指纹) 去重，防止错误循环把审计日志刷爆（DoS 放大器）；
//     3. 对单 contents 的 preload 错误总量设上限，越过即判定“preload 持续失效”。
//
//   本模块只做纯判定、指纹归一与去重计数，main.js 负责监听事件与 recordSecurityEvent。

const SEVERITY_CRITICAL = 'critical';
const SEVERITY_WARN = 'warn';

const KIND_LOAD = 'preload-load-error';       // 加载/求值期同步抛错
const KIND_EXCEPTION = 'preload-uncaught';    // 运行期未捕获异常
const KIND_REJECTION = 'preload-unhandled-rejection'; // 未处理的 Promise rejection
const KIND_UNKNOWN = 'preload-unknown-error';

const DECISION_REPORT = 'report';
const DECISION_IGNORE = 'ignore';

const IGNORE_DEDUP = 'duplicated-preload-error';
const IGNORE_CAPPED = 'preload-error-capped';
const IGNORE_BAD_STATE = 'preload-bad-state';

// 同一指纹错误最多记录次数（首次 + 少量重复），其余去重丢弃。
const MAX_REPORTS_PER_FINGERPRINT = 3;
// 单个 contents 在其生命周期内记录的 preload 错误总数上限，越过即只计数不留痕。
const MAX_REPORTS_PER_CONTENTS = 20;
// 指纹（归一化后的错误信息）最大保留长度，防止异常信息超长撑大内存。
const MAX_FINGERPRINT_LEN = 160;

function originFromUrl(rawUrl) {
  try {
    return new URL(rawUrl || '').origin;
  } catch {
    return '';
  }
}

// normalizePath 把 preload 路径里的反斜杠统一为斜杠并做小写，用于跨平台指纹稳定。
// 不做真实文件系统访问（内核须可在无 Electron 的 node:test 中运行）。
function normalizePath(p) {
  if (typeof p !== 'string') return '';
  return p.replace(/\\/g, '/').trim().toLowerCase();
}

// isPromiseRejection 依据 Electron 事件签名判断 rejection：
// 'preload-error'(event, preloadPath, error)；main.js 在拿到 error 后，用
//  error instanceof Error、以及 rejection 标志（调用方根据监听来源传入 kind 提示）。
// 这里提供基于 error 对象形状的启发式归类，供无法显式区分时兜底。
function classifyError(error, kindHint) {
  if (kindHint === KIND_REJECTION) return KIND_REJECTION;
  if (kindHint === KIND_LOAD) return KIND_LOAD;
  if (kindHint === KIND_EXCEPTION) return KIND_EXCEPTION;
  const e = error || {};
  if (e && typeof e === 'object' && e.name === 'UnhandledPromiseRejection') {
    return KIND_REJECTION;
  }
  if (e && typeof e === 'object' && (e.code === 'MODULE_NOT_FOUND' || e.code === 'ENOENT')) {
    return KIND_LOAD;
  }
  return KIND_UNKNOWN;
}

// errorFingerprint 生成稳定指纹：归一化路径 + 错误名 + 信息首行（去掉易变数字/地址）。
function errorFingerprint(preloadPath, error) {
  const e = error || {};
  let message = '';
  if (typeof e === 'string') message = e;
  else if (e && typeof e.message === 'string') message = e.message;
  else if (e && typeof e.toString === 'function') {
    try { message = e.toString(); } catch { message = ''; }
  }
  // 只取第一行，剥掉十六进制地址、行号列号等易变片段，让同一根因指纹稳定。
  let firstLine = message.split(/\r?\n/, 1)[0] || '';
  firstLine = firstLine
    .replace(/0x[0-9a-fA-F]+/g, '0x?')
    .replace(/:\d+:\d+(?=[\s)]|$)/g, ':?:?')
    .trim()
    .slice(0, MAX_FINGERPRINT_LEN);
  const name = (e && typeof e.name === 'string') ? e.name : 'Error';
  return `${normalizePath(preloadPath)}|${name}|${firstLine}`;
}

function createPreloadErrorState(now) {
  return {
    // fingerprint -> 已记录次数
    fingerprints: new Map(),
    totalErrors: 0,
    reportedCount: 0,
    loadErrorSeen: false,
    firstErrorAt: 0,
    lastErrorAt: 0,
    persistentFailure: false,
    createdAt: now || 0,
  };
}

// decidePreloadError 处理一次 preload-error。
// input: { preloadPath:string, error:Error|string, kindHint?:string, originUrl?:string }
// 返回 { decision, kind, severity, fingerprint, reason, origin, totalErrors, reportedCount,
//        persistentFailure }。DECISION_IGNORE 表示去重/限流丢弃，不再写审计。
function decidePreloadError(state, input, now) {
  const inp = input || {};
  if (!state) {
    return {
      decision: DECISION_IGNORE, kind: KIND_UNKNOWN, severity: SEVERITY_WARN,
      fingerprint: '', reason: IGNORE_BAD_STATE, origin: '',
      totalErrors: 0, reportedCount: 0, persistentFailure: false,
    };
  }
  const ts = typeof now === 'number' ? now : 0;
  if (!state.firstErrorAt) state.firstErrorAt = ts;
  state.lastErrorAt = ts;
  state.totalErrors += 1;

  const kind = classifyError(inp.error, inp.kindHint);
  const fingerprint = errorFingerprint(inp.preloadPath, inp.error);
  const origin = originFromUrl(inp.originUrl);
  const seen = state.fingerprints.get(fingerprint) || 0;

  // 加载期错误意味着 preload 整体可能没建成，提级为 critical。
  const severity = kind === KIND_LOAD ? SEVERITY_CRITICAL : SEVERITY_WARN;

  if (state.reportedCount >= MAX_REPORTS_PER_CONTENTS) {
    state.fingerprints.set(fingerprint, seen + 1);
    return {
      decision: DECISION_IGNORE, kind, severity, fingerprint, reason: IGNORE_CAPPED,
      origin, totalErrors: state.totalErrors, reportedCount: state.reportedCount,
      persistentFailure: state.persistentFailure,
    };
  }
  if (seen >= MAX_REPORTS_PER_FINGERPRINT) {
    state.fingerprints.set(fingerprint, seen + 1);
    return {
      decision: DECISION_IGNORE, kind, severity, fingerprint, reason: IGNORE_DEDUP,
      origin, totalErrors: state.totalErrors, reportedCount: state.reportedCount,
      persistentFailure: state.persistentFailure,
    };
  }

  state.fingerprints.set(fingerprint, seen + 1);
  state.reportedCount += 1;
  if (kind === KIND_LOAD) state.loadErrorSeen = true;
  // 出现加载期错误、或错误总量已很可观，判定 preload 在该 contents 上持续失效。
  if (state.loadErrorSeen || state.totalErrors >= MAX_REPORTS_PER_CONTENTS) {
    state.persistentFailure = true;
  }

  return {
    decision: DECISION_REPORT, kind, severity, fingerprint, reason: '',
    origin, totalErrors: state.totalErrors, reportedCount: state.reportedCount,
    persistentFailure: state.persistentFailure,
  };
}

// describePreloadError 给出安全事件中文文案。
function describePreloadError(result) {
  const r = result || {};
  const base = (() => {
    switch (r.kind) {
      case KIND_LOAD:
        return '预加载脚本加载/求值失败，IPC 安全桥可能未建立（严重）';
      case KIND_EXCEPTION:
        return '预加载脚本出现未捕获异常，部分安全包装可能缺失';
      case KIND_REJECTION:
        return '预加载脚本存在未处理的 Promise 拒绝';
      default:
        return '预加载脚本发生未知错误';
    }
  })();
  return r.fingerprint ? `${base}: ${r.fingerprint}` : base;
}

function describeIgnoreReason(reason) {
  switch (reason) {
    case IGNORE_DEDUP: return '同类 preload 错误已达记录上限，已去重';
    case IGNORE_CAPPED: return '该标签页 preload 错误总量已达上限，仅计数不再记录';
    case IGNORE_BAD_STATE: return '缺少有效的 preload 错误状态';
    default: return 'preload 错误被忽略';
  }
}

module.exports = {
  SEVERITY_CRITICAL,
  SEVERITY_WARN,
  KIND_LOAD,
  KIND_EXCEPTION,
  KIND_REJECTION,
  KIND_UNKNOWN,
  DECISION_REPORT,
  DECISION_IGNORE,
  IGNORE_DEDUP,
  IGNORE_CAPPED,
  IGNORE_BAD_STATE,
  MAX_REPORTS_PER_FINGERPRINT,
  MAX_REPORTS_PER_CONTENTS,
  MAX_FINGERPRINT_LEN,
  originFromUrl,
  normalizePath,
  classifyError,
  errorFingerprint,
  createPreloadErrorState,
  decidePreloadError,
  describePreloadError,
  describeIgnoreReason,
};
