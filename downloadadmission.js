'use strict';

// downloadadmission.js —— 下载准入的纯决策内核（不依赖 Electron / 不触碰文件系统）。
//
// 背景：will-download 处理器里“URL 是否允许、文件名怎么净化、属于可执行/伪装/MIME
// 不符中的哪一档”这段判定，历史上只以内联形式存在于 defaultSession 的回调里。
// 隔离 / 访客分区会话（session.fromPartition）触发的是各自 session 的 will-download，
// 默认会话上的监听器收不到，于是分区下载既没有文件名穿越净化、也没有可执行确认，
// 只能被 Chromium 默认逻辑静默处理。要把同一套保护公平地套到每个 session 上，先得
// 把“判定”从 Electron 事件回调里剥出来，变成可单测、可复用的纯函数。
//
// 本模块只做决策编排，具体能力由 deps 注入（isSafeUrl / 文件名净化 / dloadguard 类型
// 分析 / 决策常量），与 requestpipeline.js 的依赖注入风格一致，便于表驱动测试。

// 准入动作。前两类必须终止下载，confirm 需调用方弹窗问用户，warn 保存并轻提示。
const ACTION_BLOCK_UNSAFE = 'block-unsafe-url';
const ACTION_REJECT = 'reject';
const ACTION_CONFIRM = 'confirm';
const ACTION_WARN = 'warn';
const ACTION_ALLOW = 'allow';

// hostOf 尽力解析 URL 的主机；非法 URL 返回空串，不抛异常（下载链路上不能因解析
// 失败而中断判定）。
function hostOf(rawUrl) {
  try {
    return new URL(rawUrl).host || '';
  } catch {
    return '';
  }
}

// planDownloadAdmission 对一次待开始的下载给出准入结论。
//
// deps:
//   isSafeUrl(url) -> boolean                 是否为允许发起下载的安全协议/地址
//   sanitizeFilename(name) -> string          文件名穿越/伪装净化（必返回非空可落盘名）
//   analyzeName(filename, mime) -> analysis   dloadguard 的类型/伪装分析，至少含
//                                             { decision, displayName, finalExt, risks }
//   DECISION: { REJECT, CONFIRM, WARN, ALLOW } dloadguard 的决策常量
// input:
//   url          下载地址
//   rawFilename  服务端 Content-Disposition / 推断出的原始文件名（不可信）
//   mimeType     响应 MIME（可能为空串）
//
// 返回 { action, url, host, rawFilename, finalFilename, analysis }。
// block-unsafe / reject 时 analysis 可能为 null（block-unsafe 尚未做文件名分析）。
function planDownloadAdmission(deps, input) {
  const url = String((input && input.url) || '');
  const rawFilename = String((input && input.rawFilename) || '');
  const mimeType = String((input && input.mimeType) || '');
  const host = hostOf(url);
  const base = { url, host, rawFilename, finalFilename: '', analysis: null };

  let safeUrl = false;
  try {
    safeUrl = !!deps.isSafeUrl(url);
  } catch {
    safeUrl = false;
  }
  if (!safeUrl) {
    return Object.assign({}, base, { action: ACTION_BLOCK_UNSAFE });
  }

  let analysis;
  try {
    analysis = deps.analyzeName(rawFilename, mimeType) || {};
  } catch {
    // 分析器自身异常时按最严的 reject 处理，绝不带着未净化文件名继续落盘。
    analysis = { decision: deps.DECISION.REJECT, displayName: '', finalExt: '', risks: [] };
  }

  // displayName 与原始名都过一遍净化；任一可用即以分析内核的展示名为准。
  let finalFilename = '';
  try {
    finalFilename = analysis.displayName
      ? deps.sanitizeFilename(analysis.displayName)
      : deps.sanitizeFilename(rawFilename);
  } catch {
    finalFilename = '';
  }
  if (!finalFilename) finalFilename = 'download';

  const out = Object.assign({}, base, { finalFilename, analysis });
  switch (analysis.decision) {
    case deps.DECISION.REJECT:
      out.action = ACTION_REJECT;
      break;
    case deps.DECISION.CONFIRM:
      out.action = ACTION_CONFIRM;
      break;
    case deps.DECISION.WARN:
      out.action = ACTION_WARN;
      break;
    default:
      out.action = ACTION_ALLOW;
  }
  return out;
}

module.exports = {
  ACTION_BLOCK_UNSAFE,
  ACTION_REJECT,
  ACTION_CONFIRM,
  ACTION_WARN,
  ACTION_ALLOW,
  hostOf,
  planDownloadAdmission,
};
