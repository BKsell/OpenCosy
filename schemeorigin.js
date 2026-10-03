'use strict';

// schemeorigin.js —— 顶层导航的“目标协议 × 发起来源”安全矩阵。
//
// 威胁模型：
//   will-navigate / will-redirect 只在“页面自身发起导航”时触发（地址栏 loadURL、
//   新建标签等浏览器主动加载不触发）。历史代码只按目标协议分类：主框架把 file:
//   与内部 cosy: 一律视为窗内放行，没有检查“是谁发起的这次导航”。于是：
//     1) 任意 http(s) 网页可用 location.href='file:///C:/...' 把标签页顶成本地文件
//        视图，既能做本地资源探测 / UI 伪装，也能借浏览器壳打开本地文件上下文；
//     2) 任意网页可把顶层框架导航到 cosy://security、cosy://settings 等特权内部页。
//        内部页通过受信 preload 能读取安全台账 / 修改设置，即便旧页面被替换，
//        内部页也可能信任 URL 参数，构成“不可信源 → 特权页”跨越；
//     3) file: 或 data:text/html 这类本身就不可信的上下文，同样不应直接进入
//        浏览器特权内部页。
//
// 本模块只做纯判定，不碰 Electron API，便于单测。判定刻意保守：地址栏 / 浏览器
// 自身发起的导航没有发起来源，一律放行（走的是 loadURL，不经过这里）。

const INTERNAL_SCHEMES = new Set(['cosy:']);

// 内部协议集合：与 main.js 注册的自定义 scheme 保持同步。
function isInternalScheme(scheme) {
  return INTERNAL_SCHEMES.has(String(scheme || '').toLowerCase());
}

// safeParse 解析 URL，失败返回 null（不抛异常，便于在导航热路径里用）。
function safeParse(raw) {
  if (typeof raw !== 'string' || raw === '') return null;
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

// originSpace 把一个 URL 归到安全判定用的“来源空间”：
//   web       http / https
//   file      file:
//   internal  浏览器特权内部页（cosy:）
//   blob      blob: / filesystem:（继承其内嵌 origin，解析不出按 untrusted 处理）
//   data      data:
//   about     about:
//   other     其它（外部协议等，交由外部协议确认 / 拦截链路）
function originSpace(rawUrl) {
  const u = safeParse(rawUrl);
  if (!u) return 'other';
  const scheme = u.protocol.toLowerCase();
  if (scheme === 'http:' || scheme === 'https:') return 'web';
  if (scheme === 'file:') return 'file';
  if (isInternalScheme(scheme)) return 'internal';
  if (scheme === 'blob:' || scheme === 'filesystem:') return 'blob';
  if (scheme === 'data:') return 'data';
  if (scheme === 'about:') return 'about';
  return 'other';
}

// blob:/filesystem: 的真实来源要看内嵌 URL（blob:https://example.com/uuid）。
// 内嵌来源解析不出时，按不可信的 web 处理（宁枉勿纵），避免 'blob:' 伪装成无来源。
function effectiveInitiatorSpace(rawUrl) {
  const u = safeParse(rawUrl);
  if (!u) return 'none';
  const scheme = u.protocol.toLowerCase();
  if (scheme !== 'blob:' && scheme !== 'filesystem:') {
    return originSpace(rawUrl);
  }
  const rest = rawUrl.slice(scheme.length); // 去掉 "blob:" / "filesystem:"
  const inner = safeParse(rest);
  if (!inner) return 'web';
  const innerScheme = inner.protocol.toLowerCase();
  if (innerScheme === 'http:' || innerScheme === 'https:') return 'web';
  if (innerScheme === 'file:') return 'file';
  if (isInternalScheme(innerScheme)) return 'internal';
  return 'web';
}

// initiatorSpace 归一化发起来源；空 / about:blank 视为“浏览器自身 / 无来源”。
function initiatorSpace(rawUrl) {
  if (!rawUrl) return 'none';
  const space = effectiveInitiatorSpace(rawUrl);
  const u = safeParse(rawUrl);
  if (u && u.protocol.toLowerCase() === 'about:') return 'none';
  return space === 'other' ? 'none' : space;
}

// 允许导航到特权内部页的来源空间：内部页自身（内部跳转）、本地 file 上下文之外
// 的浏览器主动加载（none，即地址栏 / 新标签）。file / web / blob / data 全部拒绝。
const INTERNAL_ALLOWED_FROM = new Set(['internal', 'none']);
// 允许导航到 file: 的来源空间：另一个 file 页、内部页、浏览器主动加载。
const FILE_ALLOWED_FROM = new Set(['file', 'internal', 'none']);

// evaluate 对一次顶层导航做来源矩阵判定。
// 入参：
//   targetUrl     即将导航到的 URL
//   initiatorUrl  发起本次导航的页面 URL（contents.getURL()），无则空串
// 返回：
//   { action: 'allow' | 'block', target, from, reason }
function evaluate(targetUrl, initiatorUrl) {
  const target = originSpace(targetUrl);
  const from = initiatorSpace(initiatorUrl);

  if (target === 'internal') {
    if (!INTERNAL_ALLOWED_FROM.has(from)) {
      return {
        action: 'block', target, from,
        reason: 'untrusted-to-internal',
      };
    }
    return { action: 'allow', target, from, reason: 'internal-navigation' };
  }

  if (target === 'file') {
    if (!FILE_ALLOWED_FROM.has(from)) {
      return {
        action: 'block', target, from,
        reason: 'untrusted-to-file',
      };
    }
    return { action: 'allow', target, from, reason: 'local-file-navigation' };
  }

  // 其它目标（web / blob / data / about / 外部协议）不在本模块收紧，
  // 交给混合内容、子框架策略、外部协议确认等既有链路处理。
  return { action: 'allow', target, from, reason: 'delegated' };
}

// describeBlock 把拦截原因转成稳定的中文说明（用于安全事件，不含外部 URL 原文，
// 由调用方另行脱敏记录）。
function describeBlock(reason) {
  switch (reason) {
    case 'untrusted-to-internal':
      return '不可信网页试图导航到浏览器内部特权页面';
    case 'untrusted-to-file':
      return '网页试图导航到本地 file:// 资源';
    default:
      return '不安全的跨上下文导航';
  }
}

module.exports = {
  isInternalScheme,
  originSpace,
  effectiveInitiatorSpace,
  initiatorSpace,
  evaluate,
  describeBlock,
  INTERNAL_SCHEMES,
};
