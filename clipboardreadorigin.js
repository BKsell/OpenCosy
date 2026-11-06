'use strict';

const REASON = Object.freeze({
  OK: 'ok',
  NOT_APPLICABLE: 'not-applicable',
  NOT_CLIPBOARD_READ: 'not-clipboard-read',
  BAD_PAGE_URL: 'bad-page-url',
  INSECURE_CONTEXT: 'insecure-context',
  CROSS_ORIGIN_FRAME: 'cross-origin-frame',
  BACKGROUND_TAB: 'background-tab',
  NO_USER_GESTURE: 'no-user-gesture',
});

function parsePage(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) return null;
  try {
    return new URL(rawUrl.trim());
  } catch {
    return null;
  }
}

function originOf(rawUrl) {
  const parsed = parsePage(rawUrl);
  if (!parsed) return '';
  return `${parsed.protocol}//${parsed.host}`.toLowerCase();
}

function isLoopbackHost(hostname) {
  const host = String(hostname || '').toLowerCase();
  return host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1';
}

function isSecureContextUrl(rawUrl) {
  const parsed = parsePage(rawUrl);
  if (!parsed) return false;
  if (parsed.protocol === 'https:') return true;
  if (parsed.protocol === 'http:' && isLoopbackHost(parsed.hostname)) return true;
  return false;
}

function decideClipboardRead(input = {}) {
  const permission = String(input.permission || '');
  if (permission && permission !== 'clipboard-read' && permission !== 'clipboard-sanitized-write') {
    return { allow: true, reason: REASON.NOT_APPLICABLE, detail: '非剪贴板权限不在此守卫范围' };
  }
  if (permission === 'clipboard-sanitized-write') {
    return { allow: true, reason: REASON.NOT_APPLICABLE, detail: '写剪贴板由其他守卫处理' };
  }

  const pageUrl = input.pageUrl;
  if (!parsePage(pageUrl)) {
    return { allow: false, reason: REASON.BAD_PAGE_URL, detail: '页面地址不可解析，无法确认来源' };
  }
  if (!isSecureContextUrl(pageUrl)) {
    return { allow: false, reason: REASON.INSECURE_CONTEXT, detail: '剪贴板读取只允许在安全上下文（https 或回环地址）中发生' };
  }

  const requestOrigin = originOf(input.requestOrigin);
  const pageOrigin = originOf(pageUrl);
  if (requestOrigin && pageOrigin && requestOrigin !== pageOrigin) {
    return { allow: false, reason: REASON.CROSS_ORIGIN_FRAME, detail: '请求来源与页面来源不一致，疑似跨源子框架调用' };
  }
  if (input.isTopFrame === false) {
    return { allow: false, reason: REASON.CROSS_ORIGIN_FRAME, detail: '剪贴板读取只对顶层框架开放' };
  }
  if (input.tabActive === false) {
    return { allow: false, reason: REASON.BACKGROUND_TAB, detail: '后台标签不得静默读取剪贴板' };
  }
  if (input.userGesture !== true) {
    return { allow: false, reason: REASON.NO_USER_GESTURE, detail: '缺少用户手势，拒绝读取剪贴板' };
  }
  return { allow: true, reason: REASON.OK, detail: '顶层前台标签且具备用户手势' };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK: return '允许读取剪贴板';
    case REASON.NOT_APPLICABLE: return '不在守卫范围';
    case REASON.NOT_CLIPBOARD_READ: return '非剪贴板读取权限';
    case REASON.BAD_PAGE_URL: return '页面地址不可解析';
    case REASON.INSECURE_CONTEXT: return '非安全上下文';
    case REASON.CROSS_ORIGIN_FRAME: return '跨源或非顶层框架';
    case REASON.BACKGROUND_TAB: return '后台标签';
    case REASON.NO_USER_GESTURE: return '缺少用户手势';
    default: return '未知原因';
  }
}

module.exports = {
  REASON,
  isSecureContextUrl,
  originOf,
  decideClipboardRead,
  describeReason,
};
