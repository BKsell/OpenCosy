'use strict';

let d = {};

function bindDeps(next) {
  d = next;
}

async function launchExternalWithPrompt(url, origin, remember) {
  const scheme = normalizeExternalScheme(url);
  const gate = d.protocolRate.check(d.protocolRateLimiter, origin || '', scheme || '', String(url || ''), Date.now());
  if (!gate.ok) {
    d.recordSecurityEvent('protocol-throttled', 'warn',
      `${protocolRate.describeReason(gate.reason)}，已抑制本次唤起: ${String(url).slice(0, 120)}`, origin);
    return { ok: false, reason: gate.reason };
  }
  if (!scheme || !d.CONFIRMABLE_EXTERNAL_SCHEMES.has(scheme)) {
    d.recordSecurityEvent('protocol-blocked', 'warn',
      `尝试打开不可确认的外部协议 ${scheme || '(无效)'}: ${url}`, origin);
    d.sendToRenderer('show-toast', `已阻止打开外部协议: ${String(url).slice(0, 60)}`);
    return { ok: false, reason: 'blocked scheme' };
  }
  // 内容消毒：即便协议在白名单内，仍要挡住控制字符 / CRLF 注入 / 畸形 mailto、tel。
  // 交给系统的必须是 shellguard 放行后的规范化 URL（见 shellguard.js）。
  const extReview = d.shellGuard.reviewExternalUrl(url, d.CONFIRMABLE_EXTERNAL_SCHEMES);
  if (!extReview.ok) {
    d.recordSecurityEvent('protocol-blocked', 'warn',
      `外部唤起内容消毒未过（${shellGuard.describeReason(extReview.reason)}）: ${scheme}`, origin);
    d.sendToRenderer('show-toast', `已阻止不安全的外部链接: ${shellGuard.describeReason(extReview.reason)}`);
    return { ok: false, reason: extReview.reason };
  }
  const extBudget = d.externalBudget.judge({ url: extReview.url, origin, now: Date.now() });
  if (!extBudget.allowed) {
    d.recordSecurityEvent('protocol-flood', 'warn',
      `外部唤起被节流（${externalProtocolBudget.describeReason(extBudget.reason)}）: ${scheme}`, origin);
    d.sendToRenderer('show-toast', `已阻止外部协议唤起: ${externalProtocolBudget.describeReason(extBudget.reason)}`);
    return { ok: false, reason: extBudget.reason };
  }
  const safeExternalUrl = extReview.url;
  if (d.isRememberableOrigin(origin)) {
    const known = d.getRememberedProtocolDecision(origin, scheme);
    if (known === 'deny') {
      d.recordSecurityEvent('protocol-denied', 'info',
        `按记忆决定阻止 ${scheme} 协议唤起`, origin);
      d.sendToRenderer('show-toast', `已按记忆阻止 ${scheme} 协议（可在设置中撤销）`);
      return { ok: false, reason: 'remembered deny' };
    }
    if (known === 'allow') {
      try {
        await d.shell.openExternal(safeExternalUrl, { activate: true });
        return { ok: true, reason: 'remembered allow' };
      } catch (e) {
        return { ok: false, reason: String(e && e.message || e) };
      }
    }
  }
  const siteLabel = d.isRememberableOrigin(origin) ? origin : '当前页面';
  // 必须用异步版：showMessageBoxSync 只返回按钮序号，拿不到 checkbox 状态。
  const choice = await d.dialog.showMessageBox(d.mainWindow, {
    type: 'question',
    buttons: ['允许打开', '拒绝'],
    defaultId: 1,
    cancelId: 1,
    title: '网站想要打开外部应用',
    message: `${siteLabel} 想要打开:\n${safeExternalUrl}\n\n是否允许？`,
    checkboxLabel: '记住对此网站的选择（可在设置中撤销）',
    checkboxChecked: false
  });
  const checked = !!choice.checkboxChecked;
  const decision = choice.response === 0 ? 'allow' : 'deny';
  if (remember && checked && d.isRememberableOrigin(origin)) {
    d.rememberProtocolDecision(origin, scheme, decision);
  }
  if (decision !== 'allow') {
    d.recordSecurityEvent('protocol-denied', 'info', `用户拒绝了 ${scheme} 协议唤起`, origin);
    return { ok: false, reason: 'user denied' };
  }
  try {
    await d.shell.openExternal(safeExternalUrl, { activate: true });
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: String(e && e.message || e) };
  }
}

function classifyFrameNavigation(url, isMainFrame) {
  const scheme = normalizeExternalScheme(url);
  if (!scheme) return 'block';
  if (isMainFrame) {
    // 主框架允许的窗内协议与 isSafeUrl 保持一致，避免这里放行了别处不认的协议。
    if (scheme === 'http:' || scheme === 'https:' || scheme === 'file:' || scheme === 'cosy:') {
      return 'in-pane';
    }
  } else if (SUBFRAME_WEB_SCHEMES.has(scheme)) {
    return 'in-pane';
  }
  if (d.CONFIRMABLE_EXTERNAL_SCHEMES.has(scheme)) return 'confirm';
  return 'block';
}

function handleFrameNavigationAttempt(contents, url, isMainFrame) {
  const kind = classifyFrameNavigation(url, isMainFrame);
  if (kind === 'in-pane') return false;
  if (kind === 'confirm') {
    const origin = d.originOfContents(contents);
    // 不 await：导航事件里不能挂起异步流程，弹窗结果在另一条路径里处理。
    launchExternalWithPrompt(url, origin, true);
    return true;
  }
  const scheme = normalizeExternalScheme(url) || '未知协议';
  d.recordSecurityEvent('protocol-blocked', isMainFrame ? 'warn' : 'info',
    `${isMainFrame ? '主框架' : '子框架'}外部协议导航被阻止: ${scheme} ${url}`,
    d.originOfContents(contents));
  // 子框架拦截不弹 toast：恶意页面可以一秒塞几十个 iframe，toast 会变成轰炸。
  if (isMainFrame) {
    d.sendToRenderer('show-toast', `已阻止不安全的外部协议导航: ${scheme}`);
  } else {
    console.log(`[protocol-guard] 已阻止子框架外部协议导航: ${scheme}`);
  }
  return true;
}

async function confirmAndOpenExternal(url, origin) {
  if (!url || typeof url !== 'string') return { ok: false, reason: 'empty url' };
  if (url.startsWith('http://') || url.startsWith('https://')) {
    if (!d.isSafeUrl(url)) {
      d.recordSecurityEvent('protocol-blocked', 'critical',
        `外部协议入口拒绝了不安全的 http(s) 地址: ${url}`, origin);
      return { ok: false, reason: 'unsafe url' };
    }
    d.createNewTab(url);
    return { ok: true };
  }
  return await launchExternalWithPrompt(url, origin || '', false);
}

module.exports = { launchExternalWithPrompt, classifyFrameNavigation, handleFrameNavigationAttempt, confirmAndOpenExternal, bindDeps };
