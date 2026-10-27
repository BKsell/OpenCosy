'use strict';

// offlineguard.js —— 网络在线状态与“离线时该怎么处理请求/导航”的纯决策内核。
//
// 现代浏览器在 navigator.onLine=false 时只会让请求失败，不会给 UI 任何结构化提示，
// 也不区分“用户主动开了飞行模式”和“这是个纯本地页面”。本模块把这层判断收敛成
// 一组纯函数，供 main.js 在 online/offline 事件与 before-request 处复用，避免各处
// 各自写 `if (!navigator.onLine)` 又口径不一。
//
// 策略：
//   - file:// / chrome-extension:// / data: 等本地来源永远视为“可用”，不该因为断网
//     就提示离线；
//   - http(s) 导航在离线时，返回 showOfflineError=true，让 UI 渲染统一离线错误页，
//     而不是干等连接超时；
//   - 子资源（图片/字体/xhr）离线时不弹错误页，只允许调用方静默失败/走缓存；
//   - 不做真实网络探测（那会自己发请求、徒增流量与隐私面），只读 navigator.onLine。

const LOCAL_SCHEMES = new Set(['file:', 'chrome-extension:', 'data:', 'blob:', 'about:']);

function schemeOf(url) {
  const m = /^([a-z][a-z0-9+.-]*:)/i.exec(String(url || '').trim());
  return m ? m[1].toLowerCase() : '';
}

// isLocalOriginTarget 判断目标 URL 是否属于不依赖外网的本地来源。
function isLocalOriginTarget(url) {
  const s = schemeOf(url);
  return LOCAL_SCHEMES.has(s);
}

// decideOfflineRequest 对一次请求做离线决策。
// online: navigator.onLine 的当前值；details: { url, resourceType }。
// 返回 { mode: 'normal'|'local'|'offline-block'|'offline-soft', showBanner }。
function decideOfflineRequest(online, details) {
  const url = String((details && details.url) || '');
  const rt = (details && details.resourceType) || '';

  if (online) {
    return { mode: 'normal', showBanner: false };
  }
  // 离线了：本地来源照常放行。
  if (isLocalOriginTarget(url)) {
    return { mode: 'local', showBanner: false };
  }
  // 只对 http(s) 的离线请求做处理。
  const s = schemeOf(url);
  if (s !== 'http:' && s !== 'https:') {
    return { mode: 'local', showBanner: false };
  }
  // 顶层导航离线 -> 硬错误页；子资源 -> 软失败（静默，走缓存/空态）。
  if (rt === 'mainFrame') {
    return { mode: 'offline-block', showBanner: true };
  }
  return { mode: 'offline-soft', showBanner: true };
}

// offlineBannerText 给 UI 的一行状态文案，纯函数便于快照测试。
function offlineBannerText(online) {
  return online ? '' : '网络已断开，正在显示缓存内容';
}

// shouldSuppressOfflineForHost 白名单：某些 Web 应用自己有离线 Service Worker，
// 不该被本模块的硬拦截抢在前面。当前仅作为可扩展点，默认不压任何 host。
function shouldSuppressOfflineForHost(/* host */) {
  return false;
}

module.exports = {
  LOCAL_SCHEMES,
  schemeOf,
  isLocalOriginTarget,
  decideOfflineRequest,
  offlineBannerText,
  shouldSuppressOfflineForHost,
};
