"use strict";

const securityEventStorePath = path.join(app.getPath('userData'), 'security-events.json');
const MAX_SECURITY_EVENTS = 1000;
const MAX_SECURITY_DETAIL_CHARS = 300;

// 事件类型即 UI 上的分组；新增拦截点时优先复用已有类型。
function loadSecurityEvents() {
  if (securityEventsLoaded) return;
  securityEventsLoaded = true;
  try {
    const data = ledgerStore.readJSONStore(securityEventStorePath, {});
    const entries = Array.isArray(data && data.events) ? data.events : null;
    if (!entries) return;
    for (const e of entries) {
      if (!e || typeof e !== 'object') continue;
      if (!SECURITY_EVENT_TYPES.has(e.type)) continue;
      if (e.severity !== 'info' && e.severity !== 'warn' && e.severity !== 'critical') continue;
      securityEvents.push({
        id: String(e.id || ''),
        time: Number(e.time) || Date.now(),
        type: e.type,
        severity: e.severity,
        origin: typeof e.origin === 'string' ? e.origin.slice(0, 300) : '',
        detail: typeof e.detail === 'string' ? e.detail.slice(0, MAX_SECURITY_DETAIL_CHARS) : '',
      });
      if (securityEvents.length >= MAX_SECURITY_EVENTS) break;
    }
  } catch {}
}

function persistSecurityEvents() {
  if (securityEventSaveTimer) clearTimeout(securityEventSaveTimer);
  securityEventSaveTimer = setTimeout(() => {
    try {
      ledgerStore.writeJSONStore(securityEventStorePath, { version: 1, events: securityEvents });
    } catch {}
  }, 300);
}

// sanitizeSecurityDetail 清掉控制字符并限长。安全日志的展示方是我们自己的
// 内部页面，但仍按"数据不可信"处理：事件 detail 来自 URL / 文件名 / 权限名。
function sanitizeSecurityDetail(s) {
  let str = String(s == null ? '' : s);
  str = str.replace(/[\x00-\x1f\x7f]/g, ' ').replace(/\s+/g, ' ').trim();
  if (str.length > MAX_SECURITY_DETAIL_CHARS) {
    str = str.slice(0, MAX_SECURITY_DETAIL_CHARS) + '…';
  }
  return str;
}

function recordSecurityEvent(type, severity, detail = '', origin = '') {
  if (!SECURITY_EVENT_TYPES.has(type)) return;
  if (severity !== 'info' && severity !== 'warn' && severity !== 'critical') return;
  loadSecurityEvents();
  const event = {
    id: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
    time: Date.now(),
    type,
    severity,
    origin: sanitizeSecurityDetail(origin),
    detail: sanitizeSecurityDetail(detail),
  };
  securityEvents.push(event);
  // 超容丢最旧的，新事件永远在末尾（UI 展示时倒序）。
  if (securityEvents.length > MAX_SECURITY_EVENTS) {
    securityEvents.splice(0, securityEvents.length - MAX_SECURITY_EVENTS);
  }
  persistSecurityEvents();
}

// listSecurityEvents 返回事件副本（最新在前）。type 为空表示全部。
function listSecurityEvents(typeFilter = '', limit = 200) {
  loadSecurityEvents();
  let items = securityEvents;
  if (typeFilter && SECURITY_EVENT_TYPES.has(typeFilter)) {
    items = securityEvents.filter(e => e.type === typeFilter);
  }
  const n = Math.max(1, Math.min(Number(limit) || 200, MAX_SECURITY_EVENTS));
  return items.slice(-n).reverse().map(e => ({ ...e }));
}

function clearSecurityEvents() {
  loadSecurityEvents();
  securityEvents.length = 0;
  try { fsSync.unlinkSync(securityEventStorePath); } catch {}
  persistSecurityEvents();
  return true;
}

// ===== CSP 违规报告中心（csp-reports.json / cosy://security 面板）=====
// Chromium 的内容安全策略只负责"拦"，拦完之后在 Electron 里没有像 DevTools
// 那样统一的主进程出口：内部页面（cosy:// 系列）一旦出现注入尝试或资源
// 误引用，console 里的 Refused to load/exec 一闪而过，发布版根本看不到。
//
// 这里实现一条只服务于"我们自己内部页面"的上报链：
//   1. 内部页面监听 document 的 securitypolicyviolation（捕获阶段），
//      通过 preload 白名单通道 report-csp-violation 上报结构化字段；
//   2. 主进程不信任 renderer 自报的 documentURI / origin——一律以
//      event.senderFrame.url 为准重新判定，非 cosy:// 帧直接丢弃，
//      这样公网页面即使拿到 preload 桥也无法伪造或灌爆台账；
//   3. 每窗 10 秒最多 20 条，超出只记一条安全事件（防止恶意内部页面
//      死循环上报制造磁盘 / 渲染压力）；
//   4. 落 csp-reports.json（原子 rename，最近 500 条），字段全部控制
//      字符清洗 + 限长，UI 一律 textContent 渲染。

module.exports = { securityEventStorePath, MAX_SECURITY_EVENTS, MAX_SECURITY_DETAIL_CHARS, loadSecurityEvents, persistSecurityEvents, sanitizeSecurityDetail, recordSecurityEvent, listSecurityEvents, clearSecurityEvents };
