const { app } = require('electron');
const path = require('path');
const fsSync = require('fs');
const ledgerStore = require('./ledgerstore');

let sendToRenderer = () => {};

function bindRendererNotifier(fn) {
  if (typeof fn === 'function') sendToRenderer = fn;
}

// ===== 安全事件中心（security-events.json / cosy://security）=====
// 浏览器自身的安全闸（外部协议拦截、危险下载确认、设备权限、扩展校验、
// 权限收口等）以前只有两种反馈：要么 toast 一闪而过，要么只写 console。
// 用户关掉 toast 后就没有任何地方能回答"刚才浏览器到底替我挡了什么、
// 是哪个网站在尝试"。这里把这些事件统一留痕：
//
//   - 落 userData/security-events.json，原子 rename，最多保留 1000 条；
//   - 每条明细脱敏限长，不记录 Cookie / 完整 URL 查询串以外的敏感数据，
//     控制字符一律清掉，防止日志本身成为 XSS / 注入载体；
//   - cosy://security 页面只读展示，可清空；IPC 仅主框架可调。
const securityEventStorePath = path.join(app.getPath('userData'), 'security-events.json');
const MAX_SECURITY_EVENTS = 1000;
const MAX_SECURITY_DETAIL_CHARS = 300;

// 事件类型即 UI 上的分组；新增拦截点时优先复用已有类型。
const SECURITY_EVENT_TYPES = new Set([
  'protocol-blocked',        // 危险外部协议导航 / 唤起被阻止
  'protocol-denied',         // 用户（或记忆决定）拒绝了外部协议唤起
  'download-blocked',        // 下载被直接阻止（非法 URL / 不安全来源）
  'download-rejected',       // 用户在危险文件确认框中取消
  'permission-blocked',      // 未在白名单内的浏览器权限请求被拒绝
  'device-permission-blocked', // HID/串口/USB/蓝牙等设备选择被拒绝
  'display-capture-blocked', // getDisplayMedia 屏幕/窗口/系统音频共享被拒绝
  'bluetooth-blocked',       // select-bluetooth-device 自动选择被显式取消
  'serial-blocked',          // select-serial-port 自动选择被显式取消
  'hid-blocked',             // select-hid-device 自动选择被显式取消
  'usb-blocked',             // select-usb-device 自动选择被显式取消
  'file-remote-blocked',     // file: 协议指向远程/UNC host 被拒绝
  'launch-switch-warn',      // 命令行/环境变量出现降硬（非致命）开关
  'redirect-blocked',        // 服务端重定向降级/环路/钓鱼/危险协议被拦截
  'extension-blocked',       // 扩展请求危险权限 / 校验未过
  'mixed-content-blocked',   // HTTPS 页面主动混合内容（HTTP 脚本/XHR 等）被阻止
  'auth-blocked',            // 子框架/未知方案 401/407 凭据探测被静默取消
  'auth-rate-limited',       // 同一主机认证弹框过频，进入冷却
  'client-cert-blocked',     // 无明确选择时默认不发送客户端证书
  'cookie-blocked',          // 第三方 / 非法前缀 / 无效 Secure 的 Set-Cookie 被剥离
  'pna-blocked',             // 公网页面访问本机/内网/链路本地被 PNA 拦截
  'fingerprint-blocked',     // 高熵 Client Hints / 广告信号 / 超链接打点被收敛
  'origin-boundary-blocked', // 不可信网页顶窗跳 file:/内部特权页被来源矩阵拦截
  'webview-blocked',         // <webview> 挂载 src 非法或携带提权配置被阻止 / 收口
  'window-policy',           // 窗口 webPreferences 出现越界/不安全配置被基线拒绝
  'renderer-gone',           // 渲染/GPU 进程崩溃与无响应的恢复 / 熔断处置
  'deeplink-blocked',        // 命令行/open-file/open-url 非法深链被入口消毒拦截
  'keyboard-lock-blocked',   // 网页在非全屏/高频请求键盘锁（Esc 劫持）被阻止
  'fullscreen-abuse',        // 短时间高频进出全屏（疑似点击劫持）被记录
  'print-blocked',           // window.print() 打印轰炸/冷却期请求被抑制
  'zoom-flood',              // ctrl+滚轮缩放事件洪泛，已合并广播并记录
  'devtools-url-blocked',    // DevTools 内危险/外部协议链接转跳被拦截
  'preload-error',           // preload 脚本加载/运行异常（IPC 安全桥可能残缺）
  'dialog-blocked',          // alert/confirm/prompt 弹窗轰炸 / 同文案递归 / 冷却期被抑制
  'find-rate-limited',       // 页内查找 IPC 超长/控制字符输入或高频洪泛被限流
  'title-abuse',             // 标签标题/图标高频翻转、畸形输入或非法图标来源被收敛
  'unload-bypass',           // beforeunload 强留页轰炸，越限后直接放行离开
  'inpage-flood',            // pushState/replaceState 同文档导航洪泛 / 畸形 URL 被收敛
  'console-flood',           // console-message 控制字符/超长或高频洪泛被收敛
  'hover-flood',             // update-target-url 状态栏伪造/换行注入或洪泛被收敛
  'theme-abuse',             // theme-color 非法配色/高频闪烁（伪装顶栏）被锁定
  'media-flood',             // 媒体 play/pause 自动播放风暴/媒体键抖动被冻结指示
  'plugin-crash',            // 插件崩溃字段非法或崩溃循环提示被折叠/丢弃
  'cursor-abuse',            // cursor-changed 未知类型/超大位图/高频抖动回落默认光标
  'entry-flood',             // navigation-entry-committed 脏地址/历史条目洪泛被收敛
  'child-window-blocked',    // 意外原生子窗口基线被破坏/危险首屏/开窗洪泛被销毁
  'frame-blocked',           // 子框架危险协议/畸形 URL/iframe 爆炸被收敛
  'screen-capture-active',   // 某标签进入屏幕/窗口捕获态（亮红点 + 留痕）
  'devtools-switch',         // DevTools 在真实网页/隔离子窗被打开（隔离窗立即关闭）
  'context-menu-sanitized',  // 右键菜单参数（链接/选中文本/错词/建议）被净化或丢弃
  'ipc-input-rejected',      // 渲染侧 IPC 入参形状/长度/控制字符/体量畸形被拒绝
  'remote-bridge-blocked',   // @electron/remote 反向通道 / desktopCapturer 枚举被阻断
  'raw-ipc-blocked',         // 渲染层直发原始 IPC（绕过 contextBridge）/ 同步 IPC 被收口
  'ipc-denied',
  'device-authorization-revoked', // HID/串口/蓝牙设备授权被用户收回或设备掉线（去重留痕）
  'gpu-info-update',         // GPU 被重新枚举（auxAttributes 白名单清洗，软件渲染回退告警）
  'gpu-process-crashed',     // GPU 进程崩溃/被杀（崩溃风暴折叠，提示重载）
  'accessibility-changed',   // 系统无障碍/读屏支持被打开（渲染路径变化留痕）
  'session-hardened',        // 新建非默认会话已默认拒绝权限/设备并套用隐私头
  'session-partition-rejected', // 会话分区串非法（仍强制默认拒绝，不留裸奔会话）
  'storage-cross-access',    // 跨站子框架读写顶层会话存储/缓存（每桶首次留痕）
  'storage-access-flood',    // 存储/缓存访问事件高频洪泛（窗内越限升级）
]);

const securityEvents = [];
let securityEventsLoaded = false;
let securityEventSaveTimer = null;

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
const cspReportStorePath = path.join(app.getPath('userData'), 'csp-reports.json');
const MAX_CSP_REPORTS = 500;
const CSP_RATE_WINDOW_MS = 10_000;
const CSP_RATE_MAX_PER_WINDOW = 20;
const CSP_FIELD_MAX = 300;

const cspReports = [];
let cspReportsLoaded = false;
let cspReportSaveTimer = null;
const cspRateBuckets = new Map(); // senderFrame.id -> { start, count }
const CSP_RATE_MAX_BUCKETS = 1024;

function isInternalFrameSender(senderFrame) {
  if (!senderFrame || typeof senderFrame.url !== 'string') return false;
  let u = '';
  try { u = new URL(senderFrame.url); } catch { return false; }
  return u.protocol === 'cosy:';
}

function loadCspReports() {
  if (cspReportsLoaded) return;
  cspReportsLoaded = true;
  try {
    const data = ledgerStore.readJSONStore(cspReportStorePath, {});
    const entries = Array.isArray(data && data.reports) ? data.reports : null;
    if (!entries) return;
    for (const r of entries) {
      if (!r || typeof r !== 'object') continue;
      if (typeof r.documentUri !== 'string' || !r.documentUri.startsWith('cosy:')) continue;
      if (typeof r.directive !== 'string' || !r.directive) continue;
      cspReports.push({
        id: String(r.id || ''),
        time: Number(r.time) || Date.now(),
        documentUri: r.documentUri.slice(0, CSP_FIELD_MAX),
        directive: r.directive.slice(0, CSP_FIELD_MAX),
        blockedUri: typeof r.blockedUri === 'string' ? r.blockedUri.slice(0, CSP_FIELD_MAX) : '',
        sourceFile: typeof r.sourceFile === 'string' ? r.sourceFile.slice(0, CSP_FIELD_MAX) : '',
        lineNumber: Number.isFinite(Number(r.lineNumber)) ? Number(r.lineNumber) : 0,
        columnNumber: Number.isFinite(Number(r.columnNumber)) ? Number(r.columnNumber) : 0,
        disposition: r.disposition === 'report' ? 'report' : 'enforce',
        // hits 是同一来源（documentUri+directive+blockedUri）的累计命中次数；
        // 老台账没有该字段，按 1 次补默认值，避免旧数据展示成 NaN/空白。
        hits: Math.max(1, Number(r.hits) || 1),
        lastTime: Number(r.lastTime) || (Number(r.time) || Date.now()),
      });
      if (cspReports.length >= MAX_CSP_REPORTS) break;
    }
  } catch {}
}

function persistCspReports() {
  if (cspReportSaveTimer) clearTimeout(cspReportSaveTimer);
  cspReportSaveTimer = setTimeout(() => {
    try {
      ledgerStore.writeJSONStore(cspReportStorePath, { version: 1, reports: cspReports });
    } catch {}
  }, 300);
}

function sanitizeCspField(v) {
  let s = String(v == null ? '' : v);
  s = s.replace(/[\x00-\x1f\x7f]/g, ' ').replace(/\s+/g, ' ').trim();
  return s.length > CSP_FIELD_MAX ? s.slice(0, CSP_FIELD_MAX) + '…' : s;
}

// cspRateLimitAllowed 判断该帧当前窗口内是否还能再上报一条。
// 帧关闭后 bucket 不会立刻清理，但 Map 体积受存活内部页数量限制，
// 下一轮窗口自然过期复用，无需额外生命周期钩子。
function cspRateLimitAllowed(frame) {
  const now = Date.now();
  const key = frame && frame.frameTreeNodeId != null ? frame.frameTreeNodeId : 0;
  if (cspRateBuckets.size >= CSP_RATE_MAX_BUCKETS) {
    for (const [k, b] of cspRateBuckets) {
      if (now - b.start >= CSP_RATE_WINDOW_MS) cspRateBuckets.delete(k);
    }
    while (cspRateBuckets.size >= CSP_RATE_MAX_BUCKETS) {
      cspRateBuckets.delete(cspRateBuckets.keys().next().value);
    }
  }
  let bucket = cspRateBuckets.get(key);
  if (!bucket || now - bucket.start >= CSP_RATE_WINDOW_MS) {
    bucket = { start: now, count: 0 };
    cspRateBuckets.set(key, bucket);
  }
  bucket.count += 1;
  return bucket.count <= CSP_RATE_MAX_PER_WINDOW;
}

// recordCspViolationFromRenderer 处理 renderer 上报。返回 { accepted }；
// 拒绝不抛错（上报通道本身不能影响页面运行）。
function recordCspViolationFromRenderer(senderFrame, payload) {
  if (!isInternalFrameSender(senderFrame)) {
    return { accepted: false, reason: 'non-internal frame' };
  }
  if (!cspRateLimitAllowed(senderFrame)) {
    recordSecurityEvent('permission-blocked', 'warn',
      '内部页面 CSP 上报过于频繁，已丢弃后续报告', senderFrame.url);
    return { accepted: false, reason: 'rate limited' };
  }
  loadCspReports();
  let frameUrl = '';
  try { frameUrl = new URL(senderFrame.url).href; } catch { frameUrl = senderFrame.url; }
  const directive = sanitizeCspField(payload && payload.directive);
  if (!directive) return { accepted: false, reason: 'missing directive' };
  const documentUri = sanitizeCspField(frameUrl);
  const blockedUri = sanitizeCspField(payload && payload.blockedUri);
  const now = Date.now();

  // 同一页面、同一指令、同一被拦资源反复触发时只保留一条聚合记录，
  // 用 hits 记次数并把它移到队尾（等同“最近再次出现”），避免一个页面
  // 的持续性违规把 500 条台账瞬间刷满、淹没其它来源。
  const dedupeKey = `${documentUri}\u0000${directive}\u0000${blockedUri}`;
  const existingIdx = cspReports.findIndex(r =>
    `${r.documentUri}\u0000${r.directive}\u0000${r.blockedUri}` === dedupeKey);
  if (existingIdx >= 0) {
    const existing = cspReports[existingIdx];
    existing.hits = Math.min(Number.MAX_SAFE_INTEGER, (Number(existing.hits) || 1) + 1);
    existing.lastTime = now;
    // 行/列等定位信息更新为最近一次，方便点进最新现场。
    existing.sourceFile = sanitizeCspField(payload && payload.sourceFile);
    existing.lineNumber = Math.max(0, Number(payload && payload.lineNumber) || 0);
    existing.columnNumber = Math.max(0, Number(payload && payload.columnNumber) || 0);
    cspReports.splice(existingIdx, 1);
    cspReports.push(existing);
    if (cspReports.length > MAX_CSP_REPORTS) {
      cspReports.splice(0, cspReports.length - MAX_CSP_REPORTS);
    }
    persistCspReports();
    sendToRenderer('csp-report-added', { ...existing });
    return { accepted: true, aggregated: true };
  }

  const report = {
    id: `${now.toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
    time: now,
    documentUri,
    directive,
    blockedUri,
    sourceFile: sanitizeCspField(payload && payload.sourceFile),
    lineNumber: Math.max(0, Number(payload && payload.lineNumber) || 0),
    columnNumber: Math.max(0, Number(payload && payload.columnNumber) || 0),
    disposition: payload && payload.disposition === 'report' ? 'report' : 'enforce',
    hits: 1,
    lastTime: now,
  };
  cspReports.push(report);
  if (cspReports.length > MAX_CSP_REPORTS) {
    cspReports.splice(0, cspReports.length - MAX_CSP_REPORTS);
  }
  persistCspReports();
  sendToRenderer('csp-report-added', { ...report });
  return { accepted: true };
}

function listCspReports(limit = 200) {
  loadCspReports();
  const n = Math.max(1, Math.min(Number(limit) || 200, MAX_CSP_REPORTS));
  return cspReports.slice(-n).reverse().map(r => ({ ...r }));
}

function clearCspReports() {
  loadCspReports();
  cspReports.length = 0;
  try { fsSync.unlinkSync(cspReportStorePath); } catch {}
  persistCspReports();
  return true;
}

// removeCspReport 按 id 删除单条聚合记录（安全页面板“忽略/删除这一条”用）。
// id 只接受字符串并做限长，命中才落盘；返回是否真的删掉了一条。
function removeCspReport(id) {
  loadCspReports();
  if (typeof id !== 'string') return false;
  const target = id.slice(0, 128);
  const idx = cspReports.findIndex(r => r.id === target);
  if (idx < 0) return false;
  cspReports.splice(idx, 1);
  persistCspReports();
  return true;
}

// getCspReportStats 返回台账总量与命中总数，供安全页面板顶部徽标使用，
// 不必把全部记录拉到 renderer 再做 reduce。
function getCspReportStats() {
  loadCspReports();
  let totalHits = 0;
  for (const r of cspReports) totalHits += Number(r.hits) || 1;
  return { groups: cspReports.length, totalHits };
}

module.exports = {
  bindRendererNotifier,
  recordSecurityEvent,
  listSecurityEvents,
  clearSecurityEvents,
  recordCspViolationFromRenderer,
  listCspReports,
  clearCspReports,
  removeCspReport,
  getCspReportStats,
};
