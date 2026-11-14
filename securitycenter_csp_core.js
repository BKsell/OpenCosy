const { securityEventStorePath, MAX_SECURITY_EVENTS, MAX_SECURITY_DETAIL_CHARS, loadSecurityEvents, persistSecurityEvents, sanitizeSecurityDetail, recordSecurityEvent, listSecurityEvents, clearSecurityEvents } = require('./cspsecurityevents_core');
const { app } = require('electron');
const path = require('path');
const fsSync = require('fs');
const ledgerStore = require('./ledgerstore_core');


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
  'clipboard-read-blocked',
  'download-confirmed',
  'download-content',
  'download-disk',
  'download-finish',
  'download-journal',
  'download-motw',
  'download-name',
  'download-notify',
  'download-open-blocked',
  'download-paused',
  'download-quota',
  'download-rate-limited',
  'download-resumed',
  'download-savepath',
  'download-size',
  'download-url',
  'downloads-load',
  'downloads-persist',
  'external-open-background',
  'external-open-denied',
  'external-open-prompt',
  'external-open-subframe',
  'https-only',
  'ledger-persist',
  'nav-blocked',
  'nav-guard-error',
  'nav-warn',
  'permission-cap',
  'permission-expired',
  'permission-frame',
  'plugin-resource',
  'popup-blocked',
  'protocol-flood',
  'protocol-throttled',
  'request-method',
  'settings-search-provider',
  'vault-key',
]);

const securityEvents = [];
let securityEventsLoaded = false;
let securityEventSaveTimer = null;

const cspReportStorePath = path.join(app.getPath('userData'), 'csp-reports.json');
const MAX_CSP_REPORTS = 500;
const CSP_RATE_WINDOW_MS = 10_000;
const CSP_RATE_MAX_PER_WINDOW = 20;

module.exports = {
  sendToRenderer,
  bindRendererNotifier,
  securityEventStorePath,
  MAX_SECURITY_EVENTS,
  MAX_SECURITY_DETAIL_CHARS,
  SECURITY_EVENT_TYPES,
  securityEvents,
  securityEventsLoaded,
  securityEventSaveTimer,
  loadSecurityEvents,
  persistSecurityEvents,
  sanitizeSecurityDetail,
  recordSecurityEvent,
  listSecurityEvents,
  clearSecurityEvents,
  cspReportStorePath,
  MAX_CSP_REPORTS,
  CSP_RATE_WINDOW_MS,
  CSP_RATE_MAX_PER_WINDOW,
};
