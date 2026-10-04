const { app, BrowserWindow, WebContentsView, ipcMain, session, protocol, Menu, MenuItem, dialog, shell, globalShortcut, clipboard, net, nativeTheme, webContents } = require('electron');
const path = require('path');
const fs = require('fs').promises;
const fsSync = require('fs');
const os = require('os');
const bookmarkIO = require('./bookmarkio');
const headerGrade = require('./headergrade');
const requestLog = require('./requestlog');
const brandGuard = require('./brandguard');
const phishUrl = require('./phishurl');
const certGuard = require('./certguard');
const mixedGuard = require('./mixedguard');
const netAuthGuard = require('./netauthguard');
const cookieGuard = require('./cookieguard');
const pnaGuard = require('./pna');
const fpGuard = require('./fpguard');
const dohGuard = require('./dohguard');
const permPolicy = require('./permpolicy');
const dloadGuard = require('./dloadguard');
const urlClean = require('./urlclean');
const popupGuard = require('./popupguard');
const quarantine = require('./quarantine');
const navGuard = require('./navguard');
const containerGuard = require('./container');
const schemeOrigin = require('./schemeorigin');
const webviewHarden = require('./webviewharden');
const winPolicy = require('./winpolicy');
const goneGuard = require('./goneguard');
const shellGuard = require('./shellguard');
const deeplinkGuard = require('./deeplinkguard');
const ipcGuard = require('./ipcguard');
const channelPolicy = require('./channelpolicy');
const displayGuard = require('./displayguard');
const redirectGuard = require('./redirectguard');
const switchGuard = require('./switchguard');
const devicerGuard = require('./devicerguard');
const cosyScheme = require('./cosyscheme');
const fullscreenGuard = require('./fullscreenguard');
const printGuard = require('./printguard');
const zoomGuard = require('./zoomguard');
const devtoolsGuard = require('./devtoolsguard');
const preloadGuard = require('./preloadguard');
const dialogGuard = require('./dialogguard');
const findGuard = require('./findguard');
const titleGuard = require('./titleguard');
const unloadGuard = require('./unloadguard');
const inpageGuard = require('./inpageguard');
// r32：控制台 / 悬停状态栏 / 主题色 / 媒体状态 / 插件崩溃 / 光标 / 历史条目事件收口内核。
const consoleGuard = require('./consoleguard');
const hoverGuard = require('./hoverguard');
const themeGuard = require('./themeguard');
const mediaGuard = require('./mediaguard');
const crashGuard = require('./crashguard');
const cursorGuard = require('./cursorguard');
const entryGuard = require('./entryguard');
// r33：意外原生子窗口 / iframe 生命周期 / 屏幕捕获状态 / DevTools 开关 / 右键参数 /
// IPC 入参形状，六个此前 0 接线的收口内核。
const childWindowGuard = require('./childwindowguard');
const frameGuard = require('./frameguard');
const captureGuard = require('./captureguard');
const devtoolsSwitchGuard = require('./devtoolswitchguard');
const menuGuard = require('./menuguard');
const inputGuard = require('./inputguard');
const remoteGuard = require('./remoteguard');
const ipcChannelGuard = require('./ipcchannelguard');
// r34：设备授权撤销 / GPU 进程与无障碍系统事件 / 多分区会话加固 / 跨框架存储访问，
// 四类此前 0 接线（会话策略只挂 defaultSession，分区/访客会话裸奔）的收口内核。
const revokeGuard = require('./revokeguard');
const gpuAccessGuard = require('./gpuaccessguard');
const sessionGuard = require('./sessionguard');
const storageAccessGuard = require('./storageaccessguard');
const historyGuard = require('./historyguard');
const bookmarkGuard = require('./bookmarkguard');
const restoreGuard = require('./restoreguard');
const { pathToFileURL } = require('url');

// 危险命令行开关 / ELECTRON_EXTRA_LAUNCH_ARGS 注入必须在 ready 之前就拦下：
// --disable-web-security / --remote-debugging-port / --proxy-server / --no-sandbox 等
// 在进程启动极早期就击穿安全模型，上层权限/网络防线全部不生效。这里只读 process.argv
// 快照与环境变量（app.commandLine.appendSwitch 自身追加的安全开关不会进 process.argv）。
const launchSwitchAudit = switchGuard.auditSwitches(switchGuard.collectSources(process));
if (launchSwitchAudit.hasCritical) {
  for (const f of launchSwitchAudit.findings) {
    if (f.severity === switchGuard.SEVERITY_CRITICAL) {
      // 安全事件存储此刻可能尚未初始化，先走 stderr，再在错误框里呈现。
      console.error(`[switchguard] 拒绝启动：危险开关 ${f.flag.raw}（来源 ${f.flag.source}）：${f.reason}`);
    }
  }
  const criticalText = launchSwitchAudit.criticalFlags
    .map(f => `${f.raw}${f.source === 'env:ELECTRON_EXTRA_LAUNCH_ARGS' ? '（环境变量注入）' : ''}`)
    .join('\n');
  // showErrorBox 可在 ready 前使用；给出原因后立即退出，阻止带毒浏览器继续运行。
  try {
    dialog.showErrorBox('检测到危险启动参数，OpenCosy 已拒绝启动',
      `以下命令行开关会关闭浏览器安全防护，请检查快捷方式/启动器/环境变量后重试：\n\n${criticalText}`);
  } catch {}
  app.exit(78);
}
// 非致命的降硬开关（disable-popup-blocking / enable-logging 等）不阻断启动，ready 前
// 事件存储未就绪，先写 stderr，待安全系统可用后由 ready 回调补登一条聚合记录。
for (const f of launchSwitchAudit.warnFlags) {
  console.warn(`[switchguard] 降硬开关 ${f.flag.raw}（来源 ${f.flag.source}）：${f.reason}`);
}

// 必须在 app ready 之前把 cosy: 登记为 standard + secure 特权协议，否则内置页（设置/安全/
// 权限/下载）会被当成非标准、非安全上下文，host/同源/CSP 解析都不一致。bypassCSP 不开。
try {
  protocol.registerSchemesAsPrivileged(cosyScheme.privilegedSchemeOptions());
} catch (e) {
  console.error('[cosyscheme] registerSchemesAsPrivileged 失败:', e);
}

// 现代浏览器默认要求“用户与页面有过交互”才允许带声音自动播放，
// 否则广告页一打开就能外放声音。必须在 app ready 之前设置。
app.commandLine.appendSwitch('autoplay-policy', 'document-user-activation-required');
// 禁用后台标签页的定时器节流之外的媒体/后台同步并非必要；这里只关掉
// 隐私上有顾虑的媒体推荐与 WebRTC 继续采集策略，保持其余行为不变。
app.commandLine.appendSwitch('disable-features', 'MediaRouter');

let mainWindow;
let tabs = [];
let currentTabIndex = 0;
let fileToOpen = null;
let downloads = [];
let currentDownloadInfo = null;
let isTabBarCollapsed = false;
let bookmarks = [];
let history = [];
let recentlyClosedTabs = [];

// 弹窗轰炸防护：单个标签在 POPUP_WINDOW_MS 时间窗内最多主动打开 POPUP_WINDOW_MAX 个新窗口。
// 恶意/广告页可能在脚本里疯狂 window.open 制造窗口洪流耗尽资源；
// 正常用户点击几乎不会在几秒内连续开这么多窗口，超出的一律拦截并提示。
const POPUP_WINDOW_MAX = 3;
const POPUP_WINDOW_MS = 5000;
const popupOpenTimes = new Map();

function allowPopupForTab(tabId) {
  const now = Date.now();
  const times = (popupOpenTimes.get(tabId) || []).filter(t => now - t < POPUP_WINDOW_MS);
  if (times.length >= POPUP_WINDOW_MAX) {
    popupOpenTimes.set(tabId, times);
    return false;
  }
  times.push(now);
  popupOpenTimes.set(tabId, times);
  return true;
}

// httpsOnlyEnabled 是运行时开关，默认 true；用户可以在设置里关掉。
// onBeforeRequest 据此决定是否把 http:// 升级成 https://。
let httpsOnlyEnabled = true;

// blockTrackers：第三方追踪/广告请求拦截（隐私），默认开启。
// 只拦“子资源”请求（脚本/图片/xhr/ping 等），从不拦 mainFrame 顶层导航，
// 所以即使域名误判，用户手动点开对应网站也不会被挡。
let blockTrackers = true;
// blockThirdPartyCookies：跨站（第三方）上下文写入的 Cookie 一律剥离，
// 掐断跨站追踪与 CSRF 的主要载体；默认开启，可在设置里关闭。
let blockThirdPartyCookies = true;
// hardenCookies：对第一方 Set-Cookie 补 SameSite=Lax、修正 SameSite=None 缺
// Secure、剥离非法 __Host-/__Secure- 前缀 Cookie 与 http 下的 Secure Cookie。
let hardenCookies = true;
// blockLocalNetworkAccess：阻止公网页面通过子资源请求访问本机 / 内网 /
// 169.254.169.254 云元数据等“更私有”地址（PNA 私有网络访问），默认开启。
// 顶层导航和内网页面自己访问内网不受影响。
let blockLocalNetworkAccess = true;
// reduceClientHints：剥离 Sec-CH-UA-Arch/Bitness/Model/Full-Version 等高熵提示，
// 只留兼容性所需的低熵 sec-ch-ua / platform，降低跨站可指纹度。
let reduceClientHints = true;
// blockAdSignals：剥离 Sec-Browsing-Topics、Attribution-Reporting-* 等广告归因头。
let blockAdSignals = true;
// blockHyperlinkPing：取消 <a ping> / 带 Ping-To 的超链接审计打点请求。
let blockHyperlinkPing = true;
// stripAcceptCh：移除站点下发的 Accept-CH / Critical-CH，阻止其订阅高熵提示
// 并触发带新头的重试。
let stripAcceptCh = true;
// webrtcMode：strict(默认,不暴露内网 IP) / balanced(mDNS 混淆) / legacy(不干预)。
let webrtcMode = fpGuard.DEFAULT_WEBRTC_POLICY;
// 安全 DNS（DoH）：dohMode off/automatic(默认)/secure；dohProvider 为内置 id 或 custom。
let dohMode = dohGuard.DEFAULT_MODE;
let dohProvider = 'cloudflare';
let dohCustomUrl = '';
let dohActive = false; // 运行时实际是否成功启用了宿主解析器控件
// crashRecovery：渲染进程崩溃 / OOM 时自动重载一次并弹横幅；可在设置关闭。
let crashRecoveryEnabled = true;
// 每个 webContents 的崩溃次数，用于阻止“崩溃→重载→又崩溃”的无限循环。
const crashReloadCounts = new Map();
// 每个页面 webContents 一条服务端重定向链状态（降级/环路/钓鱼），did-navigate 归零。
const redirectChainStates = new Map();
// r31：弹窗轰炸 / 强留页 / 标题图标洪泛 / 同文档导航洪泛，均按 webContents 独立计态。
const dialogStates = new Map();
const unloadStates = new Map();
const titleStates = new Map();
const inpageStates = new Map();
// r32：各新增 webContents 事件通道的 per-contents 状态，did-navigate 归零、destroyed 清理。
const consoleStates = new Map();
const hoverStates = new Map();
const themeStates = new Map();
const mediaStates = new Map();
const crashStates = new Map();
const cursorStates = new Map();
const entryStates = new Map();
// r33：意外子窗口 / 框架 / 捕获 / DevTools 开关的 per-contents 状态，did-navigate 归零。
const childWindowStates = new Map();
const frameStates = new Map();
const captureStates = new Map();
const devtoolsSwitchStates = new Map();
// 记录“被判定为隔离保留的意外原生子窗口”的 webContents，供 DevTools 开关事件识别基线。
const isolatedChildContents = new WeakSet();
// r33：@electron/remote 桥 / desktopCapturer 枚举、渲染层原始 IPC 通道的 per-contents 状态。
const remoteStates = new Map();
const ipcChannelStates = new Map();
// r34：设备授权撤销（hid/serial/bluetooth *-revoked）与跨框架存储/缓存访问观测的
// per-contents 状态，随 contents 销毁丢弃、随主导航重置。
const revokeStates = new Map();
const storageAccessStates = new Map();
// r34：GPU 信息更新 / GPU 进程崩溃是 app 级、与具体标签弱关联的系统事件，用进程级
// 单份状态去重；会话分区加固去重也只需要进程级一份。
const gpuCrashState = gpuAccessGuard.createCrashState();
let gpuInfoLastReport = -1;
const GPU_INFO_REPORT_COOLDOWN_MS = 30 * 1000;
const sessionGuardState = sessionGuard.createSessionGuardState();
// 允许走“原始 ipcRenderer.send”的通道白名单（与 preload.js allowedSendChannels 保持一致）。
// ipcRenderer.invoke 走内部 ipc-message-internal，不在此列；正常渲染层除此之外不应有
// 任何原始 send，出现即意味着 contextIsolation 被绕过或 preload 残缺。
const RAW_IPC_SEND_ALLOWED = new Set([
  'window-control', 'toggle-tabbar-collapse', 'navigate-to-url', 'save-settings',
  'update-theme-color', 'get-settings', 'export-config', 'show-context-menu',
  'show-more-options-menu', 'get-download-info', 'start-download', 'show-save-dialog',
  'get-downloads', 'pause-download', 'resume-download', 'cancel-download',
  'retry-download', 'remove-download', 'open-file', 'open-folder', 'clear-downloads',
  'shelf-show-all', 'close-current-tab', 'find-in-page', 'stop-find',
  'reload-tab-by-id', 'reopen-tab-url', 'reset-trackers', 'report-csp-violation',
]);
// 原始 sendSync 白名单为空：本应用渲染层不使用任何同步 IPC。
const RAW_IPC_SYNC_ALLOWED = new Set();

// getContentsState 读取按需创建的 per-contents 小状态；destroyed 时统一清理。
function getContentsState(map, id, create) {
  let st = map.get(id);
  if (!st) {
    st = create(Date.now());
    map.set(id, st);
  }
  return st;
}
// 本次会话累计拦截数与按域名计数，渲染层用来显示“已拦截 N 个追踪器”。
let blockedTrackerCount = 0;
const blockedTrackerByHost = new Map();

// 常见纯第三方追踪 / 广告网络域名（不含任何会被当主站直接访问的通用服务）。
// 按用途分组，最后合并成集合；只用于“子资源”请求拦截，绝不拦顶层导航。
const TRACKER_DOMAIN_GROUPS = {
  // 大型站点分析 / 统计
  analytics: [
    'google-analytics.com', 'googletagmanager.com', 'googletagservices.com',
    'analytics.google.com', 'stats.g.doubleclick.net', 'ssl.google-analytics.com',
    'www-google-analytics.l.google.com',
    'mixpanel.com', 'api.mixpanel.com', 'static.mixpanel.com',
    'segment.io', 'api.segment.io', 'cdn.segment.com', 'cdn-settings.segment.com',
    'amplitude.com', 'api.amplitude.com', 'cdn.amplitude.com',
    'fullstory.com', 'rs.fullstory.com', 'edge.fullstory.com',
    'hotjar.com', 'static.hotjar.com', 'script.hotjar.com', 'vars.hotjar.com',
    'clarity.ms', 'c.clarity.ms', 'i.clarity.ms',
    'matomo.cloud', 'plausible.io',
    'quantserve.com', 'pixel.quantserve.com', 'quantcount.com',
    'scorecardresearch.com', 'chartbeat.com', 'static.chartbeat.com',
    'newrelic.com', 'bam.nr-data.net', 'nr-data.net',
    'mouseflow.com', 'cdn.mouseflow.com',
    'luckyorange.com', 'd10lpsik1i8c69.cloudfront.net',
    'crazyegg.com', 'tracking.crazyegg.com', 'visualwebsiteoptimizer.com',
    'clicktale.net', 'decibelinsight.net', 'sessioncam.com',
    'logentries.com', 'loggly.com', 'heap.io',
  ],
  // 广告联盟 / 竞价 / 投放
  ads: [
    'doubleclick.net', 'googleadservices.com', 'adservice.google.com',
    'pagead2.googlesyndication.com', 'tpc.googlesyndication.com',
    'googlesyndication.com', 'adsystem.com', 'adnxs.com',
    'casalemedia.com', 'criteo.com', 'criteo.net', 'creativecdn.com',
    'taboola.com', 'trc.taboola.com', 'cdn.taboola.com',
    'outbrain.com', 'widgets.outbrain.com', 'mads.one', 'moatads.com',
    'liverail.com', 'rubiconproject.com', 'openx.net', 'pubmatic.com',
    'yieldmo.com', 'bidr.io', 'adsrvr.org', 'advertising.com',
    'adform.net', 'smartyads.com', '3lift.com', 'sharethrough.com',
    'appnexus.com', 'rfihub.com', 'krxd.net', 'bluekai.com',
    'demdex.net', 'everesttech.net', 'rlcdn.com', 'tapad.com',
    'addthis.com', 's7.addthis.com', 'zedo.com', 'adcolony.com',
    'appsflyer.com', 't.appsflyer.com', 'adjust.com', 'branch.io',
    'kochava.com', 'singular.net', 'tenjin.com',
  ],
  // 社交像素 / 跨站身份
  social: [
    'connect.facebook.net', 'pixel.facebook.com', 'graph.facebook.com',
    'an.facebook.com', 'staticxx.facebook.com', 'syndication.twitter.com',
    'platform.twitter.com', 'analytics.twitter.com',
    'tr.snapchat.com', 'sc-static.net',
    'ads.pinterest.com', 'ct.pinterest.com',
    'snap.licdn.com', 'platform.linkedin.com', 'px.ads.linkedin.com',
    'ads.linkedin.com', 'bat.bing.com', 'ads.youtube.com',
    'ads-api.tiktok.com', 'analytics.tiktok.com', 'pixel.tiktok.com',
  ],
  // 营销 / CRM / 邮件转化跟踪
  marketing: [
    'list-manage.com', 'mc.us18.list-manage.com',
    'hubspot.com', 'js.hs-scripts.com', 'js.hs-analytics.net',
    'js.hsadspixel.net', 'js.hs-banner.com',
    'intercom.io', 'js.intercomcdn.com', 'widget.intercom.io',
    'drift.com', 'js.driftt.com',
    'olark.com', 'static.olark.com', 'salesforceliveagent.com',
    'marketo.com', 'mktoresp.com', 'engage.marketo.com',
    'pardot.com', 'pi.pardot.com', 'convertkit.com', 'kajabi.com',
  ],
  // 隐私指纹 / 设备识别 / 遥测
  fingerprint: [
    'fingerprint.com', 'api.fpjs.sh', 'fpcdn.io', 'fpjs.sh',
    'iovation.com', 'mpsnare.iesnare.com', 'first-party.iovation.com',
    'threatmetrix.com', 'h-sdk.online-metrix.net', 'online-metrix.net',
    'deviceidentify.com', 'deepintent.com', 'drawbrid.ge',
    'mediavoice.com', 'bidtheatre.com', 'streampixel.io',
    'bouncex.net', 'cdn.bouncex.net', 'addroplet.com',
  ],
};

// 合并各分组，得到最终拦截集合（名单去重）。
const TRACKER_HOSTS = new Set(Object.values(TRACKER_DOMAIN_GROUPS).flat());

// hostMatchesTracker 判断主机是否为已知追踪域（精确或其子域）。
function hostMatchesTracker(hostname) {
  let h = String(hostname || '').toLowerCase().replace(/\.$/, '');
  if (!h) return false;
  if (TRACKER_HOSTS.has(h)) return true;
  for (const t of TRACKER_HOSTS) {
    if (h.endsWith('.' + t)) return true;
  }
  return false;
}

// isTrackerRequest 只拦子资源，顶层框架 / iframe 框架文档一律放行，避免误伤导航。
function isTrackerRequest(details) {
  if (!blockTrackers) return false;
  const rt = details.resourceType;
  if (rt === 'mainFrame' || rt === 'subFrame') return false;
  let host = '';
  try { host = new URL(details.url).hostname; } catch { return false; }
  return hostMatchesTracker(host);
}

function recordBlockedTracker(url) {
  blockedTrackerCount += 1;
  let host = '';
  try { host = new URL(url).hostname; } catch { host = '(unknown)'; }
  blockedTrackerByHost.set(host, (blockedTrackerByHost.get(host) || 0) + 1);
  sendToRenderer('trackers-blocked', {
    count: blockedTrackerCount,
    host,
    top: topBlockedHosts(),
  });
}

function topBlockedHosts() {
  return [...blockedTrackerByHost.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([host, n]) => ({ host, n }));
}

// ===== 导航 URL 追踪参数剥离（privacy hygiene）=====
// stripTrackingParams：地址栏直接打开 / 跳转的顶层页面，去掉 utm_*、fbclid、gclid 等
// 只用于归因、对页面内容无意义的查询参数。只作用于 http(s) 顶层导航，绝不碰 POST、
// fragment（# 后可能是前端路由）或子资源，避免破坏登录回调与应用状态。
let stripTrackingParams = true;

// 完整匹配的追踪参数名（小写）。
const TRACKING_QUERY_KEYS = new Set([
  'fbclid', 'gclid', 'gbraid', 'wbraid', 'dclid', 'gclsrc', 'msclkid',
  'yclid', 'mc_cid', 'mc_eid', 'igshid', 'ttclid', 'twclid', 'li_fat_id',
  'vero_id', 'wickedid', 'hsCtaTracking', '_hsenc', '_hsmi', 'mkt_tok',
  'oly_anon_id', 'oly_enc_id', 'vero_conv', 'soc_src', 'soc_trk',
  'spm', 'scm', 'sourceFrom', 'fromSource',
]);
// 按前缀匹配的追踪参数名（小写），覆盖 utm_source / utm_medium / utm_campaign 等整族。
const TRACKING_QUERY_PREFIXES = ['utm_', 'pk_', 'piwik_', 'matomo_', 'ga_', 'oasid_'];

function isTrackingQueryKey(rawKey) {
  const key = String(rawKey || '').toLowerCase();
  if (!key) return false;
  if (TRACKING_QUERY_KEYS.has(key)) return true;
  return TRACKING_QUERY_PREFIXES.some(p => key.startsWith(p));
}

// 返回剥离追踪参数后的 URL；没有可删参数时返回 null（调用方据此避免无谓重定向）。
function stripTrackingFromUrl(rawUrl) {
  if (!stripTrackingParams) return null;
  if (!(rawUrl.startsWith('http://') || rawUrl.startsWith('https://'))) return null;
  let u;
  try { u = new URL(rawUrl); } catch { return null; }
  if (!u.search) return null;
  const params = u.searchParams;
  let removed = false;
  // 先收集再删，避免边遍历边改。
  const keys = [];
  for (const key of params.keys()) keys.push(key);
  for (const key of keys) {
    if (isTrackingQueryKey(key)) { params.delete(key); removed = true; }
  }
  if (!removed) return null;
  const query = u.searchParams.toString();
  const rebuilt = u.origin + u.pathname + (query ? '?' + query : '') + u.hash;
  return rebuilt === rawUrl ? null : rebuilt;
}

// ===== 同形异义（homograph / IDN）反钓鱼提示 =====
// 只“提示”不拦截：对包含非 ASCII（含西里尔/希腊等与拉丁形近的字符）或易混拉丁字符、
// 且非用户常用站点的主机，发横幅让用户留意，地址栏仍照常显示，避免误伤合法国际化域名。
const SKEW_LATIN_HOSTS = new Set([
  'google', 'youtube', 'facebook', 'amazon', 'apple', 'microsoft', 'github',
  'twitter', 'x', 'instagram', 'netflix', 'paypal', 'alibaba', 'taobao',
  'baidu', 'bing', 'office', 'live', 'steam', 'epicgames',
]);

// 主机里只要出现这些码位就视为“可能在冒充拉丁字母”。
function hostnameHasSuspiciousChars(hostname) {
  // 非 ASCII：IDN（punycode 解码后的 unicode 主机），本身不是错，但组合常见品牌词要提醒。
  // eslint-disable-next-line no-control-regex
  if (/[^\x00-\x7F]/.test(hostname)) return 'nonascii';
  // 纯拉丁里的易混对：数字/特殊形替字母（如 0 替 o、1 替 l、rn 替 m 由调用方另判）。
  if (/\d/.test(hostname)) {
    const label = hostname.split('.')[0].toLowerCase();
    if (SKEW_LATIN_HOSTS.has(label.replace(/[0-9]/g, ''))) return 'digit-lookalike';
  }
  return null;
}

function analyzeHostForSpoof(hostname) {
  if (!hostname) return null;
  const h = hostname.toLowerCase().replace(/\.$/, '');
  const labels = h.split('.');
  const registrable = labels.length >= 2 ? labels[labels.length - 2] : labels[0];
  // 含非 ASCII，且品牌主体与已知拉丁品牌高度重合（去掉非拉丁后等于某品牌）→ 高危提示。
  // eslint-disable-next-line no-control-regex
  if (/[^\x00-\x7F]/.test(registrable)) {
    const asciiOnly = registrable.replace(/[^\x21-\x7e]/g, '');
    // 混合脚本：同一主体里既有拉丁又有非拉丁，是 homograph 攻击最典型特征。
    // eslint-disable-next-line no-control-regex
    const hasLatin = /[a-z]/.test(registrable);
    const hasNonLatin = /[^\x00-\x7fa-z0-9.-]/.test(registrable);
    if (hasLatin && hasNonLatin) {
      return { reason: 'mixed-script', hostname: h, hint: asciiOnly };
    }
  }
  const suspicious = hostnameHasSuspiciousChars(h);
  if (suspicious === 'digit-lookalike') {
    return { reason: 'digit-lookalike', hostname: h, hint: registrable };
  }
  return null;
}

// ===== Referrer 收敛（默认 strict-origin-when-cross-origin 语义）=====
// 网页自己的 <meta name=referrer> / 页面策略由 Chromium 处理；这里兜底修正 Electron
// 可能仍带“完整来路 URL（含查询/路径）”的情况，避免把上个页面的敏感路径、搜索词、
// token 经 Referer 头泄露给第三方：
//   - 同源：保留完整 Referer；
//   - 跨源且安全等级不降低：收敛为源（origin/）；
//   - https → http 降级：直接去除 Referer。
function originOf(u) {
  try { return new URL(u).origin; } catch { return null; }
}

function trimReferrerHeader(details, headers) {
  const referrer = headers['Referer'] || headers['referer'];
  if (!referrer) return;
  const fromOrigin = originOf(referrer);
  const toOrigin = originOf(details.url);
  if (!fromOrigin || !toOrigin) return;
  if (fromOrigin === toOrigin) return; // 同源不裁剪
  const fromHttps = referrer.startsWith('https://');
  const toHttp = details.url.startsWith('http://');
  if (fromHttps && toHttp) {
    delete headers['Referer'];
    delete headers['referer'];
    return;
  }
  // 跨源：只暴露源，不暴露路径与查询串。
  const trimmed = fromOrigin === 'null' ? '' : fromOrigin + '/';
  headers['Referer'] = trimmed;
  delete headers['referer'];
}

// clearOnExit：退出时自动清空缓存 / Cookie / 站点存储 / 历史 / 下载记录（隐私模式）。
// confirmCloseMultiple：仍有多个标签页时点 × 先二次确认，防止误关整窗。
let clearOnExit = false;
let confirmCloseMultiple = false;

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:', 'file:', 'cosy:']);
const MAX_HISTORY_ENTRIES = 1000;
const DEFAULT_WINDOW_WIDTH = 1200;
const DEFAULT_WINDOW_HEIGHT = 800;
const MIN_WINDOW_WIDTH = 800;
const MIN_WINDOW_HEIGHT = 600;
const DEFAULT_TAB_BAR_HEIGHT_HORIZONTAL = 116;
const DEFAULT_TAB_BAR_WIDTH_VERTICAL = 200;
const COLLAPSED_TAB_BAR_WIDTH = 50;
// 拼写检查：Chromium 内置 Hunspell 词典，全程本地完成，不发送任何输入内容。
// DEFAULT 是历史行为（英中双语）；ALLOWED 是设置页允许勾选的语言白名单，
// 主进程会再次用 session.availableSpellCheckerLanguages 过滤，系统没装词典的
// 语言直接跳过，避免 setSpellCheckerLanguages 抛错导致整个初始化中断。
const DEFAULT_SPELLCHECK_LANGUAGES = ['en-US', 'zh-CN'];
const ALLOWED_SPELLCHECK_LANGUAGES = [
  'en-US', 'en-GB', 'en-AU', 'zh-CN', 'zh-TW', 'ja',
  'fr-FR', 'de-DE', 'es-ES', 'ru-RU', 'ko', 'pt-BR', 'it-IT'
];
const MAX_SPELLCHECK_LANGUAGES = 5;
let spellcheckEnabled = true;
let spellcheckLanguages = DEFAULT_SPELLCHECK_LANGUAGES.slice();

// sanitizeSpellcheckLanguages 归一化语言数组：去重、限数量、白名单校验。
// 空数组 / 非数组一律回退默认，保证拼写检查不会因为设置文件损坏而彻底失效。
function sanitizeSpellcheckLanguages(raw) {
  if (!Array.isArray(raw)) return DEFAULT_SPELLCHECK_LANGUAGES.slice();
  const out = [];
  for (const lang of raw) {
    if (typeof lang !== 'string' || !ALLOWED_SPELLCHECK_LANGUAGES.includes(lang)) continue;
    if (!out.includes(lang)) out.push(lang);
    if (out.length >= MAX_SPELLCHECK_LANGUAGES) break;
  }
  return out.length ? out : DEFAULT_SPELLCHECK_LANGUAGES.slice();
}

// applySpellcheckSettings 把当前拼写检查开关 / 语言应用到默认会话。
// 每次保存设置都会重新调用；语言列表只保留当前平台真正可用的词典。
function applySpellcheckSettings() {
  try {
    const ses = session.defaultSession;
    ses.setSpellCheckerEnabled(spellcheckEnabled);
    if (!spellcheckEnabled) return;
    const available = new Set(ses.availableSpellCheckerLanguages || []);
    let langs = spellcheckLanguages.filter(l => available.has(l));
    if (!langs.length) {
      langs = DEFAULT_SPELLCHECK_LANGUAGES.filter(l => available.has(l));
    }
    if (langs.length) ses.setSpellCheckerLanguages(langs);
  } catch (e) {
    console.error('应用拼写检查设置失败:', e);
  }
}

// readPersistedSettings 在 app 启动早期同步读取已保存的设置，
// 让拼写检查这类需要在第一个页面加载前生效的偏好不必等渲染层来取。
function readPersistedSettings() {
  try {
    const p = path.join(app.getPath('userData'), 'cosySettings.json');
    if (fsSync.existsSync(p)) return JSON.parse(fsSync.readFileSync(p, 'utf-8')) || {};
  } catch (e) {
    console.error('启动时读取设置失败:', e);
  }
  return {};
}

const isDev = !app.isPackaged;

function isMainSender(event) {
  return event.sender === mainWindow?.webContents;
}

// 判断一个 file: 帧是否为“应用自带的内置静态页”（如 tab 视图加载的 src/error.html、
// src/download/index.html）。这些页物理上位于安装目录 __dirname 内；用户在标签里
// 打开的任意本地 html（D:\xxx.html）在目录外，必须按不可信帧处理。
function isInternalFileFrame(frameUrl) {
  if (typeof frameUrl !== 'string' || !frameUrl.startsWith('file:')) return false;
  let filePath;
  try {
    filePath = require('url').fileURLToPath(frameUrl);
  } catch {
    return false;
  }
  return winPolicy.isInsideRoot(filePath, __dirname);
}

// 入站 IPC 统一来源守卫：默认只放行主窗口外壳（file: 的 index.html）与 cosy: 内置
// 帧；远程网页、data/blob/about、以及用户在标签里打开的本地 html（local-file）一律
// 不进入任何业务 handler。这是 preload 降级之外的主进程第二道边界，一次性收掉过去
// “每个 handler 手写 isMainSender”的遗漏——历史上 approve/list/remove/clear-cert
// -exceptions 五个证书通道就完全没校验，任意被浏览网页都能放行 TLS 例外。
// report-csp-violation 允许任意帧投递，但其 handler 内部仍按帧来源自验并丢弃远程上报。
const ipcDenyCounter = ipcGuard.createRateCounter();
ipcGuard.installIpcGuard(ipcMain, {
  isShellSender: isMainSender,
  isInternalFileFrame,
  frameAllows: (kind, channel) => channelPolicy.frameAllows(kind, channel),
  allowAnyFrame: new Set(['report-csp-violation']),
  onReject: ({ channel, kind, reason }) => {
    try {
      const key = `${channel}|${kind}`;
      // 同一“通道+来源”10 秒内最多记 20 条，防止被浏览网页狂刷特权 IPC 打爆安全台账。
      if (!ipcDenyCounter.admit(key, 10000, 20)) return;
      recordSecurityEvent('ipc-denied', 'warn',
        `拒绝来自 ${kind} 帧的 IPC 调用: ${channel} (${reason})`, '');
    } catch {}
  },
});

function sendToRenderer(channel, ...args) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, ...args);
  }
}

// ===== 底部下载栏（download shelf）=====
// 现代浏览器在窗口底部用一条 shelf 展示下载进度，不必每次下载都新开标签页打断浏览。
// 主进程只推送可序列化的快照给主界面；DownloadItem 等 Electron 对象绝不跨进程暴露。
const MAX_SHELF_ITEMS = 3;

function shelfSnapshot() {
  const items = [];
  for (let i = downloads.length - 1; i >= 0 && items.length < MAX_SHELF_ITEMS; i--) {
    const d = downloads[i];
    items.push({
      id: d.id,
      filename: d.filename,
      url: d.url,
      totalBytes: d.totalBytes || 0,
      receivedBytes: d.receivedBytes || 0,
      progress: Number(d.progress) || 0,
      speed: d.speed || '0 B/s',
      status: d.status || 'pending',
      savePath: d.savePath || null,
    });
  }
  return items;
}

function sendShelf() {
  sendToRenderer('download-shelf', shelfSnapshot());
}

function getSafeDirs() {
  return [
    app.getPath('downloads'), app.getPath('documents'),
    app.getPath('desktop'), app.getPath('pictures'),
    app.getPath('videos'), app.getPath('music'), __dirname,
  ];
}

function isInSafeDirs(filePath) {
  return getSafeDirs().some(dir => isPathInDir(filePath, dir));
}

class Tab {
  constructor(id, url = 'cosy://newtab') {
    this.id = id;
    this.url = url;
    this.title = '新标签页';
    this.favicon = null;
    this.view = null;
    this.isLoading = false;
    this.retry403 = false;
    this.bookmarked = false;
    this.canGoBack = false;
    this.canGoForward = false;
    this.audible = false;
    this.muted = false;
    // 内存节省（Memory Saver）相关状态：
    // lastActiveAt 记录最近一次成为活动标签的时间；discarded 表示其渲染进程
    // 已被回收，切回时需要按 tab.url 重新加载。
    this.lastActiveAt = Date.now();
    this.discarded = false;
  }
}

function getHttpStatusCode(errorCode) {
  const errorMap = {
    '-105': '404', '-106': '400', '-102': '404', '-109': '404',
    '-118': '404', '-324': '500', '-501': '501', '-6': '404', '-3': '403'
  };
  return errorMap[errorCode.toString()] || '500';
}

function getErrorMessage(errorCode) {
  const messageMap = {
    '-105': '无法找到服务器', '-106': '网络连接已断开', '-102': '连接被拒绝',
    '-109': '地址无法访问', '-118': '连接超时', '-324': '服务器返回空响应',
    '-501': '不安全的响应', '-6': '文件未找到', '-3': '访问被拒绝'
  };
  return messageMap[errorCode.toString()] || '发生未知错误';
}

function getBrowserErrorText(errorCode) {
  const errorTextMap = {
    '-105': 'ERR_NAME_NOT_RESOLVED', '-106': 'ERR_INTERNET_DISCONNECTED',
    '-102': 'ERR_CONNECTION_REFUSED', '-109': 'ERR_ADDRESS_UNREACHABLE',
    '-118': 'ERR_CONNECTION_TIMED_OUT', '-324': 'ERR_EMPTY_RESPONSE',
    '-501': 'ERR_INSECURE_RESPONSE', '-6': 'ERR_FILE_NOT_FOUND', '-3': 'ERR_ACCESS_DENIED'
  };
  return errorTextMap[errorCode.toString()] || 'UNKNOWN_ERROR';
}

function isSafeUrl(url) {
  try {
    const parsed = new URL(url);
    return ALLOWED_PROTOCOLS.has(parsed.protocol);
  } catch {
    return false;
  }
}

function sanitizePath(inputPath, baseDir) {
  const resolved = path.resolve(baseDir, inputPath);
  const normalized = path.normalize(resolved);
  if (!isPathInDir(normalized, baseDir)) return null;
  return normalized;
}

function isPathInDir(filePath, dir) {
  return filePath === dir || filePath.startsWith(dir + path.sep);
}

function isValidColor(str) {
  return typeof str === 'string' && /^#[0-9a-fA-F]{3,8}$/.test(str);
}

function getCurrentTabWebContents() {
  const tab = tabs[currentTabIndex];
  return tab?.view?.webContents || null;
}

function zoomIn() {
  adjustCurrentZoom({ delta: 'in' });
}

function zoomOut() {
  adjustCurrentZoom({ delta: 'out' });
}

function resetZoom() {
  adjustCurrentZoom({ factor: 1 });
}

function toggleDevTools() {
  const wc = getCurrentTabWebContents();
  if (wc) wc.toggleDevTools();
}

function goHome() {
  const tab = tabs[currentTabIndex];
  if (tab) {
    tab.url = 'cosy://newtab';
    loadTabContent(tab);
    sendToRenderer('tab-updated', { id: tab.id, url: tab.url, title: '新标签页' });
  }
}

async function showOpenFileDialog() {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: '打开文件',
    properties: ['openFile'],
    filters: [
      { name: '网页文件', extensions: ['html', 'htm'] },
      { name: '所有文件', extensions: ['*'] }
    ]
  });
  if (!result.canceled && result.filePaths.length > 0) {
    createNewTab(`file://${result.filePaths[0]}`);
  }
}

function addToHistory(url, title) {
  // r34：历史写入统一走 historyguard 内核——只记录 http/https 导航，title 去控制
  // 字符 / 压空白 / 截断上界，URL 长度有界，同 URL 合并窗内只刷新时间戳（抑制刷新
  // 抖动与写放大）。内核用传入的 {items: history} 直接在历史数组上原地改写。
  const verdict = historyGuard.decideHistoryWrite(
    { items: history }, { url, title }, Date.now());
  if (verdict.decision === historyGuard.DECISION_SKIP) return;
  // 应用侧维持比内核安全上限（5000）更紧的展示上界 1000，超出淘汰最旧。
  if (history.length > MAX_HISTORY_ENTRIES) history = history.slice(0, MAX_HISTORY_ENTRIES);
  saveHistory();
}

function saveHistory() {
  const historyPath = path.join(app.getPath('userData'), 'history.json');
  try {
    fsSync.writeFileSync(historyPath, JSON.stringify(history, null, 2), 'utf-8');
  } catch (e) {
    console.error('保存历史记录失败:', e);
  }
}

function loadHistory() {
  const historyPath = path.join(app.getPath('userData'), 'history.json');
  try {
    if (!fsSync.existsSync(historyPath)) return;
    // history.json 是本地文件、也可能被外部程序 / 旧版本写坏：解析结果必须是数组，
    // 且每条都重新过内核净化（非 http/https、无法解析、标题含控制字符的一律丢弃 /
    // 清洗），时间戳必须为有限非负数，否则该条丢弃。绝不信任磁盘上的结构。
    let parsed;
    try {
      parsed = JSON.parse(fsSync.readFileSync(historyPath, 'utf-8'));
    } catch {
      history = [];
      return;
    }
    if (!Array.isArray(parsed)) {
      history = [];
      return;
    }
    const clean = [];
    for (const item of parsed) {
      if (!item || typeof item !== 'object') continue;
      const su = historyGuard.sanitizeHistoryUrl(item.url);
      if (!su.ok) continue;
      if (typeof item.timestamp !== 'number' || !Number.isFinite(item.timestamp)
          || item.timestamp < 0) continue;
      clean.push({
        url: su.url,
        title: historyGuard.sanitizeHistoryTitle(item.title),
        timestamp: item.timestamp,
      });
      if (clean.length >= MAX_HISTORY_ENTRIES) break;
    }
    history = clean;
  } catch (e) {
    console.error('读取历史记录失败:', e);
  }
}

function saveBookmarks() {
  const bookmarksPath = path.join(app.getPath('userData'), 'bookmarks.json');
  try {
    // r35：写盘前统一过 bookmarkguard——只落 http/https、title 去控制字符并限长、
    // 按 url 去重并收敛到硬上界。无论书签来自批量收藏 / 单条新增 / 导入，都在此收口，
    // 避免不可信标题或海量条目污染 bookmarks.json。
    const cleaned = bookmarkGuard.sanitizeBookmarkList(bookmarks, Date.now());
    bookmarks = cleaned.items;
    fsSync.writeFileSync(bookmarksPath, JSON.stringify(bookmarks, null, 2), 'utf-8');
  } catch (e) {
    console.error('保存书签失败:', e);
  }
}

function loadBookmarks() {
  const bookmarksPath = path.join(app.getPath('userData'), 'bookmarks.json');
  try {
    if (fsSync.existsSync(bookmarksPath)) {
      // bookmarks.json 不是信任边界（可被手改 / 同步盘 / 恶意进程替换 / 崩溃截断）：
      // 非数组视为空，逐条做对象 / 字段 / scheme 校验，脏项丢弃，绝不把脏结构送进 UI。
      const parsed = JSON.parse(fsSync.readFileSync(bookmarksPath, 'utf-8'));
      bookmarks = bookmarkGuard.sanitizeBookmarkList(parsed, Date.now()).items;
    }
  } catch (e) {
    console.error('读取书签失败:', e);
  }
}

function saveSession() {
  try {
    const sessionPath = path.join(app.getPath('userData'), 'session.json');
    // r35：会话条目先映射成 {url,title}，再交给 restoreguard 统一净化（仅 http/https、
    // title 去控制字符并限长）并截断到恢复上界，替代旧实现“只过滤 url、title 原样写”。
    const raw = tabs
      .filter(tab => !String(tab.url || '').startsWith('cosy://'))
      .map(tab => ({ url: tab.url, title: tab.title }));
    const sessionTabs = restoreGuard.sanitizeSessionList(raw).tabs;
    fsSync.writeFileSync(sessionPath, JSON.stringify(sessionTabs, null, 2), 'utf-8');
  } catch (e) {
    console.error('保存会话失败:', e);
  }
}

function loadSession() {
  try {
    const sessionPath = path.join(app.getPath('userData'), 'session.json');
    if (fsSync.existsSync(sessionPath)) {
      const parsed = JSON.parse(fsSync.readFileSync(sessionPath, 'utf-8'));
      // 逐条做对象 / url / title 校验：旧实现只判 Array.isArray 就 filter(isSafeUrl)，
      // null / 数字 / 嵌套数组会让恢复时访问 tab.title 抛异常并阻断全部标签恢复。
      const { tabs: restored } = restoreGuard.sanitizeSessionList(parsed);
      if (restored.length > 0) return restored;
    }
  } catch (e) {
    console.error('读取会话失败:', e);
  }
  return null;
}

function clearSession() {
  try {
    const sessionPath = path.join(app.getPath('userData'), 'session.json');
    if (fsSync.existsSync(sessionPath)) fsSync.unlinkSync(sessionPath);
  } catch (e) {
    console.error('清除会话失败:', e);
  }
}

function addToRecentlyClosed(tab) {
  if (!tab || !tab.url || String(tab.url).startsWith('cosy://')) return;
  // r35：入栈条目走 restoreguard——仅 http/https、title 去控制字符、closedAt 必须
  // 是有限毫秒时间戳，超深由内核淘汰最旧，替代旧实现对远端 title 的裸 push。
  const state = restoreGuard.createRecentlyClosedState(recentlyClosedTabs);
  const r = restoreGuard.pushRecentlyClosed(state, {
    url: tab.url, title: tab.title, closedAt: Date.now(),
  }, Date.now());
  if (r.status === 'pushed') recentlyClosedTabs = state.items;
}

function getLastClosedTab() {
  // 条目在 addToRecentlyClosed 入栈时已逐条净化，这里维持原“弹出栈顶”语义。
  if (recentlyClosedTabs.length === 0) return null;
  return recentlyClosedTabs.pop();
}

function isLocalhost(url) {
  try {
    const host = new URL(url).hostname;
    return host === 'localhost' || host === '127.0.0.1' || host === '::1';
  } catch { return false; }
}

function isPrivateNetworkHost(url) {
  try {
    const host = new URL(url).hostname.replace(/^\[|\]$/g, '');
    if (host === 'localhost' || host === '::1' || host.endsWith('.localhost')) return true;
    if (host === '::ffff:127.0.0.1') return true;
    const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (m) {
      const a = +m[1], b = +m[2];
      if (a === 127 || a === 10) return true;
      if (a === 172 && b >= 16 && b <= 31) return true;
      if (a === 192 && b === 168) return true;
      if (a === 169 && b === 254) return true;
      return false;
    }
    return false;
  } catch { return false; }
}

// readStoredSettings 只读不校验，启动时用来还原 darkMode / httpsOnly 等运行时状态。
// 校验交给 save-settings 里的 sanitizeSettings。
function readStoredSettings() {
  try {
    const p = path.join(app.getPath('userData'), 'cosySettings.json');
    if (fsSync.existsSync(p)) return JSON.parse(fsSync.readFileSync(p, 'utf-8'));
  } catch (e) { console.error('读取设置失败:', e); }
  return {};
}

// applyDarkMode 切 Chromium 原生暗色主题，影响滚动条、文件对话框、DevTools 外壳。
// renderer 的 CSS 暗色由 settings-loaded 自己管，这里只管原生 UI。
function applyDarkMode(dark) {
  nativeTheme.themeSource = dark ? 'dark' : 'light';
  sendToRenderer('native-theme-changed', { dark: !!dark });
}

// ===== Set-Cookie 加固台账（cookie-hardening.json / cosy://security 面板）=====
// 纯判定在 cookieguard.js；这里负责在 onHeadersReceived 里应用改写、聚合落盘，
// 并把“被剥离的 Cookie”登记到安全事件。SameSite 补全这类静默改写只进台账、
// 不刷安全事件列表，避免正常网站产生大量噪音。
const cookieLedgerStorePath = path.join(app.getPath('userData'), 'cookie-hardening.json');
const MAX_COOKIE_LEDGER = 500;
const cookieLedger = cookieGuard.createCookieLedger(MAX_COOKIE_LEDGER);
let cookieLedgerLoaded = false;
let cookieLedgerSaveTimer = null;

function loadCookieLedger() {
  if (cookieLedgerLoaded) return;
  cookieLedgerLoaded = true;
  try {
    const data = JSON.parse(fsSync.readFileSync(cookieLedgerStorePath, 'utf8'));
    cookieLedger.load(data);
  } catch {}
}

function persistCookieLedger() {
  if (cookieLedgerSaveTimer) clearTimeout(cookieLedgerSaveTimer);
  cookieLedgerSaveTimer = setTimeout(() => {
    try {
      const tmp = cookieLedgerStorePath + '.tmp';
      fsSync.writeFileSync(tmp, JSON.stringify(cookieLedger.toJSON()), 'utf8');
      fsSync.renameSync(tmp, cookieLedgerStorePath);
    } catch {}
  }, 300);
}

// ===== PNA 私有网络访问拦截台账（pna-access.json / cosy://security 面板）=====
const pnaLedgerStorePath = path.join(app.getPath('userData'), 'pna-access.json');
const MAX_PNA_LEDGER = 300;
const pnaLedger = new Map(); // host -> { host, space, hits, lastTime, types:Set-as-map }
let pnaLedgerLoaded = false;
let pnaLedgerSaveTimer = null;

function loadPnaLedger() {
  if (pnaLedgerLoaded) return;
  pnaLedgerLoaded = true;
  try {
    const data = JSON.parse(fsSync.readFileSync(pnaLedgerStorePath, 'utf8'));
    const rows = Array.isArray(data && data.rows) ? data.rows : [];
    for (const r of rows) {
      if (!r || typeof r.host !== 'string') continue;
      pnaLedger.set(r.host, {
        host: String(r.host).slice(0, 255),
        space: String(r.space || 'private').slice(0, 32),
        hits: Number(r.hits) || 1,
        lastTime: Number(r.lastTime) || Date.now(),
      });
    }
  } catch {}
}

function persistPnaLedger() {
  if (pnaLedgerSaveTimer) clearTimeout(pnaLedgerSaveTimer);
  pnaLedgerSaveTimer = setTimeout(() => {
    try {
      const rows = [...pnaLedger.values()];
      const tmp = pnaLedgerStorePath + '.tmp';
      fsSync.writeFileSync(tmp, JSON.stringify({ version: 1, rows }), 'utf8');
      fsSync.renameSync(tmp, pnaLedgerStorePath);
    } catch {}
  }, 400);
}

function pnaLedgerStats() {
  let blocked = 0;
  for (const v of pnaLedger.values()) blocked += v.hits;
  return { hosts: pnaLedger.size, blocked };
}

function recordPnaBlock(details, verdict) {
  loadPnaLedger();
  const host = String(verdict.targetHost || '').slice(0, 255);
  if (!host) return;
  const cur = pnaLedger.get(host) || { host, space: verdict.targetSpace || 'private', hits: 0, lastTime: 0 };
  cur.hits += 1;
  cur.lastTime = Date.now();
  cur.space = verdict.targetSpace || cur.space;
  pnaLedger.set(host, cur);
  if (pnaLedger.size > MAX_PNA_LEDGER) {
    const oldest = [...pnaLedger.entries()]
      .sort((a, b) => a[1].lastTime - b[1].lastTime)[0][0];
    pnaLedger.delete(oldest);
  }
  persistPnaLedger();
  sendToRenderer('pna-blocked-updated', pnaLedgerStats());
}

// ===== 指纹 / 跨站追踪收敛台账（fp-leaks.json / cosy://security 面板）=====
const fpLedgerStorePath = path.join(app.getPath('userData'), 'fp-leaks.json');
const MAX_FP_LEDGER = 500;
const fpLedger = fpGuard.createFingerprintLedger(MAX_FP_LEDGER);
let fpLedgerLoaded = false;
let fpLedgerSaveTimer = null;

function loadFpLedger() {
  if (fpLedgerLoaded) return;
  fpLedgerLoaded = true;
  try {
    fpLedger.load(JSON.parse(fsSync.readFileSync(fpLedgerStorePath, 'utf8')));
  } catch {}
}

function persistFpLedger() {
  if (fpLedgerSaveTimer) clearTimeout(fpLedgerSaveTimer);
  fpLedgerSaveTimer = setTimeout(() => {
    try {
      const tmp = fpLedgerStorePath + '.tmp';
      fsSync.writeFileSync(tmp, JSON.stringify(fpLedger.toJSON()), 'utf8');
      fsSync.renameSync(tmp, fpLedgerStorePath);
    } catch {}
  }, 400);
}

// recordFpHit 按主机+类别登记一条被收敛的指纹/追踪信号。
function recordFpHit(host, category, signals) {
  if (!host) return;
  loadFpLedger();
  fpLedger.record(host, category, signals);
  persistFpLedger();
  sendToRenderer('fingerprint-blocked-updated', fpLedger.stats());
}

// applyCookieHardening 就地加固响应头里的 Set-Cookie，返回本次动作列表。
// 任何异常都不阻断浏览：出错时保留原始响应头。
function applyCookieHardening(headers, details) {
  try {
    const setCookieKey = Object.prototype.hasOwnProperty.call(headers, 'set-cookie')
      ? 'set-cookie'
      : (Object.prototype.hasOwnProperty.call(headers, 'Set-Cookie') ? 'Set-Cookie' : '');
    if (!setCookieKey) return [];
    const original = cookieGuard.extractSetCookieHeaders(headers);
    if (!original.length) return [];

    const result = cookieGuard.hardenSetCookieHeader(original, details, {
      blockThirdParty: blockThirdPartyCookies,
      hardenSameSite: hardenCookies,
    });
    headers[setCookieKey] = result.lines;
    if (!result.actions.length) return [];

    loadCookieLedger();
    cookieLedger.addMany(result.actions);
    persistCookieLedger();
    for (const a of result.actions) {
      // SameSite 补全是静默改写，只进台账不刷安全事件；剥离类才登记事件。
      if (a.action === 'samesite-default-lax') continue;
      recordSecurityEvent('cookie-blocked', 'warn',
        `已剥离不安全的 Cookie「${a.name}」（${a.reason}）`, a.host);
    }
    sendToRenderer('cookie-hardening-updated', cookieLedger.stats());
    return result.actions;
  } catch {
    return [];
  }
}

function applyWebRtcPolicy() {
  // WebRTC ICE 候选默认可能暴露内网/真实公网 IP（可穿透 VPN）。
  // strict 只用默认公网接口；balanced 允许 mDNS 混淆候选；legacy 不干预。
  try {
    session.defaultSession.setWebRTCIPHandlingPolicy(fpGuard.resolveWebRtcPolicy(webrtcMode));
  } catch {}
}

// ===== 安全 DNS（DoH）状态与落盘 =====
const dohStorePath = path.join(app.getPath('userData'), 'doh-status.json');
const dohLedger = dohGuard.createDohLedger(200);
let dohLedgerLoaded = false;
let dohSaveTimer = null;

function loadDohLedger() {
  if (dohLedgerLoaded) return;
  dohLedgerLoaded = true;
  try {
    dohLedger.load(JSON.parse(fsSync.readFileSync(dohStorePath, 'utf8')));
  } catch {}
}

function persistDohLedger() {
  if (dohSaveTimer) clearTimeout(dohSaveTimer);
  dohSaveTimer = setTimeout(() => {
    try {
      const tmp = dohStorePath + '.tmp';
      fsSync.writeFileSync(tmp, JSON.stringify(dohLedger.toJSON()), 'utf8');
      fsSync.renameSync(tmp, dohStorePath);
    } catch {}
  }, 400);
}

function dohStatus() {
  return {
    mode: dohMode,
    provider: dohProvider,
    active: dohActive,
    events: dohLedger.list().slice(0, 50),
  };
}

// applySecureDns 在启动 / 设置变更时把安全 DNS 策略下发给宿主解析器。
// 老版本 Electron 没有 setHostResolverControls 时静默降级为关闭，不阻断浏览。
function applySecureDns() {
  loadDohLedger();
  const resolved = dohGuard.resolveControls({
    mode: dohMode,
    provider: dohProvider,
    customUrl: dohCustomUrl,
  });
  const sess = session.defaultSession;
  if (typeof sess.setHostResolverControls !== 'function') {
    dohActive = false;
    dohLedger.add({ mode: dohMode, event: 'unsupported', detail: 'no setHostResolverControls' });
    persistDohLedger();
    return;
  }
  try {
    sess.setHostResolverControls(resolved.controls);
    dohActive = resolved.mode !== dohGuard.SECURE_DNS_MODES.OFF;
    if (resolved.warning) {
      dohLedger.add({ mode: resolved.mode, event: 'fallback', detail: resolved.warning });
      recordSecurityEvent('fingerprint-blocked', 'warn',
        `安全 DNS 自定义服务器非法（${resolved.warning}），已回退到自动模式`, '');
    } else {
      dohLedger.add({
        mode: resolved.mode,
        event: 'applied',
        detail: resolved.template || resolved.mode,
      });
    }
    persistDohLedger();
  } catch (e) {
    dohActive = false;
    dohLedger.add({ mode: dohMode, event: 'error', detail: String(e && e.message || e).slice(0, 200) });
    persistDohLedger();
  }
}

function setupSecurityHeaders() {
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    const headers = details.responseHeaders || {};
    // 安全头评级必须在下面任何 setIfMissing 之前完成，反映服务器原始姿态；
    // 只评远端顶层文档，不评我们自己强制注入的 cosy:// 页面与第三方子资源。
    if (details.resourceType === 'mainFrame' && /^https?:/i.test(details.url)) {
      recordHeaderGrade(details.url, headers);
    }
    // 移除站点下发的 Accept-CH / Critical-CH：阻止其订阅高熵 Client Hints，
    // Critical-CH 还会触发带新头的重试，一并清掉以掐断放大通道。
    try {
      const removedCh = fpGuard.stripAcceptClientHints(headers, { stripAcceptCh });
      if (removedCh.length) {
        const chHost = fpGuard.hostOf(details.url);
        recordFpHit(chHost, 'accept-ch', removedCh);
      }
    } catch {}
    const setIfMissing = (name, value) => {
      if (!headers[name] && !headers[name.toLowerCase()]) headers[name] = value;
    };
    setIfMissing('X-Content-Type-Options', ['nosniff']);
    setIfMissing('X-Frame-Options', ['SAMEORIGIN']);
    setIfMissing('Referrer-Policy', ['strict-origin-when-cross-origin']);
    // 关闭 FLoC / 广告兴趣组 / Topics / 隐私令牌等追踪特性。
    // 指令由 permpolicy 内核统一构建（强制关闭项不可被放开，白名单防头注入）；
    // 站点未自行下发策略时注入默认值，尊重站点对其它能力的显式配置。
    setIfMissing('Permissions-Policy', [permPolicy.defaultHeader()]);
    const isLocal = details.url.startsWith('cosy://') || details.url.startsWith('file://');
    if (isLocal && !headers['Content-Security-Policy'] && !headers['content-security-policy']) {
      // 自有 UI 页面的 CSP 比公网站点更严：
      //  object-src 'none'      ：彻底禁掉插件 / 嵌入对象（Flash 残留、恶意 <embed>）；
      //  base-uri 'self'       ：页面不允许被 <base> 改掉所有相对 URL 的基准；
      //  form-action 'self'    ：表单不允许提交到外部源（防内部页被注入后外发数据）；
      //  frame-ancestors 'none'：任何页面都不许 iframe 我们的内部 UI（等价 X-Frame-Options DENY）；
      //  worker-src 'self'     ：worker 只能从自身加载，挡 data: blob: worker 注入。
      headers['Content-Security-Policy'] = [
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data: https:; " +
        "connect-src 'self' https:; " +
        "object-src 'none'; " +
        "base-uri 'self'; " +
        "form-action 'self'; " +
        "frame-ancestors 'none'; " +
        "worker-src 'self';"
      ];
    }
    // 本地页面（cosy:// / file://）加 COOP/COEP/CORP，跨源资源进不来，
    // 防止恶意网页把我们的设置页 / 下载页 iframe 化后读内容（Spectre 类侧信道）。
    if (isLocal) {
      headers['Cross-Origin-Opener-Policy'] = ['same-origin'];
      headers['Cross-Origin-Embedder-Policy'] = ['require-corp'];
      headers['Cross-Origin-Resource-Policy'] = ['same-origin'];
    }
    // HTTPS 响应默认补 HSTS，让浏览器后续访问自动升级（1 年 + includeSubDomains）。
    // 已经自带 HSTS 的站点不覆盖。
    if (details.url.startsWith('https://') &&
        !headers['Strict-Transport-Security'] && !headers['strict-transport-security']) {
      headers['Strict-Transport-Security'] = ['max-age=31536000; includeSubDomains'];
    }
    // Cookie 加固放在所有响应头处理之后、回写之前：剥离第三方 / 非法前缀 /
    // http 下 Secure 的 Set-Cookie，并为第一方 Cookie 补 SameSite=Lax。
    // 仅处理 http(s) 响应，内部 cosy:// 页面不种浏览器 Cookie。
    if (/^https?:/i.test(details.url)) {
      applyCookieHardening(headers, details);
    }
    callback({ responseHeaders: headers });
  });

  session.defaultSession.webRequest.onBeforeSendHeaders((details, callback) => {
    const headers = details.requestHeaders;
    headers['DNT'] = '1';
    headers['Sec-GPC'] = '1';
    headers['Upgrade-Insecure-Requests'] = '1';
    trimReferrerHeader(details, headers);
    // 指纹 / 广告信号收敛：剥离高熵 Client Hints 与归因 / Topics 请求头。
    try {
      const fpOptions = {
        reduceClientHints,
        blockAdSignals,
        blockHyperlinkPing,
        stripAcceptCh,
        webrtcMode,
      };
      const removed = fpGuard.sanitizeOutboundHeaders(details, headers, fpOptions);
      const host = fpGuard.hostOf(details.url);
      if (host && removed.clientHints.length) {
        recordFpHit(host, 'client-hints', removed.clientHints);
      }
      if (host && removed.adSignals.length) {
        recordFpHit(host, 'ad-signals', removed.adSignals);
      }
    } catch {}
    callback({ requestHeaders: headers });
  });

  session.defaultSession.webRequest.onBeforeRequest((details, callback) => {
    const isHttpUrl = details.url.startsWith('http://') || details.url.startsWith('https://');
    // 超链接审计打点（<a ping> / sendBeacon 类 ping）：静默取消，顶层导航不受影响。
    if (isHttpUrl) {
      try {
        if (fpGuard.isHyperlinkPing(details, { blockHyperlinkPing })) {
          const host = fpGuard.hostOf(details.url);
          recordFpHit(host, 'ping', ['hyperlink-ping']);
          recordSecurityEvent('fingerprint-blocked', 'info',
            `已阻止超链接打点请求（ping）：${details.url}`, host);
          recordRequestAttempt(details, true);
          return callback({ cancel: true });
        }
      } catch {}
    }
    // 第三方追踪 / 广告子资源：直接取消（不动顶层导航）。
    if (isHttpUrl && isTrackerRequest(details)) {
      recordBlockedTracker(details.url);
      recordRequestAttempt(details, true);
      return callback({ cancel: true });
    }

    // 私有网络访问（PNA）：公网页面不得借浏览器打本机 / 内网 / 云元数据。
    if (isHttpUrl) {
      try {
        const verdict = pnaGuard.evaluatePnaRequest(details, {
          enabled: blockLocalNetworkAccess,
        });
        if (verdict.block) {
          recordPnaBlock(details, verdict);
          recordSecurityEvent('pna-blocked', 'warn',
            `已阻止公网页面访问${verdict.targetSpace === 'loopback' ? '本机' :
              verdict.targetSpace === 'link-local' ? '链路本地/元数据' : '内网'}地址：${details.url}`,
            verdict.targetHost || '');
          recordRequestAttempt(details, true);
          return callback({ cancel: true });
        }
      } catch { /* 判定异常不干预浏览 */ }
    }

    // 混合内容：HTTPS 页面却去加载 HTTP 子资源，会把整页保护拆掉。
    // 主动内容（脚本 / XHR / 子框架 / WebSocket / 样式 / 插件对象）直接阻断；
    // 被动内容（图片 / 媒体 / 字体 / ping）自动升级到 HTTPS，升级请求会
    // 带着新 URL 再进本回调且判定为 secure-resource，不会形成重定向环。
    // 顶层 mainFrame 导航由分类器判定为 allow，交给下面的 HTTPS-only 链路。
    try {
      const mixedPage = details.documentURL || details.originURL || '';
      const mixed = mixedGuard.classifyMixedContent(details.url, mixedPage, details.resourceType);
      if (mixed.action === 'block') {
        recordSecurityEvent('mixed-content-blocked', 'warn',
          `已阻止混合内容（${mixed.resourceType}）：${details.url}（页面 ${mixedPage}）`,
          String(mixedPage).slice(0, 2048));
        recordRequestAttempt(details, true);
        return callback({ cancel: true });
      }
      if (mixed.action === 'upgrade' && mixed.upgrade) {
        return callback({ redirectURL: mixed.upgrade });
      }
    } catch { /* 判定异常则不干预，退回 Chromium 默认策略 */ }

    // 顶层导航：剥离 utm_* 等追踪参数（只重定向一次，不动 fragment / 子资源）。
    let workingUrl = details.url;
    if (isHttpUrl && details.resourceType === 'mainFrame') {
      const stripped = stripTrackingFromUrl(details.url);
      if (stripped && stripped !== details.url) {
        return callback({ redirectURL: stripped });
      }
      // 同形异义 / IDN 反钓鱼提示（只提示，不阻断导航）。
      try {
        const navHost = new URL(details.url).hostname;
        const spoof = analyzeHostForSpoof(navHost);
        if (spoof) sendToRenderer('spoof-warning', spoof);
        // 品牌仿冒 / 拼写劫持（纯拉丁拼写编辑距离、子域碰瓷、品牌词+诱导词），
        // 与上面的 homograph 检测互补；命中后发横幅并登记到安全中心台账。
        const brandHit = brandGuard.analyzeBrand(navHost);
        if (brandHit) {
          recordBrandSpoof(brandHit);
          sendToRenderer('brand-spoof-warning', brandHit);
        }
        // URL 结构特征钓鱼：userinfo 偷渡、裸/十六进制 IP、编码主机、
        // punycode+品牌、可疑后缀/端口/深层子域叠加等。只对 high 级提示，
        // 中低风险不打扰，把普通网站误伤降到最低。
        const phishHit = phishUrl.analyze(details.url);
        if (phishHit && phishHit.level === 'high') {
          const topSignal = Array.isArray(phishHit.signals) && phishHit.signals.length
            ? phishHit.signals[0] : null;
          // 登记进安全中心品牌/钓鱼台账，复用同一按主机聚合的落盘通道。
          recordBrandSpoof({
            hostname: phishHit.hostname,
            brand: phishHit.brand,
            reason: 'url-structural',
            hint: topSignal ? topSignal.detail : 'URL 结构高度可疑',
          });
          sendToRenderer('phish-url-warning', {
            hostname: phishHit.hostname,
            url: phishHit.url,
            score: phishHit.score,
            brand: phishHit.brand,
            signals: phishHit.signals,
          });
        }
      } catch { /* 无效主机名忽略 */ }
    }

    // HTTPS-only 模式：用户可在设置里关掉；私网/回环主机永远保留 http://
    if (httpsOnlyEnabled && workingUrl.startsWith('http://') && !isPrivateNetworkHost(workingUrl)) {
      callback({ redirectURL: 'https://' + workingUrl.slice(7) });
    } else {
      // 走到“放行”这一最终决策才记一次；上面的 redirect 会带着新 URL 再进本回调，
      // 不在中途记录，避免同一条请求被重复计数。
      recordRequestAttempt(details, false);
      callback({});
    }
  });
}

// 注意：'openExternal' 不再自动放行。网页调 window.openExternal / <a href="ms-*:">
// 之前只要在这个集合里就会被静默拉系统程序，等于把 Follina 那类协议投毒开放给任意站点。
// 外部协议走 confirmAndOpenExternal()，先白名单 scheme 再弹原生确认框。
const ALLOWED_PERMISSIONS = new Set([
  'media', 'geolocation', 'notifications', 'midi', 'midiSysex',
  'pointerLock', 'fullscreen', 'clipboard-sanitized-write',
  'pop-up'
]);

// confirmAndOpenExternal 统一入口：http(s) 开新标签，外部协议走按站点记忆的确认流。
// renderer 想让浏览器"点 mailto:" 必须走这个 IPC，不许直接 shell.openExternal。
async function confirmAndOpenExternal(url, origin) {
  if (!url || typeof url !== 'string') return { ok: false, reason: 'empty url' };
  if (url.startsWith('http://') || url.startsWith('https://')) {
    if (!isSafeUrl(url)) {
      recordSecurityEvent('protocol-blocked', 'critical',
        `外部协议入口拒绝了不安全的 http(s) 地址: ${url}`, origin);
      return { ok: false, reason: 'unsafe url' };
    }
    createNewTab(url);
    return { ok: true };
  }
  return await launchExternalWithPrompt(url, origin || '', false);
}

// ===== 外部协议唤起防护（protocol-launch guard）=====
// 背景：Chromium 拉起本机协议处理器（ms-word: / zoommtg: / ms-cmd: 这一族，
// Follina/CVE-2022-30190 就是协议处理器投毒）不只发生在主框架导航里——
// 页面里的 <iframe src="ms-word:..">、子框架 302 跳到外部协议，同样可能直接
// 启动本机程序。而 will-navigate 只覆盖主框架，历史代码因此漏掉了子框架这一面。
//
// 这里做三件事：
//  1. 主框架导航到 mailto:/tel: 时，收口到"按 站点+协议 记忆决定"的确认弹窗；
//     其它外部协议（ms-*:/smb:/file:/vbscript: 等）一律阻止并提示。
//  2. 所有 webContents 增加 will-frame-navigate 监听：子框架只允许真正的 Web
//     协议（http/https/blob/data/about），iframe 永远无法拉起本机程序。
//  3. 用户在弹窗里勾选"记住对此网站的选择"后按 origin+scheme 持久化，设置页
//     可查看 / 撤销，决定文件原子落盘。

const protocolDecisionStorePath = path.join(app.getPath('userData'), 'protocol-decisions.json');
const MAX_PROTOCOL_DECISIONS = 500;
// 只有这两个协议允许在用户确认后交给系统处理器；其它外部协议没有商量余地。
const CONFIRMABLE_EXTERNAL_SCHEMES = new Set(['mailto:', 'tel:']);
// 子框架允许的协议集合。iframe 场景下 blob:/data: 有正当用途（预览、文档），
// 但 file:/cosy:/任何外部协议都不允许。
const SUBFRAME_WEB_SCHEMES = new Set(['http:', 'https:', 'blob:', 'data:', 'about:']);
// key: `${origin} ${scheme}` -> { decision: 'allow'|'deny', updatedAt }
const protocolDecisions = new Map();
let protocolDecisionsLoaded = false;
let protocolSaveTimer = null;

function protocolDecisionKey(origin, scheme) {
  return origin + ' ' + scheme;
}

function normalizeExternalScheme(url) {
  try {
    const scheme = new URL(url).protocol.toLowerCase();
    // 协议名只允许 RFC 3986 字母开头的有限字符，挡掉伪造 / 控制字符输入。
    if (!/^[a-z][a-z0-9+.-]{0,31}:$/.test(scheme)) return '';
    return scheme;
  } catch {
    return '';
  }
}

function loadProtocolDecisions() {
  if (protocolDecisionsLoaded) return;
  protocolDecisionsLoaded = true;
  try {
    const data = JSON.parse(fsSync.readFileSync(protocolDecisionStorePath, 'utf8'));
    const entries = data && typeof data === 'object' ? data.decisions : null;
    if (!entries || typeof entries !== 'object') return;
    for (const [k, v] of Object.entries(entries)) {
      if (typeof k !== 'string' || !v || typeof v !== 'object') continue;
      const sp = k.indexOf(' ');
      if (sp <= 0) continue;
      const origin = k.slice(0, sp);
      const scheme = k.slice(sp + 1);
      if (!isRememberableOrigin(origin)) continue;
      if (!CONFIRMABLE_EXTERNAL_SCHEMES.has(scheme)) continue;
      if (v.decision !== 'allow' && v.decision !== 'deny') continue;
      if (protocolDecisions.size >= MAX_PROTOCOL_DECISIONS) break;
      protocolDecisions.set(k, { decision: v.decision, updatedAt: Number(v.updatedAt) || Date.now() });
    }
  } catch {}
}

function persistProtocolDecisions() {
  if (protocolSaveTimer) clearTimeout(protocolSaveTimer);
  protocolSaveTimer = setTimeout(() => {
    try {
      const decisions = {};
      for (const [k, v] of protocolDecisions) decisions[k] = v;
      const tmp = protocolDecisionStorePath + '.tmp';
      fsSync.writeFileSync(tmp, JSON.stringify({ version: 1, decisions }), 'utf8');
      fsSync.renameSync(tmp, protocolDecisionStorePath);
    } catch {}
  }, 300);
}

function getRememberedProtocolDecision(origin, scheme) {
  loadProtocolDecisions();
  if (!isRememberableOrigin(origin) || !CONFIRMABLE_EXTERNAL_SCHEMES.has(scheme)) return null;
  const v = protocolDecisions.get(protocolDecisionKey(origin, scheme));
  return v ? v.decision : null;
}

function rememberProtocolDecision(origin, scheme, decision) {
  loadProtocolDecisions();
  if (!isRememberableOrigin(origin)) return false;
  if (!CONFIRMABLE_EXTERNAL_SCHEMES.has(scheme)) return false;
  if (decision !== 'allow' && decision !== 'deny') return false;
  if (protocolDecisions.size >= MAX_PROTOCOL_DECISIONS &&
      !protocolDecisions.has(protocolDecisionKey(origin, scheme))) {
    return false;
  }
  protocolDecisions.set(protocolDecisionKey(origin, scheme), { decision, updatedAt: Date.now() });
  persistProtocolDecisions();
  return true;
}

// classifyFrameNavigation 判断一次（主/子框架）导航该如何处理：
//   'in-pane'  ：浏览器内正常加载；
//   'confirm'  ：外部协议但可在确认后交给系统（mailto/tel）；
//   'block'    ：危险 / 不允许的协议，必须取消。
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
  if (CONFIRMABLE_EXTERNAL_SCHEMES.has(scheme)) return 'confirm';
  return 'block';
}

function originOfContents(contents) {
  try {
    return new URL(contents.getURL()).origin;
  } catch {
    return '';
  }
}

// launchExternalWithPrompt 是所有"页面想唤起外部程序"的唯一出口。
// remembered 决定直接兑现，否则弹原生确认框；remember=true 时按 origin+scheme 记忆。
async function launchExternalWithPrompt(url, origin, remember) {
  const scheme = normalizeExternalScheme(url);
  if (!scheme || !CONFIRMABLE_EXTERNAL_SCHEMES.has(scheme)) {
    recordSecurityEvent('protocol-blocked', 'warn',
      `尝试打开不可确认的外部协议 ${scheme || '(无效)'}: ${url}`, origin);
    sendToRenderer('show-toast', `已阻止打开外部协议: ${String(url).slice(0, 60)}`);
    return { ok: false, reason: 'blocked scheme' };
  }
  // 内容消毒：即便协议在白名单内，仍要挡住控制字符 / CRLF 注入 / 畸形 mailto、tel。
  // 交给系统的必须是 shellguard 放行后的规范化 URL（见 shellguard.js）。
  const extReview = shellGuard.reviewExternalUrl(url, CONFIRMABLE_EXTERNAL_SCHEMES);
  if (!extReview.ok) {
    recordSecurityEvent('protocol-blocked', 'warn',
      `外部唤起内容消毒未过（${shellGuard.describeReason(extReview.reason)}）: ${scheme}`, origin);
    sendToRenderer('show-toast', `已阻止不安全的外部链接: ${shellGuard.describeReason(extReview.reason)}`);
    return { ok: false, reason: extReview.reason };
  }
  const safeExternalUrl = extReview.url;
  if (isRememberableOrigin(origin)) {
    const known = getRememberedProtocolDecision(origin, scheme);
    if (known === 'deny') {
      recordSecurityEvent('protocol-denied', 'info',
        `按记忆决定阻止 ${scheme} 协议唤起`, origin);
      sendToRenderer('show-toast', `已按记忆阻止 ${scheme} 协议（可在设置中撤销）`);
      return { ok: false, reason: 'remembered deny' };
    }
    if (known === 'allow') {
      try {
        await shell.openExternal(safeExternalUrl, { activate: true });
        return { ok: true, reason: 'remembered allow' };
      } catch (e) {
        return { ok: false, reason: String(e && e.message || e) };
      }
    }
  }
  const siteLabel = isRememberableOrigin(origin) ? origin : '当前页面';
  // 必须用异步版：showMessageBoxSync 只返回按钮序号，拿不到 checkbox 状态。
  const choice = await dialog.showMessageBox(mainWindow, {
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
  if (remember && checked && isRememberableOrigin(origin)) {
    rememberProtocolDecision(origin, scheme, decision);
  }
  if (decision !== 'allow') {
    recordSecurityEvent('protocol-denied', 'info', `用户拒绝了 ${scheme} 协议唤起`, origin);
    return { ok: false, reason: 'user denied' };
  }
  try {
    await shell.openExternal(safeExternalUrl, { activate: true });
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: String(e && e.message || e) };
  }
}

// handleFrameNavigationAttempt 供 will-navigate / will-frame-navigate /
// will-redirect 统一调用，返回 true 表示"已经接管，原导航必须 preventDefault"。
function handleFrameNavigationAttempt(contents, url, isMainFrame) {
  const kind = classifyFrameNavigation(url, isMainFrame);
  if (kind === 'in-pane') return false;
  if (kind === 'confirm') {
    const origin = originOfContents(contents);
    // 不 await：导航事件里不能挂起异步流程，弹窗结果在另一条路径里处理。
    launchExternalWithPrompt(url, origin, true);
    return true;
  }
  const scheme = normalizeExternalScheme(url) || '未知协议';
  recordSecurityEvent('protocol-blocked', isMainFrame ? 'warn' : 'info',
    `${isMainFrame ? '主框架' : '子框架'}外部协议导航被阻止: ${scheme} ${url}`,
    originOfContents(contents));
  // 子框架拦截不弹 toast：恶意页面可以一秒塞几十个 iframe，toast 会变成轰炸。
  if (isMainFrame) {
    sendToRenderer('show-toast', `已阻止不安全的外部协议导航: ${scheme}`);
  } else {
    console.log(`[protocol-guard] 已阻止子框架外部协议导航: ${scheme}`);
  }
  return true;
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
    const data = JSON.parse(fsSync.readFileSync(securityEventStorePath, 'utf8'));
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
      const tmp = securityEventStorePath + '.tmp';
      fsSync.writeFileSync(tmp, JSON.stringify({ version: 1, events: securityEvents }), 'utf8');
      fsSync.renameSync(tmp, securityEventStorePath);
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
    const data = JSON.parse(fsSync.readFileSync(cspReportStorePath, 'utf8'));
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
      const tmp = cspReportStorePath + '.tmp';
      fsSync.writeFileSync(tmp, JSON.stringify({ version: 1, reports: cspReports }), 'utf8');
      fsSync.renameSync(tmp, cspReportStorePath);
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

// ===== 远端站点响应安全头评级（security-headers.json / cosy://security）=====
// onHeadersReceived 里对每个远端顶层文档，用“服务器原始下发”的响应头（在我们
// 补头之前）跑一次纯函数评级，按 host 聚合最近一次结果，落本地台账并在安全中心
// 展示。只看我们自己强制注入之前的原始头，才能反映站点本身的真实姿态。
//
// 隐私与体量约束：
//  - 只跟 mainFrame，不跟图片/脚本等子资源，避免第三方 CDN 域名灌爆台账；
//  - 按 host 去重（同一站只留最新评级），上限 300 个主机，原子 rename 落盘；
//  - 不记录完整路径/查询，只存 host、评级、各检查项与时间。
const headerGradeStorePath = path.join(app.getPath('userData'), 'security-headers.json');
const MAX_HEADER_GRADE_HOSTS = 300;

const headerGrades = [];
let headerGradesLoaded = false;
let headerGradeSaveTimer = null;

function loadHeaderGrades() {
  if (headerGradesLoaded) return;
  headerGradesLoaded = true;
  try {
    const data = JSON.parse(fsSync.readFileSync(headerGradeStorePath, 'utf8'));
    const entries = Array.isArray(data && data.hosts) ? data.hosts : null;
    if (!entries) return;
    for (const h of entries) {
      if (!h || typeof h !== 'object' || typeof h.host !== 'string' || !h.host) continue;
      if (typeof h.grade !== 'string' || !/^[A-F]$/.test(h.grade)) continue;
      headerGrades.push({
        host: h.host.slice(0, 253),
        time: Number(h.time) || Date.now(),
        visits: Math.max(1, Number(h.visits) || 1),
        grade: h.grade,
        percent: Math.max(0, Math.min(100, Number(h.percent) || 0)),
        insecureTransport: !!h.insecureTransport,
        checks: Array.isArray(h.checks) ? h.checks.slice(0, 16) : [],
        warnings: Array.isArray(h.warnings) ? h.warnings.slice(0, 16) : [],
      });
      if (headerGrades.length >= MAX_HEADER_GRADE_HOSTS) break;
    }
  } catch {}
}

function persistHeaderGrades() {
  if (headerGradeSaveTimer) clearTimeout(headerGradeSaveTimer);
  headerGradeSaveTimer = setTimeout(() => {
    try {
      const tmp = headerGradeStorePath + '.tmp';
      fsSync.writeFileSync(tmp, JSON.stringify({ version: 1, hosts: headerGrades }), 'utf8');
      fsSync.renameSync(tmp, headerGradeStorePath);
    } catch {}
  }, 400);
}

// recordHeaderGrade 对一次顶层文档响应评级并按 host 聚合。纯计算，不抛错。
function recordHeaderGrade(url, rawHeaders) {
  if (typeof url !== 'string' || !/^https?:/i.test(url)) return;
  let result;
  try {
    result = headerGrade.gradeSecurityHeaders(url, rawHeaders);
  } catch {
    return;
  }
  if (!result || !result.host) return;
  loadHeaderGrades();
  const now = Date.now();
  const idx = headerGrades.findIndex(h => h.host === result.host);
  const record = {
    host: result.host,
    time: now,
    visits: 1,
    grade: result.grade,
    percent: result.percent,
    insecureTransport: !!result.insecureTransport,
    checks: result.checks.map(c => ({
      id: String(c.id), name: String(c.name), weight: Number(c.weight) || 0,
      score: Number(c.score) || 0, status: String(c.status),
      value: String(c.value || '').slice(0, 300), note: String(c.note || '').slice(0, 300),
    })),
    warnings: result.warnings.map(w => String(w).slice(0, 200)).slice(0, 16),
  };
  if (idx >= 0) {
    record.visits = Math.min(Number.MAX_SAFE_INTEGER, (Number(headerGrades[idx].visits) || 1) + 1);
    headerGrades.splice(idx, 1);
    headerGrades.push(record);
  } else {
    headerGrades.push(record);
  }
  if (headerGrades.length > MAX_HEADER_GRADE_HOSTS) {
    headerGrades.splice(0, headerGrades.length - MAX_HEADER_GRADE_HOSTS);
  }
  persistHeaderGrades();
  sendToRenderer('header-grade-updated', { host: record.host, grade: record.grade, percent: record.percent });
}

function listHeaderGrades(limit = 200) {
  loadHeaderGrades();
  const n = Math.max(1, Math.min(Number(limit) || 200, MAX_HEADER_GRADE_HOSTS));
  return headerGrades.slice(-n).reverse().map(h => ({ ...h, checks: h.checks.map(c => ({ ...c })) }));
}

function clearHeaderGrades() {
  loadHeaderGrades();
  headerGrades.length = 0;
  try { fsSync.unlinkSync(headerGradeStorePath); } catch {}
  persistHeaderGrades();
  return true;
}

function getHeaderGradeStats() {
  loadHeaderGrades();
  const byGrade = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  let insecure = 0;
  for (const h of headerGrades) {
    if (byGrade[h.grade] != null) byGrade[h.grade] += 1;
    if (h.insecureTransport) insecure += 1;
  }
  return { hosts: headerGrades.length, byGrade, insecureHosts: insecure };
}

// ===== 后台跨主机连接台账（request-log.json / cosy://security）=====
// onBeforeRequest 对每条 http(s) 请求只抽取“主机/资源类型/是否被拦/是否顶层
// 打开过”交给纯模块 requestlog 聚合，让用户在安全中心看见一个网站后台到底连了
// 哪些第三方主机、连了多少次、多少被我们拦下。刻意只存主机、永不存路径与查询，
// 上限 400 主机，原子 rename 落盘。
const requestLogStorePath = path.join(app.getPath('userData'), 'request-log.json');
const MAX_REQUEST_LOG_HOSTS = 400;
let requestLogStore = requestLog.createStore(MAX_REQUEST_LOG_HOSTS);
let requestLogLoaded = false;
let requestLogSaveTimer = null;
let requestLogNotifyTimer = null;

function loadRequestLog() {
  if (requestLogLoaded) return;
  requestLogLoaded = true;
  try {
    const data = JSON.parse(fsSync.readFileSync(requestLogStorePath, 'utf8'));
    if (data && Array.isArray(data.entries)) {
      requestLogStore = requestLog.hydrate(data.entries, MAX_REQUEST_LOG_HOSTS);
    }
  } catch {}
}

function persistRequestLog() {
  if (requestLogSaveTimer) clearTimeout(requestLogSaveTimer);
  requestLogSaveTimer = setTimeout(() => {
    try {
      const tmp = requestLogStorePath + '.tmp';
      const entries = requestLog.toList(requestLogStore);
      fsSync.writeFileSync(tmp, JSON.stringify({ version: 1, savedAt: Date.now(), entries }), 'utf8');
      fsSync.renameSync(tmp, requestLogStorePath);
    } catch {}
  }, 5000);
}

// recordRequestAttempt 由 onBeforeRequest 调用；任何异常都不影响浏览。
function recordRequestAttempt(details, blocked) {
  try {
    if (!details || typeof details.url !== 'string') return;
    if (!/^https?:/i.test(details.url)) return;
    loadRequestLog();
    requestLog.ingest(requestLogStore, {
      url: details.url,
      resourceType: details.resourceType,
      blocked: !!blocked,
      navigated: !blocked && details.resourceType === 'mainFrame',
      time: Date.now(),
    });
    persistRequestLog();
    if (requestLogNotifyTimer) return;
    requestLogNotifyTimer = setTimeout(() => {
      requestLogNotifyTimer = null;
      sendToRenderer('request-log-updated', requestLog.stats(requestLogStore));
    }, 2000);
    requestLogNotifyTimer.unref?.();
  } catch {}
}

function listRequestLogEntries(limit = 200) {
  loadRequestLog();
  const n = Math.max(1, Math.min(Number(limit) || 200, MAX_REQUEST_LOG_HOSTS));
  return requestLog.toList(requestLogStore).slice(0, n);
}

function getRequestLogStats() {
  loadRequestLog();
  return requestLog.stats(requestLogStore);
}

function clearRequestLog() {
  loadRequestLog();
  requestLog.clear(requestLogStore);
  try { fsSync.unlinkSync(requestLogStorePath); } catch {}
  persistRequestLog();
  return true;
}

// ===== 品牌仿冒 / 拼写劫持命中台账（brand-spoofs.json / cosy://security）=====
// 顶层导航命中 brandguard 后，把“主机 + 被仿冒品牌 + 命中原因”按主机聚合落盘，
// 让用户在安全中心看到最近有哪些疑似钓鱼域名被提示过、分别在冒充谁。
// 隐私约束与 requestlog 一致：只存主机名与品牌名，不存路径/查询/Cookie；
// 上限 300 主机，超出淘汰最久未活动的；写盘走临时文件 + 原子 rename。
const brandSpoofStorePath = path.join(app.getPath('userData'), 'brand-spoofs.json');
const MAX_BRAND_SPOOF_HOSTS = 300;
const BRAND_SPOOF_REASONS = new Set([
  'typo-domain', 'brand-in-subdomain', 'brand-keyword-impersonation',
  // URL 结构钓鱼（userinfo 偷渡 / 裸或十六进制 IP / 编码主机 / punycode 等强信号）。
  'url-structural',
]);
let brandSpoofs = [];
let brandSpoofsLoaded = false;
let brandSpoofSaveTimer = null;
let brandSpoofNotifyTimer = null;

function loadBrandSpoofs() {
  if (brandSpoofsLoaded) return;
  brandSpoofsLoaded = true;
  try {
    const data = JSON.parse(fsSync.readFileSync(brandSpoofStorePath, 'utf8'));
    if (data && Array.isArray(data.hosts)) {
      const now = Date.now();
      for (const h of data.hosts) {
        if (!h || typeof h !== 'object') continue;
        if (typeof h.host !== 'string' || !h.host) continue;
        if (!BRAND_SPOOF_REASONS.has(h.reason)) continue;
        brandSpoofs.push({
          host: String(h.host).slice(0, 253),
          brand: String(h.brand || '').slice(0, 40),
          reason: h.reason,
          hint: String(h.hint || '').slice(0, 120),
          firstTime: Number(h.firstTime) || now,
          lastTime: Number(h.lastTime) || now,
          count: Math.max(1, Number(h.count) || 1),
        });
      }
      if (brandSpoofs.length > MAX_BRAND_SPOOF_HOSTS) {
        brandSpoofs = brandSpoofs.slice(-MAX_BRAND_SPOOF_HOSTS);
      }
    }
  } catch {}
}

function persistBrandSpoofs() {
  if (brandSpoofSaveTimer) clearTimeout(brandSpoofSaveTimer);
  brandSpoofSaveTimer = setTimeout(() => {
    try {
      const tmp = brandSpoofStorePath + '.tmp';
      fsSync.writeFileSync(tmp, JSON.stringify({ version: 1, savedAt: Date.now(), hosts: brandSpoofs }), 'utf8');
      fsSync.renameSync(tmp, brandSpoofStorePath);
    } catch {}
  }, 5000);
}

// recordBrandSpoof 由 onBeforeRequest 顶层导航调用；入参来自纯模块，仍重新白名单化，
// 防止脏数据写盘。任何异常都不影响浏览。
function recordBrandSpoof(hit) {
  try {
    if (!hit || typeof hit !== 'object') return;
    const host = String(hit.hostname || '').toLowerCase().replace(/\.$/, '').slice(0, 253);
    if (!host || !BRAND_SPOOF_REASONS.has(hit.reason)) return;
    const now = Date.now();
    loadBrandSpoofs();
    const idx = brandSpoofs.findIndex(h => h.host === host);
    if (idx >= 0) {
      const rec = brandSpoofs[idx];
      rec.lastTime = now;
      rec.count = Math.min(Number.MAX_SAFE_INTEGER, (Number(rec.count) || 1) + 1);
      // 最近一次的原因/品牌更可信（同一主机可能命中多条规则）。
      rec.reason = hit.reason;
      rec.brand = String(hit.brand || rec.brand || '').slice(0, 40);
      rec.hint = String(hit.hint || rec.hint || '').slice(0, 120);
      brandSpoofs.splice(idx, 1);
      brandSpoofs.push(rec);
    } else {
      brandSpoofs.push({
        host,
        brand: String(hit.brand || '').slice(0, 40),
        reason: hit.reason,
        hint: String(hit.hint || '').slice(0, 120),
        firstTime: now,
        lastTime: now,
        count: 1,
      });
    }
    if (brandSpoofs.length > MAX_BRAND_SPOOF_HOSTS) {
      brandSpoofs.splice(0, brandSpoofs.length - MAX_BRAND_SPOOF_HOSTS);
    }
    persistBrandSpoofs();
    if (brandSpoofNotifyTimer) return;
    brandSpoofNotifyTimer = setTimeout(() => {
      brandSpoofNotifyTimer = null;
      sendToRenderer('brand-spoof-updated', getBrandSpoofStats());
    }, 2000);
    brandSpoofNotifyTimer.unref?.();
  } catch {}
}

function listBrandSpoofEntries(limit = 200) {
  loadBrandSpoofs();
  const n = Math.max(1, Math.min(Number(limit) || 200, MAX_BRAND_SPOOF_HOSTS));
  return brandSpoofs.slice(-n).reverse().map(h => ({ ...h }));
}

function getBrandSpoofStats() {
  loadBrandSpoofs();
  const byReason = {
    'typo-domain': 0,
    'brand-in-subdomain': 0,
    'brand-keyword-impersonation': 0,
    'url-structural': 0,
  };
  const brands = new Set();
  for (const h of brandSpoofs) {
    if (byReason[h.reason] === undefined) byReason[h.reason] = 0;
    byReason[h.reason] += 1;
    if (h.brand) brands.add(h.brand);
  }
  return { hosts: brandSpoofs.length, byReason, distinctBrands: brands.size };
}

function clearBrandSpoofs() {
  loadBrandSpoofs();
  brandSpoofs = [];
  try { fsSync.unlinkSync(brandSpoofStorePath); } catch {}
  persistBrandSpoofs();
  return true;
}

// ===== TLS 证书错误硬拦截 + 主机/指纹绑定例外（cert-exceptions.json）=====
// Electron 默认在证书校验失败时“放行”，这对浏览器是致命的：中间人代理、
// 自签名劫持都会无声通过。这里改为默认阻止，只有用户在看到红色拦截页后
// 显式加入例外才放行；例外绑定“主机 + 该张证书 SHA-256 指纹”，同一主机
// 换成另一张证书（典型劫持信号）会重新拦截。吊销 / 公钥固定等硬错误
// 一律不提供继续入口（判定逻辑在 certguard.js）。
const certExceptionStorePath = path.join(app.getPath('userData'), 'cert-exceptions.json');
const MAX_CERT_EXCEPTIONS = 300;
const CERT_CHALLENGE_TTL = 10 * 60 * 1000; // 待确认的拦截挑战保留 10 分钟
let certExceptions = [];
let certExceptionsLoaded = false;
let certExceptionSaveTimer = null;
const certChallenges = new Map(); // nonce -> 拦截上下文

function loadCertExceptions() {
  if (certExceptionsLoaded) return;
  certExceptionsLoaded = true;
  try {
    const data = JSON.parse(fsSync.readFileSync(certExceptionStorePath, 'utf8'));
    if (data && Array.isArray(data.exceptions)) {
      for (const raw of data.exceptions) {
        const rec = certGuard.sanitizeExceptionRecord(raw);
        if (rec) certExceptions.push(rec);
      }
      if (certExceptions.length > MAX_CERT_EXCEPTIONS) {
        certExceptions = certExceptions.slice(-MAX_CERT_EXCEPTIONS);
      }
    }
  } catch {}
}

function persistCertExceptions() {
  if (certExceptionSaveTimer) clearTimeout(certExceptionSaveTimer);
  certExceptionSaveTimer = setTimeout(() => {
    try {
      const tmp = certExceptionStorePath + '.tmp';
      fsSync.writeFileSync(tmp, JSON.stringify({ version: 1, savedAt: Date.now(), exceptions: certExceptions }), 'utf8');
      fsSync.renameSync(tmp, certExceptionStorePath);
    } catch {}
  }, 1000);
}

// certExceptionAllowed 判断当前失败事件是否命中已批准的“主机+指纹”例外。
function certExceptionAllowed(url, certificate) {
  const verdict = certGuard.classifyCertError({ url, certificate });
  if (!verdict.host || !verdict.cert || !verdict.cert.fingerprint) return false;
  loadCertExceptions();
  return certExceptions.some(e => certGuard.exceptionMatches(e, {
    host: verdict.host,
    fingerprint: verdict.cert.fingerprint,
  }));
}

function addCertException(url, certificate, code) {
  const entry = certGuard.createException({ host: url, certificate, code });
  if (!entry) return false;
  loadCertExceptions();
  const idx = certExceptions.findIndex(e =>
    e.host === entry.host && e.fingerprint === entry.fingerprint);
  if (idx >= 0) {
    certExceptions.splice(idx, 1);
  } else if (certExceptions.length >= MAX_CERT_EXCEPTIONS) {
    certExceptions.shift(); // 台账满了淘汰最旧的一条
  }
  certExceptions.push(entry);
  persistCertExceptions();
  return true;
}

function removeCertException(host, fingerprint) {
  loadCertExceptions();
  const h = certGuard.normalizeHost(host);
  const fp = certGuard.normalizeFingerprint(fingerprint);
  const before = certExceptions.length;
  certExceptions = certExceptions.filter(e =>
    !(e.host === h && (!fp || e.fingerprint === fp)));
  if (certExceptions.length !== before) persistCertExceptions();
  return true;
}

function clearCertExceptions() {
  loadCertExceptions();
  certExceptions = [];
  try { fsSync.unlinkSync(certExceptionStorePath); } catch {}
  persistCertExceptions();
  return true;
}

function listCertExceptionEntries(limit = 200) {
  loadCertExceptions();
  const n = Math.max(1, Math.min(Number(limit) || 200, MAX_CERT_EXCEPTIONS));
  return certExceptions.slice(-n).reverse().map(e => ({ ...e }));
}

function getCertExceptionStats() {
  loadCertExceptions();
  const hosts = new Set(certExceptions.map(e => e.host));
  return { exceptions: certExceptions.length, hosts: hosts.size };
}

// makeCertChallenge 为一次拦截生成一次性 nonce，供渲染进程“仍要前往”回传。
function makeCertChallenge(verdict, webContentsId) {
  const nonce = require('crypto').randomBytes(16).toString('hex');
  certChallenges.set(nonce, {
    host: verdict.host,
    code: verdict.code,
    fingerprint: verdict.cert ? verdict.cert.fingerprint : '',
    webContentsId,
    createdAt: Date.now(),
  });
  setTimeout(() => certChallenges.delete(nonce), CERT_CHALLENGE_TTL).unref?.();
  return nonce;
}

// consumeCertChallenge 取出并销毁一次挑战，返回 null 表示过期/伪造。
function consumeCertChallenge(nonce) {
  if (typeof nonce !== 'string' || nonce.length !== 32) return null;
  const c = certChallenges.get(nonce);
  if (!c) return null;
  certChallenges.delete(nonce);
  if (Date.now() - c.createdAt > CERT_CHALLENGE_TTL) return null;
  return c;
}

// 证书校验失败：默认阻止。命中已批准例外才放行；否则向主界面推送全屏
// 拦截页（仅主框架导航）。证书对象在送渲染进程前经 summarizeCertificate
// 脱敏，只给展示所需字段。
app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
  try {
    if (certExceptionAllowed(url, certificate)) {
      event.preventDefault();
      callback(true);
      return;
    }
    event.preventDefault();
    callback(false);

    const verdict = certGuard.classifyCertError({ url, error, certificate });
    if (!verdict.host) return;
    // 只为主框架导航弹拦截页；子资源（图片/脚本等）证书错误静默阻止即可。
    let isMainFrame = false;
    try {
      const cur = webContents.getURL ? webContents.getURL() : '';
      isMainFrame = !cur || certGuard.normalizeHost(cur) === verdict.host;
    } catch { isMainFrame = true; }
    if (!isMainFrame) return;

    const nonce = makeCertChallenge(verdict, webContents.id);
    sendToRenderer('cert-error-blocked', {
      nonce,
      url: String(url).slice(0, 2048),
      host: verdict.host,
      code: verdict.code,
      overridable: verdict.overridable,
      title: verdict.title,
      detail: verdict.detail,
      cert: verdict.cert,
      shortFingerprint: certGuard.shortFingerprint(verdict.cert ? verdict.cert.fingerprint : ''),
    });
  } catch {
    // 任何意外都 fail-closed，绝不因异常而默认放行。
    try { event.preventDefault(); } catch {}
    try { callback(false); } catch {}
  }
});

ipcMain.handle('approve-cert-exception', (event, payload = {}) => {
  const challenge = consumeCertChallenge(payload.nonce);
  if (!challenge) return { ok: false, error: '挑战已过期或无效，请重新访问' };
  const verdict2 = certGuard.errorInfo(challenge.code);
  if (!verdict2.overridable) return { ok: false, error: '该证书错误不可绕过' };
  const ok = addCertException(challenge.host, {
    fingerprint: challenge.fingerprint ? `sha256/${challenge.fingerprint}` : '',
    subjectName: '',
    issuerName: '',
  }, challenge.code);
  if (!ok) return { ok: false, error: '例外记录失败' };
  // 放行后重新加载对应标签；找不到则只记录、不导航。
  try {
    const target = webContents.fromId(challenge.webContentsId);
    if (target && !target.isDestroyed()) {
      setImmediate(() => { try { target.reload(); } catch {} });
    }
  } catch {}
  sendToRenderer('cert-exception-updated', getCertExceptionStats());
  return { ok: true };
});

ipcMain.handle('list-cert-exceptions', (event, payload = {}) => ({
  entries: listCertExceptionEntries(payload.limit),
  stats: getCertExceptionStats(),
}));

ipcMain.handle('remove-cert-exception', (event, payload = {}) => {
  removeCertException(payload.host, payload.fingerprint);
  sendToRenderer('cert-exception-updated', getCertExceptionStats());
  return { ok: true };
});

ipcMain.handle('clear-cert-exceptions', () => {
  clearCertExceptions();
  sendToRenderer('cert-exception-updated', getCertExceptionStats());
  return { ok: true };
});

ipcMain.handle('get-cert-exception-stats', () => getCertExceptionStats());

// ===== 网络身份认证治理（login / select-client-certificate）=====
// Electron 缺省会对任何框架的 HTTP 401 弹原生登录框，且可能静默复用当前
// Windows/域凭据；select-client-certificate 在多证书时也可能自动选一张发走，
// 把客户端证书身份泄露给任意站点。判定内核在 netauthguard.js，这里只负责
// 接系统事件、做限流、把挑战交给我们自己的渲染层弹框，并落“记住的证书”台账。
const netAuthCrypto = require('crypto');
const clientCertStorePath = path.join(app.getPath('userData'), 'client-cert-choices.json');
const MAX_CLIENT_CERT_PICK_CHARS = 64;

const clientCertStore = new netAuthGuard.RememberedClientCertStore();
const authLimiter = new netAuthGuard.AuthPromptRateLimiter();
const authStats = new netAuthGuard.AuthPromptStats();
let clientCertStoreLoaded = false;
let clientCertSaveTimer = null;

// nonce -> { callback, kind, timer, key }。认证 / 证书选择都是“可挂起的回调”，
// 等待渲染层返回；统一放 Map 里，超时或窗口关闭时统一取消，绝不遗留悬挂回调。
const pendingAuthChallenges = new Map();

function netAuthNonce() {
  return 'na-' + netAuthCrypto.randomBytes(12).toString('hex');
}

function loadClientCertChoices() {
  if (clientCertStoreLoaded) return;
  clientCertStoreLoaded = true;
  try {
    const raw = fsSync.readFileSync(clientCertStorePath, 'utf8');
    clientCertStore.loadJSON(raw);
  } catch {}
}

function persistClientCertChoices() {
  if (clientCertSaveTimer) clearTimeout(clientCertSaveTimer);
  clientCertSaveTimer = setTimeout(() => {
    try {
      const tmp = clientCertStorePath + '.tmp';
      fsSync.writeFileSync(tmp, JSON.stringify(clientCertStore.toJSON()), 'utf8');
      fsSync.renameSync(tmp, clientCertStorePath);
    } catch {}
  }, 300);
}

// failAuthCallback 在“不弹框 / 超时 / 窗口关闭”等路径上安全地兑现一个空凭据，
// 让请求以未认证失败，而不是卡住或回退到系统默认行为。
function failAuthCallback(callback) {
  try { callback(); } catch {}
}

function rejectAuthChallenge(nonce) {
  const c = pendingAuthChallenges.get(nonce);
  if (!c) return false;
  clearTimeout(c.timer);
  pendingAuthChallenges.delete(nonce);
  failAuthCallback(c.callback);
  return true;
}

function authEventOrigin(webContents) {
  try {
    return new URL(webContents.getURL()).origin;
  } catch {
    return '';
  }
}

// sanitizeCertPickList 只把证书的非敏感摘要给渲染层，绝不传证书对象本体。
function sanitizeCertPickList(certificateList) {
  const out = [];
  const list = Array.isArray(certificateList) ? certificateList : [];
  for (let i = 0; i < list.length && i < MAX_CLIENT_CERT_PICK_CHARS; i++) {
    const s = netAuthGuard.summarizeClientCert(list[i]);
    out.push({
      index: i,
      fingerprint: s.fingerprint,
      issuer: s.issuer,
      subject: s.subject,
      serialNumber: s.serialNumber,
    });
  }
  return out;
}

function setupNetworkAuth() {
  loadClientCertChoices();

  // HTTP/代理身份认证。isProxy 时走 407 判定，否则按 401 主/子框架判定。
  app.on('login', (loginEvent, webContents, request, authInfo, callback) => {
    loginEvent.preventDefault();
    const info = authInfo || {};
    const isProxy = info.isProxy === true;
    const verdict = isProxy
      ? netAuthGuard.classifyProxyAuth({ url: request && request.url, authInfo: info })
      : netAuthGuard.classifyServerAuth({
          url: request && request.url,
          // Electron 41 在 response details 里给 resourceType；缺省时按子框架
          // fail-closed，不允许在无法确认顶层的情况下弹框（可能泄露凭据）。
          isMainFrame: request && request.resourceType === 'mainFrame',
          authInfo: info,
        });
    authStats.recordEvent({ decision: verdict.decision, reason: verdict.reason, scheme: verdict.scheme });

    if (verdict.decision !== 'prompt') {
      failAuthCallback(callback);
      recordSecurityEvent('auth-blocked', 'warn',
        `${isProxy ? '代理' : '服务器'}认证被拦截：${verdict.reason}（${verdict.scheme || '未知方案'}）`,
        isProxy ? (verdict.host || 'proxy') : verdict.key);
      return;
    }

    const gate = authLimiter.request(verdict.key, Date.now());
    if (!gate.allow) {
      authStats.recordRateLimited();
      failAuthCallback(callback);
      recordSecurityEvent('auth-rate-limited', 'warn',
        `认证弹框过频已临时冷却：${verdict.key}（${gate.reason}）`, verdict.key);
      return;
    }

    // 有界待处理队列：超过上限直接取消最旧的同类挑战，防止 401 风暴堆积。
    if (pendingAuthChallenges.size >= netAuthGuard.MAX_PENDING_PROMPTS) {
      const oldest = pendingAuthChallenges.keys().next().value;
      rejectAuthChallenge(oldest);
    }

    const nonce = netAuthNonce();
    const timer = setTimeout(() => {
      if (!pendingAuthChallenges.has(nonce)) return;
      pendingAuthChallenges.delete(nonce);
      failAuthCallback(callback);
    }, netAuthGuard.AUTH_PROMPT_TIMEOUT_MS);
    pendingAuthChallenges.set(nonce, { callback, timer, key: verdict.key, kind: 'login' });

    sendToRenderer('network-auth-required', {
      nonce,
      isProxy,
      host: verdict.host || '',
      key: verdict.key,
      scheme: verdict.scheme,
      schemeLabel: netAuthGuard.describeAuthScheme(verdict.scheme),
      realm: verdict.realm || '',
      origin: authEventOrigin(webContents),
    });
  });

  // TLS 客户端证书：默认不发送，除非用户为该主机明确记住过一张证书的指纹。
  session.defaultSession.on('select-client-certificate', (certEvent, webContents, url, certificateList, callback) => {
    certEvent.preventDefault();
    let hostname = '';
    try { hostname = new URL(url).hostname; } catch {}
    const remembered = hostname ? clientCertStore.get(hostname) : null;
    const pick = netAuthGuard.chooseClientCertificate({
      certificateList,
      rememberedFingerprint: remembered ? remembered.fingerprint : '',
    });
    if (pick.index >= 0 && certificateList[pick.index]) {
      try { callback(certificateList[pick.index]); } catch { try { callback(); } catch {} }
      return;
    }
    authStats.recordCertSuppressed();
    recordSecurityEvent('client-cert-blocked', 'info',
      `未自动发送客户端证书：${hostname || '未知主机'}（${pick.reason}）`, url);

    if (pendingAuthChallenges.size >= netAuthGuard.MAX_PENDING_PROMPTS) {
      try { callback(); } catch {}
      return;
    }
    const nonce = netAuthNonce();
    const timer = setTimeout(() => {
      if (!pendingAuthChallenges.has(nonce)) return;
      pendingAuthChallenges.delete(nonce);
      try { callback(); } catch {}
    }, netAuthGuard.AUTH_PROMPT_TIMEOUT_MS);
    pendingAuthChallenges.set(nonce, { callback, timer, key: url, kind: 'cert', certificateList, hostname });
    sendToRenderer('client-cert-required', {
      nonce,
      host: hostname,
      origin: authEventOrigin(webContents),
      certificates: sanitizeCertPickList(certificateList),
    });
  });
}

// 渲染层提交账号口令。只接受主界面，且 nonce 必须仍在待处理表里。
ipcMain.handle('submit-network-auth', (event, payload = {}) => {
  if (!isMainSender(event)) return { ok: false, error: 'denied' };
  const challenge = pendingAuthChallenges.get(payload.nonce);
  if (!challenge || challenge.kind !== 'login') return { ok: false, error: '挑战已过期或无效' };
  const clean = netAuthGuard.sanitizeAuthSubmit({ username: payload.username, password: payload.password });
  if (!clean.ok) return { ok: false, error: '账号或口令不合法' };
  clearTimeout(challenge.timer);
  pendingAuthChallenges.delete(payload.nonce);
  try { challenge.callback(clean.username, clean.password); } catch {}
  authLimiter.reset(challenge.key);
  authStats.recordSuccess();
  return { ok: true };
});

ipcMain.handle('cancel-network-auth', (event, payload = {}) => {
  if (!isMainSender(event)) return { ok: false, error: 'denied' };
  return { ok: rejectAuthChallenge(payload.nonce) };
});

// 渲染层选择客户端证书；remember=true 时把该主机->指纹记入台账。
ipcMain.handle('choose-client-cert', (event, payload = {}) => {
  if (!isMainSender(event)) return { ok: false, error: 'denied' };
  const challenge = pendingAuthChallenges.get(payload.nonce);
  if (!challenge || challenge.kind !== 'cert') return { ok: false, error: '挑战已过期或无效' };
  const idx = Number(payload.index);
  const list = Array.isArray(challenge.certificateList) ? challenge.certificateList : [];
  if (!Number.isInteger(idx) || idx < 0 || idx >= list.length) {
    return { ok: false, error: '证书序号无效' };
  }
  clearTimeout(challenge.timer);
  pendingAuthChallenges.delete(payload.nonce);
  try { challenge.callback(list[idx]); } catch {}
  if (payload.remember === true && challenge.hostname) {
    if (clientCertStore.remember(challenge.hostname, list[idx], Date.now())) persistClientCertChoices();
  }
  sendToRenderer('client-cert-choices-updated', getClientCertChoiceStats());
  return { ok: true };
});

ipcMain.handle('cancel-client-cert', (event, payload = {}) => {
  if (!isMainSender(event)) return { ok: false, error: 'denied' };
  const challenge = pendingAuthChallenges.get(payload.nonce);
  if (!challenge || challenge.kind !== 'cert') return { ok: false, error: '挑战已过期或无效' };
  clearTimeout(challenge.timer);
  pendingAuthChallenges.delete(payload.nonce);
  try { challenge.callback(); } catch {}
  return { ok: true };
});

ipcMain.handle('list-remembered-certs', (event, payload = {}) => {
  if (!isMainSender(event)) return { ok: false, error: 'denied' };
  loadClientCertChoices();
  const limit = Math.min(Number(payload.limit) || netAuthGuard.MAX_REMEMBERED_CERT_HOSTS, netAuthGuard.MAX_REMEMBERED_CERT_HOSTS);
  return { ok: true, entries: clientCertStore.list().slice(0, limit), stats: getClientCertChoiceStats() };
});

ipcMain.handle('forget-remembered-cert', (event, payload = {}) => {
  if (!isMainSender(event)) return { ok: false, error: 'denied' };
  if (typeof payload.host !== 'string') return { ok: false, error: 'bad-host' };
  clientCertStore.forget(payload.host);
  persistClientCertChoices();
  sendToRenderer('client-cert-choices-updated', getClientCertChoiceStats());
  return { ok: true };
});

ipcMain.handle('clear-remembered-certs', (event) => {
  if (!isMainSender(event)) return { ok: false, error: 'denied' };
  clientCertStore.clear();
  persistClientCertChoices();
  sendToRenderer('client-cert-choices-updated', getClientCertChoiceStats());
  return { ok: true };
});

ipcMain.handle('get-auth-stats', (event) => {
  if (!isMainSender(event)) return { ok: false, error: 'denied' };
  return { ok: true, stats: authStats.toJSON() };
});

// ===== Cookie 加固台账（cosy://security 面板）=====
ipcMain.handle('list-cookie-hardening', (event) => {
  if (!isMainSender(event)) return { ok: false, error: 'denied', entries: [] };
  loadCookieLedger();
  return { ok: true, entries: cookieLedger.list() };
});

ipcMain.handle('get-cookie-hardening-stats', (event) => {
  if (!isMainSender(event)) return { ok: false, error: 'denied' };
  loadCookieLedger();
  return { ok: true, stats: cookieLedger.stats() };
});

ipcMain.handle('clear-cookie-hardening', (event) => {
  if (!isMainSender(event)) return { ok: false, error: 'denied' };
  cookieLedger.clear();
  persistCookieLedger();
  sendToRenderer('cookie-hardening-updated', cookieLedger.stats());
  return { ok: true, stats: cookieLedger.stats() };
});

// ===== PNA 私有网络访问台账 =====
ipcMain.handle('list-pna-blocks', (event) => {
  if (!isMainSender(event)) return { ok: false, error: 'denied', entries: [] };
  loadPnaLedger();
  const entries = [...pnaLedger.values()].sort((a, b) => b.lastTime - a.lastTime);
  return { ok: true, entries };
});

ipcMain.handle('get-pna-block-stats', (event) => {
  if (!isMainSender(event)) return { ok: false, error: 'denied' };
  loadPnaLedger();
  return { ok: true, stats: pnaLedgerStats() };
});

ipcMain.handle('clear-pna-blocks', (event) => {
  if (!isMainSender(event)) return { ok: false, error: 'denied' };
  pnaLedger.clear();
  persistPnaLedger();
  sendToRenderer('pna-blocked-updated', pnaLedgerStats());
  return { ok: true, stats: pnaLedgerStats() };
});

ipcMain.handle('list-fingerprint-entries', (event) => {
  if (!isMainSender(event)) return { ok: false, error: 'denied', entries: [] };
  loadFpLedger();
  return { ok: true, entries: fpLedger.entries() };
});

ipcMain.handle('get-fingerprint-stats', (event) => {
  if (!isMainSender(event)) return { ok: false, error: 'denied' };
  loadFpLedger();
  return { ok: true, stats: fpLedger.stats() };
});

ipcMain.handle('clear-fingerprint-entries', (event) => {
  if (!isMainSender(event)) return { ok: false, error: 'denied' };
  fpLedger.clear();
  persistFpLedger();
  sendToRenderer('fingerprint-blocked-updated', fpLedger.stats());
  return { ok: true, stats: fpLedger.stats() };
});

ipcMain.handle('get-doh-status', (event) => {
  if (!isMainSender(event)) return { ok: false, error: 'denied' };
  loadDohLedger();
  return {
    ok: true,
    supported: typeof session.defaultSession.setHostResolverControls === 'function',
    status: dohStatus(),
    providers: dohGuard.KNOWN_PROVIDERS,
    forcedFeatures: permPolicy.FORCED_DISABLE,
  };
});

ipcMain.handle('clear-doh-events', (event) => {
  if (!isMainSender(event)) return { ok: false, error: 'denied' };
  dohLedger.clear();
  persistDohLedger();
  return { ok: true };
});

function getClientCertChoiceStats() {
  const entries = clientCertStore.list();
  return { count: entries.length, max: netAuthGuard.MAX_REMEMBERED_CERT_HOSTS };
}


// ===== 下载完整性校验（download-hashes.json / cosy://hashes）=====
// Electron 的下载项只保证"字节传完了"，不保证字节没被中间人 / 镜像污染。
// 现代浏览器在"显示下载文件的校验和"这件事上普遍缺位：用户从第三方站下了
// 安装包后想核对官方公布的 SHA-256，只能自己翻 certutil。这里在每次下载
// 完成后异步流式计算 SHA-256（不占大内存），登记到本机台账，并在
// cosy://hashes 页面提供一键比对 + 任意本地文件校验。
//
// 设计约束：
//  - 串行队列：多个大文件同时下完时顺序摘要，避免把磁盘 IO 打满；
//  - 只跟普通文件，拒绝符号链接，防止摘要时被人换掉路径；
//  - 体积上限 512 GiB——正常下载永远碰不到，只有"恶意/失控的超大文件
//    拖死磁盘"时才触发；
//  - 台账只记文件名与来源主机，不记完整本地路径，减少隐私落盘。
const nodeCrypto = require('crypto');
const downloadHashStorePath = path.join(app.getPath('userData'), 'download-hashes.json');
const MAX_DOWNLOAD_HASH_RECORDS = 500;
const MAX_HASHABLE_DOWNLOAD_BYTES = 512 << 30; // 512 GiB
const HASH_READ_CHUNK = 1024 * 1024;           // 1 MiB 读取块

const downloadHashRecords = [];
let downloadHashesLoaded = false;
let downloadHashSaveTimer = null;
let downloadHashChain = Promise.resolve();

function loadDownloadHashes() {
  if (downloadHashesLoaded) return;
  downloadHashesLoaded = true;
  try {
    const data = JSON.parse(fsSync.readFileSync(downloadHashStorePath, 'utf8'));
    const entries = Array.isArray(data && data.records) ? data.records : null;
    if (!entries) return;
    for (const r of entries) {
      if (!r || typeof r !== 'object') continue;
      if (typeof r.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(r.sha256)) continue;
      if (typeof r.filename !== 'string' || !r.filename) continue;
      downloadHashRecords.push({
        id: String(r.id || ''),
        time: Number(r.time) || Date.now(),
        filename: r.filename.slice(0, 255),
        size: Number.isFinite(Number(r.size)) ? Number(r.size) : 0,
        sha256: r.sha256,
        host: typeof r.host === 'string' ? r.host.slice(0, 255) : '',
      });
      if (downloadHashRecords.length >= MAX_DOWNLOAD_HASH_RECORDS) break;
    }
  } catch {}
}

function persistDownloadHashes() {
  if (downloadHashSaveTimer) clearTimeout(downloadHashSaveTimer);
  downloadHashSaveTimer = setTimeout(() => {
    try {
      const tmp = downloadHashStorePath + '.tmp';
      fsSync.writeFileSync(tmp, JSON.stringify({ version: 1, records: downloadHashRecords }), 'utf8');
      fsSync.renameSync(tmp, downloadHashStorePath);
    } catch {}
  }, 300);
}

// hashFileSha256 以 1 MiB 流式块计算摘要，返回 { sha256, size }。
// 路径必须是普通文件；不存在 / 是符号链接 / 超体积上限一律拒绝。
function hashFileSha256(filePath) {
  return new Promise((resolve, reject) => {
    let stat;
    try {
      stat = fsSync.lstatSync(filePath);
    } catch (e) { reject(e); return; }
    if (!stat.isFile()) { reject(new Error('目标不是普通文件（拒绝摘要符号链接或特殊文件）')); return; }
    if (stat.size > MAX_HASHABLE_DOWNLOAD_BYTES) {
      reject(new Error('文件体积超过摘要安全上限'));
      return;
    }
    const hash = nodeCrypto.createHash('sha256');
    const input = fsSync.createReadStream(filePath, { highWaterMark: HASH_READ_CHUNK });
    let size = 0;
    input.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_HASHABLE_DOWNLOAD_BYTES) {
        input.destroy(new Error('文件体积超过摘要安全上限'));
        return;
      }
      hash.update(chunk);
    });
    input.on('end', () => resolve({ sha256: hash.digest('hex'), size }));
    input.on('error', reject);
  });
}

function upsertDownloadHashRecord(record) {
  loadDownloadHashes();
  const idx = downloadHashRecords.findIndex(r => r.id === record.id);
  if (idx >= 0) downloadHashRecords.splice(idx, 1);
  downloadHashRecords.push(record);
  if (downloadHashRecords.length > MAX_DOWNLOAD_HASH_RECORDS) {
    downloadHashRecords.splice(0, downloadHashRecords.length - MAX_DOWNLOAD_HASH_RECORDS);
  }
  persistDownloadHashes();
}

// queueDownloadHashing 把一次下载完成事件排进串行摘要链。
// 摘要是附加能力，任何失败都静默跳过，绝不能影响下载本身的可用性。
function queueDownloadHashing(task) {
  downloadHashChain = downloadHashChain.then(async () => {
    try {
      const { sha256, size } = await hashFileSha256(task.savePath);
      let host = '';
      try { host = new URL(task.url).host; } catch {}
      const record = {
        id: String(task.id),
        time: Date.now(),
        filename: String(task.filename || '').slice(0, 255) || 'download',
        size,
        sha256,
        host,
      };
      upsertDownloadHashRecord(record);
      sendToRenderer('download-hashed', record);
    } catch (e) {
      console.log('[download-hash] 摘要失败，已跳过:', String(e && e.message || e));
    }
  });
  return downloadHashChain;
}

function listDownloadHashes(limit = 200) {
  loadDownloadHashes();
  const n = Math.max(1, Math.min(Number(limit) || 200, MAX_DOWNLOAD_HASH_RECORDS));
  return downloadHashRecords.slice(-n).reverse().map(r => ({ ...r }));
}

function removeDownloadHashRecord(id) {
  loadDownloadHashes();
  const idx = downloadHashRecords.findIndex(r => r.id === String(id));
  if (idx < 0) return false;
  downloadHashRecords.splice(idx, 1);
  persistDownloadHashes();
  return true;
}

function clearDownloadHashes() {
  loadDownloadHashes();
  downloadHashRecords.length = 0;
  try { fsSync.unlinkSync(downloadHashStorePath); } catch {}
  persistDownloadHashes();
  return true;
}

// normalizeExpectedHash 校验用户粘贴的期望摘要：支持 64 位 hex，
// 兼容大小写与首尾空白；其它输入返回空串，由调用方判定为非法。
function normalizeExpectedHash(input) {
  const s = String(input || '').trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(s) ? s : '';
}

function verifyDownloadHashById(id, expected) {
  loadDownloadHashes();
  const want = normalizeExpectedHash(expected);
  if (!want) return { ok: false, reason: 'invalid-expected' };
  const rec = downloadHashRecords.find(r => r.id === String(id));
  if (!rec) return { ok: false, reason: 'not-found' };
  // 常量时间比较，避免把摘要比对变成时序侧信道。
  let acc = 0;
  for (let i = 0; i < 64; i++) acc |= rec.sha256.charCodeAt(i) ^ want.charCodeAt(i);
  const match = acc === 0;
  return { ok: match, match, filename: rec.filename, actual: rec.sha256 };
}

// hashLocalFileViaDialog 让用户在 cosy://hashes 页面选择任意本地文件计算
// 摘要，用于校验从别处拷贝来的安装包。只回传文件名 / 大小 / 摘要，不回传路径。
async function hashLocalFileViaDialog() {
  const choice = await dialog.showOpenDialog(mainWindow, {
    title: '选择要计算 SHA-256 的文件',
    properties: ['openFile']
  });
  if (choice.canceled || !choice.filePaths || !choice.filePaths.length) {
    return { ok: false, reason: 'canceled' };
  }
  const filePath = choice.filePaths[0];
  const { sha256, size } = await hashFileSha256(filePath);
  return { ok: true, filename: path.basename(filePath), size, sha256 };
}


// 与 Chromium 自带的内容设置平行：用户在询问条上勾"始终允许/拒绝"后，按
// origin+permission 持久化，下次同站点再请求时不再打扰。决定文件与缩放记忆
// 一样放 userData，原子 rename 落盘，损坏静默丢弃，绝不拖垮启动。
const REMEMBERED_PAGE_PERMISSIONS = new Set([
  'media', 'geolocation', 'notifications', 'midi', 'midiSysex', 'clipboard-read',
]);
const permissionStorePath = path.join(app.getPath('userData'), 'permission-decisions.json');
const MAX_PERMISSION_DECISIONS = 1000;
// key 为 `${origin} ${permission}` -> { decision: 'allow'|'deny', updatedAt }
const permissionDecisions = new Map();
let permissionDecisionsLoaded = false;
let permissionSaveTimer = null;

function permissionStoreKey(origin, permission) {
  return origin + ' ' + permission;
}

// 只记忆真实网页 origin：cosy:// 内部页、file://、data: 等不允许进入决定表，
// 避免内部页名或本地文件路径被当成站点长期授权。
function isRememberableOrigin(origin) {
  if (typeof origin !== 'string' || origin.length === 0 || origin.length > 300) return false;
  try {
    const u = new URL(origin);
    return (u.protocol === 'https:' || u.protocol === 'http:') && !!u.hostname;
  } catch {
    return false;
  }
}

function loadPermissionDecisions() {
  if (permissionDecisionsLoaded) return;
  permissionDecisionsLoaded = true;
  try {
    const data = JSON.parse(fsSync.readFileSync(permissionStorePath, 'utf8'));
    const entries = data && typeof data === 'object' ? data.decisions : null;
    if (!entries || typeof entries !== 'object') return;
    for (const [k, v] of Object.entries(entries)) {
      if (typeof k !== 'string' || !v || typeof v !== 'object') continue;
      const sp = k.indexOf(' ');
      if (sp <= 0) continue;
      const origin = k.slice(0, sp);
      const permission = k.slice(sp + 1);
      if (!isRememberableOrigin(origin)) continue;
      if (!REMEMBERED_PAGE_PERMISSIONS.has(permission)) continue;
      if (v.decision !== 'allow' && v.decision !== 'deny') continue;
      if (permissionDecisions.size >= MAX_PERMISSION_DECISIONS) break;
      permissionDecisions.set(k, { decision: v.decision, updatedAt: Number(v.updatedAt) || Date.now() });
    }
  } catch {}
}

function persistPermissionDecisions() {
  if (permissionSaveTimer) clearTimeout(permissionSaveTimer);
  permissionSaveTimer = setTimeout(() => {
    try {
      const decisions = {};
      for (const [k, v] of permissionDecisions) decisions[k] = v;
      const tmp = permissionStorePath + '.tmp';
      fsSync.writeFileSync(tmp, JSON.stringify({ version: 1, decisions }), 'utf8');
      fsSync.renameSync(tmp, permissionStorePath);
    } catch {}
  }, 300);
}

function getRememberedPermission(origin, permission) {
  loadPermissionDecisions();
  if (!isRememberableOrigin(origin) || !REMEMBERED_PAGE_PERMISSIONS.has(permission)) return null;
  const v = permissionDecisions.get(permissionStoreKey(origin, permission));
  return v ? v.decision : null;
}

function rememberPermission(origin, permission, decision) {
  loadPermissionDecisions();
  if (!isRememberableOrigin(origin)) return false;
  if (!REMEMBERED_PAGE_PERMISSIONS.has(permission)) return false;
  if (decision !== 'allow' && decision !== 'deny') return false;
  const key = permissionStoreKey(origin, permission);
  if (!permissionDecisions.has(key) && permissionDecisions.size >= MAX_PERMISSION_DECISIONS) return false;
  permissionDecisions.set(key, { decision, updatedAt: Date.now() });
  persistPermissionDecisions();
  return true;
}

function forgetPermission(origin, permission) {
  loadPermissionDecisions();
  const deleted = permissionDecisions.delete(permissionStoreKey(origin, permission));
  if (deleted) persistPermissionDecisions();
  return deleted;
}

function listPermissionDecisions() {
  loadPermissionDecisions();
  const out = [];
  for (const [k, v] of permissionDecisions) {
    const sp = k.indexOf(' ');
    out.push({
      origin: k.slice(0, sp),
      permission: k.slice(sp + 1),
      decision: v.decision,
      updatedAt: v.updatedAt,
    });
  }
  out.sort((a, b) => a.origin.localeCompare(b.origin) || a.permission.localeCompare(b.permission));
  return out;
}

function clearPermissionDecisionsForOrigin(origin) {
  loadPermissionDecisions();
  if (!isRememberableOrigin(origin)) return 0;
  let n = 0;
  const prefix = origin + ' ';
  for (const k of Array.from(permissionDecisions.keys())) {
    if (k.startsWith(prefix)) {
      permissionDecisions.delete(k);
      n++;
    }
  }
  if (n) persistPermissionDecisions();
  return n;
}

function setupPermissionHandlers() {
  // 敏感权限不能再静默放行：旧实现里 media/geolocation/notifications/midi 全部
  // callback(true)，任意网站都能不经询问打开摄像头、麦克风、定位、通知。
  // 这些改为向当前标签的渲染层发请求，由页面内询问条决定，默认安全失败。
  const SENSITIVE_PAGE_PERMISSIONS = new Set([
    'media', 'geolocation', 'notifications', 'midi', 'midiSysex',
    // 读剪贴板能拿到密码 / 验证码 / 钱包地址等敏感内容，绝不静默放行，
    // 必须像摄像头定位那样弹询问条由用户显式授权。
    'clipboard-read',
  ]);
  // requestId -> settle(granted)，只允许决一次，超时 / 页面销毁默认拒绝。
  const pendingPermissionRequests = new Map();
  let permissionSeq = 0;
  const permissionDecisionTimeoutMs = 60000;

  const tabIdForContents = (wc) => {
    const tab = tabs.find(t => t.view && t.view.webContents === wc);
    return tab ? tab.id : null;
  };

  session.defaultSession.setPermissionRequestHandler((webContents, permission, callback, details) => {
    // openExternal 不再静默放行：弹一次原生确认。这里拿不到具体 URL，
    // 真正带 URL 的外部协议请求走 confirmAndOpenExternal IPC。
    if (permission === 'openExternal') {
      const choice = dialog.showMessageBoxSync(mainWindow, {
        type: 'question',
        buttons: ['允许', '拒绝'],
        defaultId: 1,
        cancelId: 1,
        title: '网站请求打开外部程序',
        message: '当前网站请求调用系统外部应用，是否允许？'
      });
      callback(choice === 0);
      return;
    }

    if (SENSITIVE_PAGE_PERMISSIONS.has(permission)) {
      let origin = '';
      try { origin = new URL(webContents.getURL()).origin; } catch { origin = ''; }

      // 用户对该站点记忆过"始终允许/拒绝"：直接兑现决定，不再弹询问条。
      const remembered = getRememberedPermission(origin, permission);
      if (remembered === 'allow' || remembered === 'deny') {
        callback(remembered === 'allow');
        return;
      }

      const requestId = String(++permissionSeq);
      let settled = false;
      let timer = null;
      const cleanup = () => {
        if (timer) clearTimeout(timer);
        webContents.removeListener('destroyed', onDestroyed);
        pendingPermissionRequests.delete(requestId);
      };
      const finish = (granted) => {
        if (settled) return;
        settled = true;
        cleanup();
        try { callback(!!granted); } catch {}
      };
      const onDestroyed = () => finish(false);
      webContents.once('destroyed', onDestroyed);
      timer = setTimeout(() => finish(false), permissionDecisionTimeoutMs);
      pendingPermissionRequests.set(requestId, { finish, origin, permission });

      sendToRenderer('permission-request', {
        requestId,
        tabId: tabIdForContents(webContents),
        permission,
        origin,
        mediaTypes: Array.isArray(details && details.mediaTypes) ? details.mediaTypes.slice(0, 4) : [],
      });
      return;
    }

    // 其余非敏感、通常由用户手势触发的权限（fullscreen / pointerLock / clipboard 等）维持白名单。
    // 不在白名单内的权限（hid / serial / bluetooth / window-management /
    // idle-detection / usb 等设备或指纹类权限）默认拒绝并留痕。以前这里直接
    // 用 Set.has 兜底，虽然结果也是 false，但被拦的请求完全没有记录，用户无从
    // 知道某个网站在尝试枚举蓝牙 / HID 设备。
    const allowed = ALLOWED_PERMISSIONS.has(permission);
    if (!allowed) {
      let origin = '';
      try { origin = new URL(webContents.getURL()).origin; } catch {}
      recordSecurityEvent('permission-blocked', 'warn',
        `网站请求了未授权的浏览器权限: ${permission}`, origin);
    }
    callback(allowed);
  });
  session.defaultSession.setPermissionCheckHandler((webContents, permission) => {
    if (permission === 'openExternal') return false;
    // 敏感权限：记忆为"允许"才承认；记忆为"拒绝"或未记忆一律返回 false，
    // 让站点真正调用时走 request handler（弹询问条或直接兑现拒绝）。
    if (SENSITIVE_PAGE_PERMISSIONS.has(permission)) {
      let origin = '';
      try { origin = new URL(webContents.getURL()).origin; } catch { origin = ''; }
      return getRememberedPermission(origin, permission) === 'allow';
    }
    return ALLOWED_PERMISSIONS.has(permission);
  });

  // setPermissionRequestHandler 不覆盖 navigator.hid / serial / usb /
  // bluetooth 的"设备选择授权"——那是另一条独立回调。不设置时各版本
  // Electron 的默认行为不一致（部分版本直接放行设备选择弹窗），这里显式
  // 一律拒绝：浏览器场景下网页没有正当理由直连本机 HID / 串口 / USB 设备。
  if (typeof session.defaultSession.setDevicePermissionHandler === 'function') {
    session.defaultSession.setDevicePermissionHandler((details) => {
      let origin = '';
      try { origin = new URL(details && details.origin ? details.origin : '').origin; } catch {}
      const mediaType = (details && (details.deviceType || details.device && details.device.deviceClass)) || 'unknown-device';
      recordSecurityEvent('device-permission-blocked', 'warn',
        `网站尝试获取本机设备（${mediaType} / ${details && details.permissionType ? details.permissionType : '未知'}）`,
        origin);
      return false;
    });
  }

  // 屏幕共享（getDisplayMedia）走独立回调，setPermissionRequestHandler 不覆盖它。
  // 不设置时嵌入式视图在各 Electron 版本行为不一致，存在静默录屏风险；这里显式
  // 一律拒绝（即便内部 cosy: 页面也不放行），并按画面/仅音频/畸形分类留痕。
  if (displayGuard.isDisplayMediaHandlerAvailable(session.defaultSession)) {
    session.defaultSession.setDisplayMediaRequestHandler((request, callback) => {
      const decision = displayGuard.decideDisplayMedia(request);
      const mediaText = decision.mediaTypes.join(',') || 'unknown';
      recordSecurityEvent('display-capture-blocked', 'warn',
        `网站请求屏幕共享已拒绝（${decision.reason}；${mediaText}）`, decision.origin);
      // callback 必须回一个 video：undefined 才表示拒绝；不回会导致 Promise 悬挂。
      try { callback({ video: undefined, audio: undefined }); } catch {}
    });
  }

  // 渲染层询问条回传决策；找不到对应请求时忽略。
  // payload.remember=true 表示用户勾了"始终…"，按 origin+permission 持久化。
  ipcMain.handle('permission-response', (event, payload = {}) => {
    if (!isMainSender(event)) return { success: false };
    const { requestId, granted, remember } = payload || {};
    const entry = pendingPermissionRequests.get(String(requestId));
    if (!entry || typeof entry.finish !== 'function') return { success: false, reason: 'unknown request' };
    if (remember) rememberPermission(entry.origin, entry.permission, granted ? 'allow' : 'deny');
    entry.finish(!!granted);
    return { success: true, remembered: !!remember };
  });

  // ===== 站点权限管理页（cosy://permissions）专用 IPC，全部仅主框架可调 =====
  ipcMain.handle('list-permission-decisions', (event) => {
    if (!isMainSender(event)) return [];
    return listPermissionDecisions();
  });
  ipcMain.handle('reset-permission-decision', (event, payload = {}) => {
    if (!isMainSender(event)) return { success: false };
    const origin = String(payload.origin || '');
    const permission = String(payload.permission || '');
    if (!isRememberableOrigin(origin) || !REMEMBERED_PAGE_PERMISSIONS.has(permission)) {
      return { success: false, reason: 'invalid target' };
    }
    return { success: forgetPermission(origin, permission) };
  });
  ipcMain.handle('clear-permission-decisions', (event, payload = {}) => {
    if (!isMainSender(event)) return { success: false };
    const origin = String(payload.origin || '');
    if (!isRememberableOrigin(origin)) return { success: false, reason: 'invalid origin' };
    return { success: true, removed: clearPermissionDecisionsForOrigin(origin) };
  });

  // ===== 安全事件中心（cosy://security）只读 / 清空 IPC，仅主框架可调 =====
  ipcMain.handle('list-security-events', (event, payload = {}) => {
    if (!isMainSender(event)) return [];
    return listSecurityEvents(String(payload.type || ''), Number(payload.limit) || 200);
  });
  ipcMain.handle('clear-security-events', (event) => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, cleared: clearSecurityEvents() };
  });

  // ===== CSP 违规上报（renderer send）/ 面板读取清空（invoke），仅内部帧 =====
  // 上报用 send 而不是 invoke：违规是"通知"语义，页面不该等待也不该拿到
  // 是否被记录的回执之外的信息；这里也不回包，避免成为时序探测面。
  ipcMain.on('report-csp-violation', (event, payload) => {
    recordCspViolationFromRenderer(event.senderFrame, payload);
  });
  ipcMain.handle('list-csp-reports', (event, payload = {}) => {
    if (!isMainSender(event)) return [];
    return listCspReports(Number(payload.limit) || 200);
  });
  ipcMain.handle('clear-csp-reports', (event) => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, cleared: clearCspReports() };
  });
  ipcMain.handle('remove-csp-report', (event, payload = {}) => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, removed: removeCspReport(payload && payload.id) };
  });
  ipcMain.handle('get-csp-report-stats', (event) => {
    if (!isMainSender(event)) return { groups: 0, totalHits: 0 };
    return getCspReportStats();
  });
  ipcMain.handle('list-header-grades', (event, payload = {}) => {
    if (!isMainSender(event)) return [];
    return listHeaderGrades(Number(payload.limit) || 200);
  });
  ipcMain.handle('clear-header-grades', (event) => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, cleared: clearHeaderGrades() };
  });
  ipcMain.handle('get-header-grade-stats', (event) => {
    if (!isMainSender(event)) return { hosts: 0, byGrade: {}, insecureHosts: 0 };
    return getHeaderGradeStats();
  });

  // ===== 后台跨主机连接台账（cosy://security）IPC，仅主框架可调 =====
  ipcMain.handle('list-request-log', (event, payload = {}) => {
    if (!isMainSender(event)) return [];
    return listRequestLogEntries(Number(payload.limit) || 200);
  });
  ipcMain.handle('clear-request-log', (event) => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, cleared: clearRequestLog() };
  });
  ipcMain.handle('get-request-log-stats', (event) => {
    if (!isMainSender(event)) {
      return { hosts: 0, requests: 0, blocked: 0, backgroundHosts: 0, insecureHosts: 0 };
    }
    return getRequestLogStats();
  });

  // ===== 品牌仿冒 / 拼写劫持命中台账（cosy://security）IPC，仅主框架可调 =====
  ipcMain.handle('list-brand-spoofs', (event, payload = {}) => {
    if (!isMainSender(event)) return [];
    return listBrandSpoofEntries(Number(payload.limit) || 200);
  });
  ipcMain.handle('clear-brand-spoofs', (event) => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, cleared: clearBrandSpoofs() };
  });
  ipcMain.handle('get-brand-spoof-stats', (event) => {
    if (!isMainSender(event)) {
      return { hosts: 0, byReason: {}, distinctBrands: 0 };
    }
    return getBrandSpoofStats();
  });

  // ===== 下载完整性校验（cosy://hashes）IPC，仅主框架可调 =====
  ipcMain.handle('list-download-hashes', (event, payload = {}) => {
    if (!isMainSender(event)) return [];
    return listDownloadHashes(Number(payload.limit) || 200);
  });
  ipcMain.handle('verify-download-hash', (event, payload = {}) => {
    if (!isMainSender(event)) return { ok: false, reason: 'denied' };
    return verifyDownloadHashById(payload.id, payload.expected);
  });
  ipcMain.handle('remove-download-hash', (event, payload = {}) => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, removed: removeDownloadHashRecord(payload.id) };
  });
  ipcMain.handle('clear-download-hashes', (event) => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, cleared: clearDownloadHashes() };
  });
  ipcMain.handle('hash-local-file', (event) => {
    if (!isMainSender(event)) return { ok: false, reason: 'denied' };
    return hashLocalFileViaDialog();
  });

  // ===== 下载风险台账（cosy://security）IPC，仅主框架可调 =====
  ipcMain.handle('list-download-risks', (event, payload = {}) => {
    if (!isMainSender(event)) return [];
    return listDownloadRisks(Number(payload.limit) || 200);
  });
  ipcMain.handle('clear-download-risks', (event) => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, cleared: clearDownloadRisks() };
  });

  // ===== 链接净化（去追踪参数 / 解跳转包装），仅主框架可调 =====
  // 纯字符串处理，不触网；供安全中心的“净化复制链接”工具调用。
  ipcMain.handle('clean-share-url', (event, payload = {}) => {
    if (!isMainSender(event)) return { ok: false, reason: 'denied' };
    if (typeof payload.url !== 'string' || payload.url.length > 4096) {
      return { ok: false, reason: 'invalid-url' };
    }
    const res = urlClean.cleanShareTarget(payload.url);
    return {
      ok: true,
      url: res.url,
      changed: !!res.changed,
      unwrapped: !!res.unwrapped,
      removedKeys: Array.isArray(res.removedKeys) ? res.removedKeys.slice(0, 50) : [],
    };
  });
}

// setupGlobalWebContentsHooks 给所有 webContents 兜底：
// - 任何没被我们显式设置过 windowOpenHandler 的 webContents（扩展后台页、插件 popup、
//   未来新增的窗口等）默认 deny 弹窗，只放行我们白名单里的协议；
// - 拦 will-navigate，不允许跳到 javascript:/data:/vbscript: 这些危险 scheme；
// - beforeunload 弹确认，避免用户关标签时把没保存的表单/SQL 编辑器内容直接丢了。
function setupGlobalWebContentsHooks() {
  // GPU 进程崩溃时通知界面（Electron 14+ 的统一子进程事件）。GPU 进程通常会自动重启，
  // 这里只提示一次，避免用户面对“画面突然空白却不知道发生了什么”。
  app.on('child-process-gone', (_gpuEvent, details) => {
    if (details && details.type === 'GPU') {
      sendToRenderer('gpu-process-gone', { reason: details.reason || 'unknown' });
    }
  });

  // handleUnsafeNavigation 对主框架导航做 IDN 同形异义字 / 降级检查。
  // 返回 true 表示已拦截（调用方需 preventDefault）。block 直接挡；warn 弹原生
  // 确认，用户放弃则同样挡掉。内部页（cosy://）不参与判定。
  function handleUnsafeNavigation(targetContents, navUrl) {
    try {
      if (typeof navUrl !== 'string' || !navUrl) return false;
      if (navUrl.startsWith('cosy://') || navUrl.startsWith('about:')) return false;
      let currentUrl = '';
      try { currentUrl = targetContents.getURL(); } catch { currentUrl = ''; }
      const decision = navGuard.decideNavigation({ currentUrl, targetUrl: navUrl });
      if (decision.action === navGuard.RISK_OK) return false;

      const reasonText = [].concat(decision.reasons.host || [], decision.reasons.nav || []).join('; ');
      if (decision.action === navGuard.RISK_BLOCK) {
        recordSecurityEvent('nav-blocked', 'warn',
          `已阻止可疑导航: ${navUrl} (${reasonText})`, originOfContents(targetContents));
        sendToRenderer('show-toast', '已阻止一次可疑导航（仿冒域名或安全降级）');
        return true;
      }

      // warn：让用户在原生对话框里明确选择。
        const choice = dialog.showMessageBoxSync(mainWindow, {
          type: 'warning',
          buttons: ['返回安全页面', '仍然继续'],
          defaultId: 0,
          cancelId: 0,
          title: '安全提示：可疑的网站地址',
          message: '这个网址可能是仿冒网站或存在安全降级，是否仍要访问？',
          detail: [
            `地址：${navUrl}`,
            `原因：${reasonText || '可疑域名特征'}`,
            '',
            '该地址可能使用了与正规网站极其相似的字符，或正从不安全的明文连接加载。',
            '继续访问可能导致账号、密码等信息泄露。',
          ].join('\n'),
          noLink: true,
        });
        recordSecurityEvent('nav-warn', 'info',
          `可疑导航提示 ${choice === 1 ? '用户继续' : '用户返回'}: ${navUrl} (${reasonText})`,
          originOfContents(targetContents));
        return choice !== 1;
    } catch (guardErr) {
      // 守卫自身异常绝不能阻断正常浏览：失败放行并留痕。
      recordSecurityEvent('nav-guard-error', 'info',
        `导航守卫异常放行: ${String(guardErr && guardErr.message || guardErr)}`, '');
      return false;
    }
  }

  app.on('web-contents-created', (_event, contents) => {
    // 主窗口 UI 自己管 navigation，跳过；只给页面 tab 兜底
    if (contents === mainWindow?.webContents) return;

    // 每个页面 contents 独立维护一条服务端重定向链状态（降级/环路/钓鱼判定）。
    const redirectState = redirectGuard.createRedirectState(Date.now());
    contents.on('destroyed', () => {
      redirectChainStates.delete(contents.id);
      dialogStates.delete(contents.id);
      unloadStates.delete(contents.id);
      titleStates.delete(contents.id);
      inpageStates.delete(contents.id);
      consoleStates.delete(contents.id);
      hoverStates.delete(contents.id);
      themeStates.delete(contents.id);
      mediaStates.delete(contents.id);
      crashStates.delete(contents.id);
      cursorStates.delete(contents.id);
      entryStates.delete(contents.id);
      childWindowStates.delete(contents.id);
      frameStates.delete(contents.id);
      captureStates.delete(contents.id);
      devtoolsSwitchStates.delete(contents.id);
      remoteStates.delete(contents.id);
      ipcChannelStates.delete(contents.id);
      revokeStates.delete(contents.id);
      storageAccessStates.delete(contents.id);
    });
    redirectChainStates.set(contents.id, redirectState);
    // 顶层真正落地导航后，重定向链归零，开始统计下一条链。
    contents.on('did-navigate', () => {
      redirectGuard.resetState(redirectState, Date.now());
      // 进入新的顶层文档：强留页配额与同文档导航洪泛计数都按页面生命周期重置。
      unloadGuard.resetForNavigation(unloadStates.get(contents.id));
      inpageGuard.resetForNavigation(inpageStates.get(contents.id));
      // r32：各事件通道的洪泛/冷却配额随主导航重置（插件崩溃计数同样随文档生命周期清空）。
      consoleGuard.resetForNavigation(consoleStates.get(contents.id));
      hoverGuard.resetForNavigation(hoverStates.get(contents.id));
      themeGuard.resetForNavigation(themeStates.get(contents.id));
      mediaGuard.resetForNavigation(mediaStates.get(contents.id));
      crashGuard.resetForNavigation(crashStates.get(contents.id));
      cursorGuard.resetForNavigation(cursorStates.get(contents.id));
      entryGuard.resetForNavigation(entryStates.get(contents.id));
      // r33：换文档后子窗口 / iframe / 捕获 / DevTools 开关配额随生命周期重置。
      childWindowGuard.resetForNavigation(childWindowStates.get(contents.id));
      frameGuard.resetForNavigation(frameStates.get(contents.id), Date.now());
      captureGuard.resetForNavigation(captureStates.get(contents.id), Date.now());
      devtoolsSwitchGuard.resetForNavigation(devtoolsSwitchStates.get(contents.id), Date.now());
      remoteGuard.resetForNavigation(remoteStates.get(contents.id));
      ipcChannelGuard.resetForNavigation(ipcChannelStates.get(contents.id));
      // r34：换顶层文档后，设备撤销去重与跨框架存储访问分桶按新源重新计，避免把
      // 上一个文档的跨源桶/撤销冷却带到新页面。删除后下次事件经 getContentsState 重建。
      revokeStates.delete(contents.id);
      storageAccessStates.delete(contents.id);
    });

    // handleRedirect 在 navguard 的来源矩阵之前先做“重定向专项”判定，返回 true
    // 表示已拦截（调用方应 preventDefault）。
    const handleRedirect = (fromUrl, toUrl) => {
      let currentUrl = fromUrl || '';
      if (!currentUrl) {
        try { currentUrl = contents.getURL(); } catch {}
      }
      const verdict = redirectGuard.decideRedirect(
        redirectState, { fromUrl: currentUrl, toUrl }, Date.now());
      if (verdict.action === redirectGuard.REDIRECT_BLOCK) {
        recordSecurityEvent('redirect-blocked', 'warn',
          `危险重定向已拦截（${verdict.reasons.map(redirectGuard.describeReason).join('；')}）: ${toUrl}`,
          originOfContents(contents));
        return true;
      }
      return false;
    };

    contents.setWindowOpenHandler(({ url }) => {
      // 兜底窗口：外部协议走确认流，不允许直接 openExternal。
      const extScheme = normalizeExternalScheme(url);
      if (CONFIRMABLE_EXTERNAL_SCHEMES.has(extScheme)) {
        launchExternalWithPrompt(url, originOfContents(contents), true);
        return { action: 'deny' };
      }
      // 兜底窗口同样禁止 javascript:/data:/file: 等危险协议弹窗。
      const fallbackPopup = popupGuard.decidePopup({
        currentUrl: (() => { try { return contents.getURL(); } catch { return ''; } })(),
        targetUrl: url,
      });
      if (fallbackPopup.action === 'block') {
        recordSecurityEvent('popup-blocked', 'warn', `拦截危险协议弹窗: ${url}`, originOfContents(contents));
        return { action: 'deny' };
      }
      if (!isSafeUrl(url)) return { action: 'deny' };
      // 从 tab 里点 _blank 的，统一丢回我们的 createNewTab
      setImmediate(() => createNewTab(url));
      return { action: 'deny' };
    });

    // navigator.bluetooth.requestDevice 的设备选择事件。无人监听时部分平台会
    // 自动选中枚举到的第一个蓝牙设备继续配对，等于把本机蓝牙设备暴露给网页；
    // 这里显式 callback('') 取消选择并留痕。
    contents.on('select-bluetooth-device', (btEvent, btDevices, btCallback) => {
      try { btEvent.preventDefault(); } catch {}
      const verdict = displayGuard.decideBluetoothSelection({
        url: (() => { try { return contents.getURL(); } catch { return ''; } })(),
        devices: btDevices,
      });
      recordSecurityEvent('bluetooth-blocked', 'warn',
        `网站请求蓝牙设备已取消（枚举 ${verdict.deviceCount} 台）`, verdict.origin);
      try { btCallback(''); } catch {}
    });

    // 串口 / HID / USB 的“设备选择”回调与蓝牙同理：不监听时部分平台会自动选中枚举到
    // 的第一个设备。网页没有理由独占本机串口/HID/USB（U 盾、键盘、烧录器等），统一
    // 显式取消选择（callback('')），绝不依赖默认行为。
    const contentsOriginUrl = () => {
      try { return contents.getURL(); } catch { return ''; }
    };
    contents.on('select-serial-port', (seEvent, portList, _seWc, seCallback) => {
      try { seEvent.preventDefault(); } catch {}
      const v = devicerGuard.decideDeviceChooser({
        kind: devicerGuard.KIND_SERIAL, originUrl: contentsOriginUrl(), portList,
      });
      recordSecurityEvent('serial-blocked', 'warn',
        `网站请求${devicerGuard.describeKind(v.kind)}设备已取消（枚举 ${v.deviceCount} 台）`, v.origin);
      try { seCallback(''); } catch {}
    });
    contents.on('select-hid-device', (hidEvent, hidDetails, hidCallback) => {
      try { hidEvent.preventDefault(); } catch {}
      const v = devicerGuard.decideDeviceChooser({
        kind: devicerGuard.KIND_HID, originUrl: contentsOriginUrl(), details: hidDetails,
      });
      recordSecurityEvent('hid-blocked', 'warn',
        `网站请求${devicerGuard.describeKind(v.kind)}设备已取消（枚举 ${v.deviceCount} 台）`, v.origin);
      try { hidCallback(''); } catch {}
    });
    contents.on('select-usb-device', (usbEvent, usbDetails, usbCallback) => {
      try { usbEvent.preventDefault(); } catch {}
      const v = devicerGuard.decideDeviceChooser({
        kind: devicerGuard.KIND_USB, originUrl: contentsOriginUrl(), details: usbDetails,
      });
      recordSecurityEvent('usb-blocked', 'warn',
        `网站请求${devicerGuard.describeKind(v.kind)}设备已取消（枚举 ${v.deviceCount} 台）`, v.origin);
      try { usbCallback(''); } catch {}
    });

    // 本浏览器用 WebContentsView 承载页面，从不使用 <webview> 标签。
    // 若有页面尝试 attach webview，一律阻止：webview 默认能携带自己的
    // webPreferences（nodeIntegration/disablewebsecurity），是常见提权通道。
    contents.on('will-attach-webview', (attachEvent, webPreferences, params) => {      // 完整的 webview 挂载审计：src 仅允许远程 http(s)，guest 自带 preload /
      // Node 集成 / 关闭安全开关 / 挂载主会话分区等一律收口（见 webviewharden.js）。
      const verdict = webviewHarden.review(webPreferences, params);
      if (verdict.reasons.length) {
        recordSecurityEvent('webview-blocked', verdict.blocked ? 'warn' : 'info',
          `webview 挂载审计: ${verdict.reasons.map(webviewHarden.describeReason).join('；')}`,
          originOfContents(contents));
      }
      if (verdict.blocked) {
        attachEvent.preventDefault();
        return;
      }
      // src 合法时也用安全基线整体覆盖 guest 配置，杜绝任何残留提权项。
      for (const key of Object.keys(webPreferences)) delete webPreferences[key];
      Object.assign(webPreferences, verdict.prefs);
    });

    // 主框架导航：http(s)/file/cosy 放行，mailto/tel 走按站点记忆的确认弹窗，
    // 其它外部协议（ms-*:/smb:/vbscript: 等）直接阻止。
    contents.on('will-navigate', (navEvent, url) => {
      // 来源矩阵：远程网页 / data / blob 等不可信上下文不得把顶层框架顶到
      // file:// 本地资源或 cosy: 特权内部页（地址栏 loadURL 不触发本事件，
      // 故浏览器自身打开本地文件不受影响）。
      let navInitiator = '';
      try { navInitiator = contents.getURL(); } catch {}
      try {
        const boundary = schemeOrigin.evaluate(url, navInitiator);
        if (boundary.action === 'block') {
          recordSecurityEvent('origin-boundary-blocked', 'warn',
            `${schemeOrigin.describeBlock(boundary.reason)}: ${String(url).slice(0, 200)}`,
            navInitiator);
          sendToRenderer('show-toast', '已阻止网页导航到本地文件或浏览器内部页面');
          navEvent.preventDefault();
          return;
        }
      } catch { /* 判定异常不干预，交后续链路 */ }
      // 导航安全：IDN 同形异义字钓鱼 / 混合脚本域名直接拦；整词同形 / Punycode
      // 与 HTTPS→HTTP 同站降级弹原生确认；跨主机 http 降级直接拦。
      if (handleUnsafeNavigation(contents, url)) {
        navEvent.preventDefault();
        return;
      }
      if (handleFrameNavigationAttempt(contents, url, true)) {
        navEvent.preventDefault();
      }
    });

    // 子框架导航：这是历史代码漏掉的面——iframe src="ms-word:.." 或子框架 302
    // 到外部协议同样能唤起本机程序。子框架只允许纯 Web 协议，其余一律取消。
    contents.on('will-frame-navigate', (frameEvent, url, isMainFrame) => {
      // 主框架导航已由上面的 will-navigate 统一处理（它还要更新地址栏 / 历史），
      // 这里只接管子框架，否则一次导航会弹两次确认框。
      if (isMainFrame) return;
      if (handleFrameNavigationAttempt(contents, url, false)) {
        frameEvent.preventDefault();
      }
    });

    // 页内查找结果转发：findInPage 只会作用于活动标签，所以这里也只把
    // 当前活动 webContents 的匹配结果送回主界面，更新“第 x / y 个匹配”。
    // 非活动标签的结果直接忽略，避免后台标签覆盖计数。
    contents.on('found-in-page', (_findEvent, result) => {
      if (contents !== getCurrentTabWebContents()) return;
      sendToRenderer('found-in-page-result', {
        activeMatchOrdinal: result.activeMatchOrdinal || 0,
        matches: result.matches || 0,
      });
    });

    // 服务端 302 也可能把框架重定向到外部协议（下载站常见手法）。
    // will-redirect 覆盖主框架；will-frame-redirect 覆盖子框架（旧 Electron
    // 没有该事件时监听器静默不生效，主框架面仍被兜住）。
    // 先走重定向专项守卫（降级/环路/钓鱼/危险 scheme），再走 navguard 来源矩阵。
    contents.on('will-redirect', (redirectEvent, url, isRedirect) => {
      if (handleRedirect('', url)) {
        redirectEvent.preventDefault();
        return;
      }
      if (handleFrameNavigationAttempt(contents, url, true)) {
        redirectEvent.preventDefault();
      }
    });

    contents.on('will-frame-redirect', (redirectEvent, url, isMainFrame) => {
      if (isMainFrame) return;
      if (handleRedirect('', url)) {
        redirectEvent.preventDefault();
        return;
      }
      if (handleFrameNavigationAttempt(contents, url, false)) {
        redirectEvent.preventDefault();
      }
    });

    // ===== 渲染进程崩溃 / 卡死恢复 =====
    // 现代浏览器在某个标签的渲染进程崩溃后会给横幅而不是整窗静默死掉。
    // 崩溃 / OOM 自动重载“一次”（第二次不再自动，避免崩溃循环把 CPU 打满），
    // 被系统杀死(killed)不自动重载；无响应时给横幅让用户选“等待 / 强制刷新”。
    contents.on('render-process-gone', (_goneEvent, details) => {
      const tab = tabs.find(t => t.view && t.view.webContents === contents);
      let goneUrl = tab?.url || '';
      if (!goneUrl) {
        try { goneUrl = contents.getURL(); } catch {}
      }
      // 用 goneguard 做窗口内有界定速 + 冷却 + 熔断，并禁止自动重载 data:/blob:
      // 等瞬时上下文（见 goneguard.js），替代旧的“只重载一次”裸计数。
      const now = Date.now();
      let goneState = crashReloadCounts.get(contents.id);
      if (!goneState) {
        goneState = goneGuard.createState(now);
        crashReloadCounts.set(contents.id, goneState);
      }
      const decision = goneGuard.decideReload(goneState, goneUrl, now);
      const recoverable = details.reason === 'crashed' || details.reason === 'oom';
      const payload = {
        tabId: contents.id,
        reason: details.reason || 'unknown',
        exitCode: typeof details.exitCode === 'number' ? details.exitCode : null,
        url: goneUrl,
        title: tab?.title || '',
        autoReloaded: false,
        recovery: decision.reason,
      };
      if (crashRecoveryEnabled && recoverable && decision.action === 'reload' &&
          !contents.isDestroyed()) {
        payload.autoReloaded = true;
        setTimeout(() => {
          if (!contents.isDestroyed()) contents.reload();
        }, 400);
      } else if (decision.action === 'error-page') {
        // 熔断 / 限频 / 不可重载上下文：留痕，界面据此显示手动恢复横幅。
        recordSecurityEvent('renderer-gone', 'info',
          `${goneGuard.describeReason(decision.reason)}（${details.reason || 'unknown'}）`,
          goneUrl);
      }
      sendToRenderer('renderer-gone', payload);
    });

    // 页面恢复正常后，把该标签的崩溃处置状态清零，给下次真正的崩溃留出恢复额度。
    contents.on('did-finish-load', () => crashReloadCounts.delete(contents.id));

    contents.on('unresponsive', () => {
      // 无响应事件在卡死期间会连续触发，用 goneguard 冷却去抖，避免横幅轰炸。
      const now = Date.now();
      let goneState = crashReloadCounts.get(contents.id);
      if (!goneState) {
        goneState = goneGuard.createState(now);
        crashReloadCounts.set(contents.id, goneState);
      }
      const verdict = goneGuard.decideUnresponsive(goneState, now);
      if (verdict.notify) {
        sendToRenderer('renderer-unresponsive', { tabId: contents.id });
      }
    });
    contents.on('responsive', () => {
      sendToRenderer('renderer-responsive', { tabId: contents.id });
    });

    // JS 模态框（alert/confirm/prompt）轰炸收口：滑动窗口配额 + 同文案去抖 + 冷却。
    // beforeunload 类型不在这里处理，交给下方 will-prevent-unload 的 unloadguard。
    contents.on('dialog', (event, type, url, text) => {
      if (dialogGuard.isBeforeUnload(type)) return;
      const st = getContentsState(dialogStates, contents.id, dialogGuard.createDialogState);
      const v = dialogGuard.decideDialog(
        st,
        { type, message: text, originUrl: url || originOfContents(contents) },
        Date.now()
      );
      if (v.decision === dialogGuard.DIALOG_SUPPRESS) {
        event.preventDefault();
        const severity = v.reason === dialogGuard.SUPPRESS_DUPLICATE ? 'info' : 'warn';
        recordSecurityEvent('dialog-blocked', severity,
          dialogGuard.describeDialogReason(v.reason), v.origin || originOfContents(contents));
      }
    });

    // 页面调 window.close() 之前触发的 beforeunload。unloadguard 给真实“未保存修改”
    // 保留每页面几次确认额度；恶意页反复强留则越限后直接放行关闭/导航（不再弹模态）。
    contents.on('will-prevent-unload', (event) => {
      const st = getContentsState(unloadStates, contents.id, unloadGuard.createUnloadState);
      const v = unloadGuard.decideUnload(st, Date.now());
      if (v.decision === unloadGuard.UNLOAD_LEAVE) {
        // 不调用 preventDefault：尊重用户的关闭/导航意图，页面照常卸载。
        recordSecurityEvent('unload-bypass', 'warn',
          unloadGuard.describeUnloadReason(v.reason), originOfContents(contents));
        return;
      }
      event.preventDefault();
      const choice = dialog.showMessageBoxSync(mainWindow, {
        type: 'question',
        buttons: ['离开此页', '留在此页'],
        defaultId: 1,
        cancelId: 1,
        title: '确认离开',
        message: '您有尚未保存的更改。确定要离开此页面吗？'
      });
      if (choice === 0) {
        contents.destroy();
      }
    });

    // ===== 全屏 / 键盘锁 / 打印 / 缩放 / DevTools 链接收口（每 contents 独立状态）=====
    const fsState = fullscreenGuard.createFullscreenState(Date.now());
    const printState = printGuard.createPrintState(Date.now());
    const zoomState = zoomGuard.createZoomState(Date.now());
    const preloadErrState = preloadGuard.createPreloadErrorState(Date.now());
    let zoomFlushTimer = null;

    const currentContentsUrl = () => {
      try { return contents.getURL(); } catch { return ''; }
    };
    const broadcastZoomLevel = (level) => {
      try {
        sendToRenderer('zoom-level-changed', {
          percent: zoomGuard.zoomLevelToPercent(level),
          factor: Math.pow(1.2, level),
        });
      } catch {}
    };

    contents.on('enter-html-full-screen', () => {
      const r = fullscreenGuard.noteEnter(fsState, Date.now(), currentContentsUrl());
      if (r.abusive) {
        recordSecurityEvent('fullscreen-abuse', 'warn',
          fullscreenGuard.describeAbuse(fullscreenGuard.ABUSE_FLICKER), originOfContents(contents));
      }
    });
    contents.on('leave-html-full-screen', () => {
      const r = fullscreenGuard.noteLeave(fsState, Date.now());
      if (r.abusive) {
        recordSecurityEvent('fullscreen-abuse', 'warn',
          fullscreenGuard.describeAbuse(fullscreenGuard.ABUSE_FLICKER), originOfContents(contents));
      }
    });

    // 键盘锁只在该内容确处全屏时放行；窗口态请求（Esc/快捷键劫持起手式）一律阻止。
    contents.on('keyboard-lock', (event) => {
      const v = fullscreenGuard.decideKeyboardLock(
        fsState, { originUrl: currentContentsUrl() }, Date.now());
      if (v.decision === fullscreenGuard.KEYBOARD_DENY) {
        event.preventDefault();
        recordSecurityEvent('keyboard-lock-blocked', 'warn',
          fullscreenGuard.describeKeyboardReason(v.reason), v.origin || originOfContents(contents));
      }
    });

    // window.print() 打印轰炸：滑动窗口配额 + 冷却，越限抑制内置打印流程。
    contents.on('print', (event) => {
      const v = printGuard.decidePrint(printState, { originUrl: currentContentsUrl() }, Date.now());
      if (v.decision === printGuard.PRINT_SUPPRESS) {
        event.preventDefault();
        recordSecurityEvent('print-blocked', 'warn',
          printGuard.describePrintReason(v.reason), v.origin || originOfContents(contents));
      }
    });

    // ctrl+滚轮缩放：量化/钳制级别，合并滚轮抖动的 IPC 广播，洪泛时暂停并留痕，
    // 平息后用一个 trailing 定时器补发最终级别（OSD 百分比不丢）。
    contents.on('zoom-changed', () => {
      let level = 0;
      try { level = contents.getZoomLevel(); } catch { level = 0; }
      const v = zoomGuard.applyZoomChange(zoomState, { level }, Date.now());
      if (v.flooded) {
        recordSecurityEvent('zoom-flood', 'info',
          zoomGuard.describeHoldReason(zoomGuard.HOLD_FLOODED), originOfContents(contents));
      }
      if (v.action === zoomGuard.ACTION_BROADCAST) {
        broadcastZoomLevel(v.level);
        return;
      }
      if (zoomFlushTimer) return;
      zoomFlushTimer = setTimeout(() => {
        zoomFlushTimer = null;
        const f = zoomGuard.flushPendingZoom(zoomState, Date.now());
        if (f.action === zoomGuard.ACTION_BROADCAST) broadcastZoomLevel(f.level);
      }, zoomGuard.ZOOM_BROADCAST_MIN_INTERVAL_MS + 5);
    });

    // DevTools 内点击链接：http/https/cosy 一律转应用内新标签页（绝不走系统外壳），
    // file/data/javascript 及任意外部应用协议直接拦截。
    contents.on('devtools-open-url', (event, url) => {
      const v = devtoolsGuard.decideDevToolsUrl(url);
      event.preventDefault();
      if (v.action === devtoolsGuard.ACTION_OPEN_TAB) {
        createNewTab(v.url);
      } else {
        recordSecurityEvent('devtools-url-blocked', 'warn',
          devtoolsGuard.describeDevToolsReason(v.reason), originOfContents(contents));
      }
    });

    contents.on('destroyed', () => {
      if (zoomFlushTimer) {
        clearTimeout(zoomFlushTimer);
        zoomFlushTimer = null;
      }
    });

    // preload 承载 IPC 白名单与 contextBridge 安全桥：加载/运行期抛错意味着安全包装
    // 可能残缺，必须按严重度留痕，并对同指纹/同标签页错误去重限流，防止错误循环刷爆日志。
    contents.on('preload-error', (event, preloadPath, error) => {
      const v = preloadGuard.decidePreloadError(
        preloadErrState,
        { preloadPath: String(preloadPath || ''), error, originUrl: currentContentsUrl() },
        Date.now());
      if (v.decision === preloadGuard.DECISION_REPORT) {
        recordSecurityEvent('preload-error', v.severity,
          preloadGuard.describePreloadError(v), v.origin || originOfContents(contents));
      }
    });

    // ===== r32：控制台 / 悬停状态栏 / 主题色 / 媒体 / 插件崩溃 / 光标 / 历史条目收口 =====
    // 说明：这些通道此前完全没有接线，页面可借其注入脏文本或打爆事件流。下列内核均为
    // per-contents 纯函数裁决；为避免“限流处理器自己刷爆安全日志”，只在“洪泛阈值首次
    // 越线”或“崩溃需要提示”这两个有界时刻 recordSecurityEvent，冷却期内的重复丢弃不记。

    // console-message：净化换行/ANSI/零宽与超长行，突发/长窗口越限后冷却丢弃。
    contents.on('console-message', (event, level, message, line, sourceId) => {
      const st = getContentsState(consoleStates, contents.id, consoleGuard.createConsoleState);
      const v = consoleGuard.decideConsole(
        st, { level, message, line, sourceId }, Date.now());
      if (v.action === consoleGuard.CONSOLE_DROP && v.reason === consoleGuard.CS_FLOOD) {
        recordSecurityEvent('console-flood', 'info',
          consoleGuard.describeConsoleReason(v.reason), originOfContents(contents));
      }
    });

    // update-target-url：悬停链接状态栏预告。只在裁决 show 时把净化后的 URL 推给渲染层
    // 显示；洪泛首次越线时清空状态栏（不残留伪造地址）并留痕，冷却期重复丢弃不再记。
    contents.on('update-target-url', (event, url) => {
      const st = getContentsState(hoverStates, contents.id, hoverGuard.createHoverState);
      const v = hoverGuard.decideHoverUrl(st, url, Date.now());
      if (v.action === hoverGuard.HOVER_SHOW) {
        try { sendToRenderer('target-url-changed', { url: v.url }); } catch {}
      } else if (v.action === hoverGuard.HOVER_DROP && v.reason === hoverGuard.DROP_FLOOD) {
        try { sendToRenderer('target-url-changed', { url: '' }); } catch {}
        recordSecurityEvent('hover-flood', 'warn',
          hoverGuard.describeHoverReason(v.reason), originOfContents(contents));
      }
    });

    // did-change-theme-color：只接受白名单颜色，高频闪烁（伪装浏览器顶栏）越限后锁定。
    contents.on('did-change-theme-color', (event, color) => {
      const st = getContentsState(themeStates, contents.id, themeGuard.createThemeState);
      const v = themeGuard.decideThemeColor(st, color, Date.now());
      if (v.action === themeGuard.THEME_DROP && v.reason === themeGuard.DROP_FLOOD) {
        recordSecurityEvent('theme-abuse', 'warn',
          themeGuard.describeThemeReason(v.reason), originOfContents(contents));
      }
    });

    // media-started-playing / media-paused：自动播放风暴/媒体键抖动收敛，维护真实播放态。
    contents.on('media-started-playing', () => {
      const st = getContentsState(mediaStates, contents.id, mediaGuard.createMediaState);
      const v = mediaGuard.decideMediaEvent(st, mediaGuard.MEDIA_STARTED, Date.now());
      if (v.action === mediaGuard.MEDIA_DROP && v.reason === mediaGuard.DROP_FLOOD) {
        recordSecurityEvent('media-flood', 'warn',
          mediaGuard.describeMediaReason(v.reason), originOfContents(contents));
      }
    });
    contents.on('media-paused', () => {
      const st = getContentsState(mediaStates, contents.id, mediaGuard.createMediaState);
      const v = mediaGuard.decideMediaEvent(st, mediaGuard.MEDIA_PAUSED, Date.now());
      if (v.action === mediaGuard.MEDIA_DROP && v.reason === mediaGuard.DROP_FLOOD) {
        recordSecurityEvent('media-flood', 'warn',
          mediaGuard.describeMediaReason(v.reason), originOfContents(contents));
      }
    });

    // plugin-crashed：净化插件名/版本（防日志注入），同一插件 30s 内的崩溃循环折叠为
    // 一次提示，折叠达上限强制汇总，计数天然有界，不会逐次弹窗/逐行刷日志。
    contents.on('plugin-crashed', (event, name, version) => {
      const st = getContentsState(crashStates, contents.id, crashGuard.createCrashState);
      const v = crashGuard.decidePluginCrash(st, name, version, Date.now());
      if (v.action === crashGuard.CRASH_NOTIFY) {
        const extra = v.suppressedSinceLastNotify > 0
          ? `（已折叠此前 ${v.suppressedSinceLastNotify} 次重复崩溃）`
          : '';
        recordSecurityEvent('plugin-crash', 'warn',
          `插件 ${v.name} ${v.version} 崩溃${extra}`, originOfContents(contents));
      }
    });

    // cursor-changed：类型白名单 + 自定义光标位图边长/字节/缩放校验 + 抖动洪泛冷却；
    // 任何非法/越限都回落 default 光标，避免超大位图 IPC 与高频切换 DoS。
    contents.on('cursor-changed', (event, type, image, scale) => {
      const st = getContentsState(cursorStates, contents.id, cursorGuard.createCursorState);
      let imageInfo = null;
      if (type === 'custom' && image && typeof image.getSize === 'function') {
        try {
          const size = image.getSize();
          let bytes = 0;
          try { const bmp = image.getBitmap(); bytes = Buffer.isBuffer(bmp) ? bmp.length : 0; } catch {}
          imageInfo = { width: size && size.width, height: size && size.height, bytes };
        } catch {
          imageInfo = null;
        }
      }
      const v = cursorGuard.decideCursorChange(st, type, imageInfo, scale, Date.now());
      // 非法类型/位图/缩放或抖动越限统一回落 default：Electron 不暴露逐事件设置光标的
      // 稳定 API，这里通过有界裁决丢弃异常事件流，仅在首次越线时留痕，避免处理器自身刷日志。
      if (v.action === cursorGuard.CURSOR_DROP && v.reason === cursorGuard.DROP_FLOOD) {
        recordSecurityEvent('cursor-abuse', 'warn',
          cursorGuard.describeCursorReason(v.reason), originOfContents(contents));
      }
    });

    // navigation-entry-committed：地址栏据此显示最终 URL，先净化脏文本，再对历史条目
    // 提交频率（pushState 历史劫持/洪泛）做滑动窗口裁决，越限冷却并冻结地址栏刷新。
    contents.on('navigation-entry-committed', (event, url) => {
      const st = getContentsState(entryStates, contents.id, entryGuard.createEntryState);
      const v = entryGuard.decideNavigationEntry(st, url, Date.now());
      if (v.action === entryGuard.ENTRY_DROP && v.reason === entryGuard.DROP_FLOOD) {
        recordSecurityEvent('entry-flood', 'warn',
          entryGuard.describeEntryReason(v.reason), originOfContents(contents));
      }
    });

    // r33：意外原生子窗口收口。setWindowOpenHandler 恒 deny 后仍可能有少数路径真正
    // new 出原生 BrowserWindow；这里核对其 webPreferences 基线与首屏地址，提权 / 危险
    // 协议 / 开窗洪泛直接销毁，幸存的 http(s) 子窗标记为隔离并留痕。
    contents.on('did-create-window', (childWindow, details) => {
      try {
        const openerSt = getContentsState(
          childWindowStates, contents.id, childWindowGuard.createChildWindowState);
        let childContents = null;
        try {
          childContents = childWindow && childWindow.webContents ? childWindow.webContents : null;
        } catch {}
        let prefs = null;
        try {
          if (childContents && typeof childContents.getLastWebPreferences === 'function') {
            prefs = childContents.getLastWebPreferences();
          }
        } catch {}
        let childUrl = '';
        try {
          childUrl = (childContents && childContents.getURL()) || (details && details.url) || '';
        } catch {}
        const verdict = childWindowGuard.evaluateChildWindow(
          { url: childUrl, prefs, openerPresent: true }, openerSt, Date.now());
        if (verdict.action === childWindowGuard.CHILD_CLOSE) {
          recordSecurityEvent('child-window-blocked', 'warn',
            `意外子窗口已销毁（${verdict.reasons.join('；')}）: ${String(childUrl).slice(0, 200)}`,
            originOfContents(contents));
          try { childWindow.destroy(); } catch {}
          return;
        }
        if (verdict.action === childWindowGuard.CHILD_ISOLATE) {
          if (childContents) isolatedChildContents.add(childContents);
          recordSecurityEvent('child-window-blocked', 'info',
            `意外子窗口按隔离基线保留（${verdict.reasons.join('；')}）`,
            verdict.origin || originOfContents(contents));
        }
      } catch (err) {
        recordSecurityEvent('child-window-blocked', 'info',
          `子窗口守卫异常: ${String((err && err.message) || err)}`, originOfContents(contents));
      }
    });

    // r33：frame-created 观测每个框架创建。该事件无法阻止框架落地，这里负责把危险
    // 协议子框架 / 畸形 URL / iframe 爆炸统一留痕，真正的危险导航仍由 will-frame-navigate
    // 与 CSP 兜底；洪泛折叠为单条 info，避免刷爆审计。
    contents.on('frame-created', (event, frame) => {
      try {
        const st = getContentsState(frameStates, contents.id, frameGuard.createFrameState);
        const v = frameGuard.evaluateFrame(frame, st, Date.now());
        if (v.action === frameGuard.FRAME_DROP && v.reasons.length > 0) {
          const sev = v.reasons.includes('frame-flood') ? 'info' : 'warn';
          const tail = frame && frame.url ? ': ' + String(frame.url).slice(0, 200) : '';
          recordSecurityEvent('frame-blocked', sev,
            `子框架事件异常（${v.reasons.join('；')}）${tail}`,
            v.origin || originOfContents(contents));
        }
      } catch (err) {
        recordSecurityEvent('frame-blocked', 'info',
          `框架守卫异常: ${String((err && err.message) || err)}`, originOfContents(contents));
      }
    });

    // r33：screen-capture-changed 让“某个标签真的进入屏幕/窗口捕获态”可见：任何进入
    // 捕获（start / 未停先换句柄）都亮留痕，畸形 / 高频切换事件被折叠，避免网页静默录屏。
    contents.on('screen-capture-changed', (event, id, captureInfo) => {
      try {
        const st = getContentsState(captureStates, contents.id, captureGuard.createCaptureState);
        const v = captureGuard.evaluateCaptureChange(st, id, captureInfo, Date.now());
        if (v.action === captureGuard.CAPTURE_SIGNAL) {
          if (v.phase === 'started' || v.phase === 'replaced') {
            const audio = v.hasAudio ? '含音频' : '无音频';
            recordSecurityEvent('screen-capture-active', 'warn',
              v.phase === 'replaced'
                ? `屏幕捕获句柄被替换（${audio}），该标签可能持续被录制`
                : `标签进入屏幕/窗口捕获态（${audio}），请注意录屏提示`,
              originOfContents(contents));
          }
        } else if (v.action === captureGuard.CAPTURE_DROP) {
          recordSecurityEvent('screen-capture-active', 'info',
            `屏幕捕获状态事件异常已忽略（${v.reasons.join('；')}）`, originOfContents(contents));
        }
      } catch (err) {
        recordSecurityEvent('screen-capture-active', 'info',
          `捕获状态守卫异常: ${String((err && err.message) || err)}`, originOfContents(contents));
      }
    });

    // r33：devtools-opened/closed 收口调试通道本身。隔离子窗口按基线不该有 DevTools，
    // 一旦被打开立即关闭并告警；普通标签打开 DevTools 只留痕（不阻断开发者），高频
    // 开关（自动化 / 环境探测）折叠冷却。
    contents.on('devtools-opened', () => {
      try {
        const st = getContentsState(
          devtoolsSwitchStates, contents.id, devtoolsSwitchGuard.createDevtoolsState);
        const isIso = isolatedChildContents.has(contents);
        const v = devtoolsSwitchGuard.evaluateDevtoolsToggle(
          st, 'opened', { isIsolatedChild: isIso }, Date.now());
        if (v.action === devtoolsSwitchGuard.DEVTOOLS_CLOSE) {
          recordSecurityEvent('devtools-switch', 'warn',
            '按基线不应具备 DevTools 的隔离窗口被打开开发者工具，已立即关闭',
            originOfContents(contents));
          try { contents.closeDevTools(); } catch {}
        } else if (v.action === devtoolsSwitchGuard.DEVTOOLS_AUDIT) {
          recordSecurityEvent('devtools-switch', 'info',
            '该标签打开了开发者工具：请勿在控制台粘贴来源不明的代码',
            originOfContents(contents));
        }
      } catch (err) {
        recordSecurityEvent('devtools-switch', 'info',
          `DevTools 开关守卫异常: ${String((err && err.message) || err)}`, originOfContents(contents));
      }
    });
    contents.on('devtools-closed', () => {
      const st = devtoolsSwitchStates.get(contents.id);
      if (st) devtoolsSwitchGuard.evaluateDevtoolsToggle(st, 'closed', {}, Date.now());
    });

    // r33：@electron/remote 反向桥与 desktopCapturer 枚举深度防御。浏览器场景不启用
    // remote，任何一个这些事件触发都意味着提权面被打开——统一 preventDefault 拒绝，
    // 并把目标模块/全局名净化后按高危留痕；高频尝试折叠冷却。
    const installRemoteBlocker = (channel, isNamed) => {
      contents.on(channel, (event, target) => {
        try {
          const st = getContentsState(remoteStates, contents.id, remoteGuard.createRemoteState);
          const v = remoteGuard.evaluateRemoteBridge(
            { channel, target: isNamed ? target : undefined }, st, Date.now());
          event.preventDefault();
          const sev = v.reasons.includes('remote-bridge-flood') ? 'info' : 'warn';
          const tail = isNamed && v.target ? `（目标: ${v.target}）` : '';
          recordSecurityEvent('remote-bridge-blocked', sev,
            `远程桥通道 ${v.channel} 已被浏览器策略阻止${tail}`, originOfContents(contents));
        } catch (err) {
          try { event.preventDefault(); } catch {}
          recordSecurityEvent('remote-bridge-blocked', 'warn',
            `远程桥守卫异常: ${String((err && err.message) || err)}`, originOfContents(contents));
        }
      });
    };
    installRemoteBlocker(remoteGuard.REMOTE_CHANNELS.REQUIRE, true);
    installRemoteBlocker(remoteGuard.REMOTE_CHANNELS.GET_BUILTIN, true);
    installRemoteBlocker(remoteGuard.REMOTE_CHANNELS.GET_GLOBAL, true);
    installRemoteBlocker(remoteGuard.REMOTE_CHANNELS.GET_CURRENT_WINDOW, false);
    installRemoteBlocker(remoteGuard.REMOTE_CHANNELS.GET_CURRENT_WEB_CONTENTS, false);
    installRemoteBlocker(remoteGuard.REMOTE_CHANNELS.DESKTOP_CAPTURER, false);

    // r33：渲染层“直发原始 IPC”收口。正常业务只走 contextBridge 白名单 API；若网页在
    // contextIsolation 被绕过 / preload 残缺时直接 ipcRenderer.send 未授权通道，这里拦截。
    // invoke 走内部通道不触发本事件，故白名单只列 send 通道。
    contents.on('ipc-message', (event, channel, ...args) => {
      try {
        const st = getContentsState(
          ipcChannelStates, contents.id, ipcChannelGuard.createIpcChannelState);
        const v = ipcChannelGuard.evaluateIpcChannel(
          { channel, kind: ipcChannelGuard.IPC_ASYNC, argsLength: args.length },
          RAW_IPC_SEND_ALLOWED, st, Date.now());
        if (v.action === ipcChannelGuard.IPC_BLOCK) {
          event.preventDefault();
          recordSecurityEvent('raw-ipc-blocked', 'warn',
            `渲染层直发未授权/异常原始 IPC 通道 ${v.channel}（${v.reasons.join('；')}）`,
            originOfContents(contents));
        }
      } catch (err) {
        recordSecurityEvent('raw-ipc-blocked', 'info',
          `原始 IPC 守卫异常: ${String((err && err.message) || err)}`, originOfContents(contents));
      }
    });
    // sendSync 白名单为空，任何同步直发都阻止，并回一个安全值，避免网页拿到 undefined
    // 后逻辑异常，同时杜绝同步消息阻塞主进程的拒绝服务。
    contents.on('ipc-message-sync', (event, channel, ...args) => {
      try {
        const st = getContentsState(
          ipcChannelStates, contents.id, ipcChannelGuard.createIpcChannelState);
        const v = ipcChannelGuard.evaluateIpcChannel(
          { channel, kind: ipcChannelGuard.IPC_SYNC, argsLength: args.length },
          RAW_IPC_SYNC_ALLOWED, st, Date.now());
        if (v.action === ipcChannelGuard.IPC_BLOCK) {
          event.preventDefault();
          try { event.returnValue = null; } catch {}
          recordSecurityEvent('raw-ipc-blocked', 'warn',
            `渲染层同步 IPC（sendSync）被禁止 ${v.channel}（${v.reasons.join('；')}）`,
            originOfContents(contents));
        }
      } catch (err) {
        try { event.preventDefault(); event.returnValue = null; } catch {}
        recordSecurityEvent('raw-ipc-blocked', 'warn',
          `同步 IPC 守卫异常: ${String((err && err.message) || err)}`, originOfContents(contents));
      }
    });

    // ===== r34：设备授权撤销 + 跨框架存储/缓存访问收口 =====
    // hid/serial/bluetooth 的 *-revoked 事件此前 0 监听：授权被用户收回 / 设备掉线
    // 完全无留痕，且可被“申请—掉线—再申请”抖动刷成事件洪泛。统一走 revokeGuard
    // 按 源+类别+设备 时间窗去重，仅在窗口外落一条审计。
    const handleDeviceRevoked = (kind, device) => {
      try {
        const st = getContentsState(revokeStates, contents.id, revokeGuard.createRevokeState);
        const v = revokeGuard.decideRevocation(
          st, { kind, originUrl: currentContentsUrl(), device }, Date.now());
        if (v.action === revokeGuard.ACTION_RECORD) {
          recordSecurityEvent('device-authorization-revoked', 'info',
            v.detail, v.origin || originOfContents(contents));
        }
      } catch (err) {
        recordSecurityEvent('device-authorization-revoked', 'info',
          `设备撤销守卫异常: ${String((err && err.message) || err)}`, originOfContents(contents));
      }
    };
    contents.on('hid-device-revoked', (_e, device) => {
      handleDeviceRevoked(revokeGuard.KIND_HID, device);
    });
    contents.on('serial-port-revoked', (_e, port) => {
      // serial 撤销回调给的是端口对象，可能带 portName / usbVendorId / usbProductId。
      handleDeviceRevoked(revokeGuard.KIND_SERIAL, port);
    });
    contents.on('bluetooth-device-revoked', (_e, deviceId) => {
      // 蓝牙撤销给的是 deviceId 字符串，包一层成内核期望的 device 形状。
      handleDeviceRevoked(revokeGuard.KIND_BLUETOOTH,
        typeof deviceId === 'string' ? { deviceId } : {});
    });

    // seen-session-storage-data-access / seen-cache-storage-data-access 是观测型事件
    // （不可 preventDefault）。价值在于发现“跨站子框架读写顶层存储”与高频存储事件洪泛。
    // 只在“跨源桶首次”与“窗内越限”两个有界时刻留痕，避免观测处理器自己刷爆日志。
    const handleStorageDataAccess = (kind, details) => {
      try {
        const st = getContentsState(
          storageAccessStates, contents.id, storageAccessGuard.createStorageAccessState);
        let frameUrl = '';
        try { frameUrl = details && details.frame && details.frame.url ? details.frame.url : ''; } catch {}
        const topUrl = currentContentsUrl();
        const storageType = kind === storageAccessGuard.KIND_CACHE
          ? (details && details.cacheType) : (details && details.storageType);
        const v = storageAccessGuard.decideStorageAccess(
          st,
          { kind, frameUrl, topUrl, key: details && details.key, storageType },
          Date.now());
        if (v.action !== storageAccessGuard.ACTION_REPORT) return;
        if (v.reason === 'cross-origin-storage-access') {
          const label = kind === storageAccessGuard.KIND_CACHE ? '缓存分区' : '会话存储';
          recordSecurityEvent('storage-cross-access', 'info',
            `跨站子框架访问顶层${label}：${v.frameOrigin || '未知源'} -> ${v.topOrigin || '未知源'}`,
            v.topOrigin || originOfContents(contents));
        } else if (v.reason === 'storage-access-flood') {
          recordSecurityEvent('storage-access-flood', 'warn',
            `存储访问事件高频洪泛（${kind}，窗口内 ${v.windowHits} 次）`,
            v.topOrigin || originOfContents(contents));
        }
      } catch (err) {
        recordSecurityEvent('storage-access-flood', 'info',
          `存储访问守卫异常: ${String((err && err.message) || err)}`, originOfContents(contents));
      }
    };
    contents.on('seen-session-storage-data-access', (event, details) => {
      handleStorageDataAccess(storageAccessGuard.KIND_SESSION, details);
    });
    contents.on('seen-cache-storage-data-access', (event, details) => {
      handleStorageDataAccess(storageAccessGuard.KIND_CACHE, details);
    });
  });
}

// setupNetworkStatus 监听 Chromium 的 online/offline 事件，把状态推给 renderer，
// 地址栏/错误页可以据此显示"已断开连接"横幅。
function setupNetworkStatus() {
  const report = () => {
    sendToRenderer('network-status-changed', { online: net.isOnline() });
  };
  app.on('online', report);
  app.on('offline', report);
  // 启动时先报一次当前状态
  setTimeout(report, 500);
}

// r34：GPU 进程崩溃 / GPU 信息更新 / 无障碍支持变化是 app 级系统事件，与具体标签弱
// 关联，用进程级单份状态去重。崩溃风暴折叠为一条审计并提示重载；GPU 重枚举只保留
// 白名单字段，软件渲染回退时留痕；系统读屏被打开（渲染路径变化）留痕。
function setupSystemEventGuards() {
  app.on('gpu-process-crashed', (_event, killed) => {
    try {
      const v = gpuAccessGuard.decideGPUCrash(gpuCrashState, { killed: !!killed }, Date.now());
      if (v.action !== gpuAccessGuard.ACTION_RECORD) return;
      recordSecurityEvent('gpu-process-crashed', 'warn', v.detail, '');
      try {
        sendToRenderer('gpu-process-gone', { reason: v.killed ? 'killed' : 'crashed' });
        if (mainWindow && !mainWindow.isDestroyed()) {
          sendToRenderer('show-toast',
            v.killed ? 'GPU 进程被系统终止，如画面异常请按 Ctrl+R 重载'
                     : 'GPU 进程崩溃已自动恢复，如画面异常请按 Ctrl+R 重载');
        }
      } catch {}
    } catch (err) {
      recordSecurityEvent('gpu-process-crashed', 'info',
        `GPU 崩溃守卫异常: ${String((err && err.message) || err)}`, '');
    }
  });

  app.on('gpu-info-update', () => {
    const now = Date.now();
    if (gpuInfoLastReport >= 0 && now - gpuInfoLastReport < GPU_INFO_REPORT_COOLDOWN_MS) return;
    // 用 basic 信息（含 auxAttributes），避免 'complete' 触发可能较慢的完整枚举。
    Promise.resolve()
      .then(() => (typeof app.getGPUInfo === 'function' ? app.getGPUInfo('basic') : null))
      .then((info) => {
        const clean = gpuAccessGuard.sanitizeGPUInfo(info && info.auxAttributes);
        if (clean.kept === 0) return;
        gpuInfoLastReport = Date.now();
        if (clean.fields.softwareRendering === true) {
          recordSecurityEvent('gpu-info-update', 'warn',
            'GPU 被重新枚举且当前回退到软件渲染（硬件加速可能不可用）', '');
        } else {
          recordSecurityEvent('gpu-info-update', 'info',
            'GPU 信息已更新（硬件加速生效）', '');
        }
      })
      .catch(() => {});
  });

  app.on('accessibility-support-changed', (_event, enabled) => {
    try {
      const v = gpuAccessGuard.decideAccessibilityChange(enabled);
      if (v.shouldRecord) {
        recordSecurityEvent('accessibility-changed', 'info', v.detail, '');
      }
    } catch {}
  });
}

// r34：补齐“只加固 defaultSession、漏了后续 fromPartition 会话”的纵深防御缺口。
// app 'session-created' 对每个新会话触发（defaultSession 已在 setupPermissionHandlers /
// setupSecurityHeaders 中单独加固，这里靠 sessionGuard 去重跳过）。任何非默认会话都
// 套用最保守基线：权限 / 设备选择一律拒绝（访客 / 隔离会话不弹主标签询问条），并挂
// 出向隐私头（DNT / GPC / Upgrade-Insecure / Referrer 收敛）。
function setupExtraSessionHardening() {
  const originOfPermissionRequest = (webContents) => {
    try {
      return webContents && typeof webContents.getURL === 'function'
        ? new URL(webContents.getURL()).origin : '';
    } catch {
      return '';
    }
  };

  const applyOutgoingPrivacyHeaders = (ses) => {
    try {
      ses.webRequest.onBeforeSendHeaders((details, callback) => {
        const headers = details.requestHeaders || {};
        headers['DNT'] = '1';
        headers['Sec-GPC'] = '1';
        headers['Upgrade-Insecure-Requests'] = '1';
        try { trimReferrerHeader(details, headers); } catch {}
        callback({ requestHeaders: headers });
      });
    } catch {}
  };

  app.on('session-created', (ses) => {
    let partition = '';
    try { partition = typeof ses.getStoragePath === 'function' ? '' : (ses.partition || ''); } catch {}
    // session 对象未必直接暴露 partition；sessionGuard 只需要分区串。取不到时按空串，
    // 但 defaultSession 已被单独加固并占位，真正落到这里的空串会话仍按最保守基线处理。
    let decision;
    try {
      decision = sessionGuard.decideSessionHarden(sessionGuardState, { partition });
    } catch {
      decision = null;
    }

    // defaultSession 已加固，去重命中后不重复注册。
    if (decision && decision.alreadyHardened) return;

    if (decision && !decision.shouldHarden) {
      // 分区串非法：不留裸奔会话，仍强制默认拒绝，并留一条独立事件提示分区异常。
      try {
        ses.setPermissionRequestHandler((wc, _permission, cb) => {
          try { cb(false); } catch {}
        });
        if (typeof ses.setPermissionCheckHandler === 'function') {
          ses.setPermissionCheckHandler(() => false);
        }
        if (typeof ses.setDevicePermissionHandler === 'function') {
          ses.setDevicePermissionHandler(() => false);
        }
      } catch {}
      applyOutgoingPrivacyHeaders(ses);
      recordSecurityEvent('session-partition-rejected', 'warn',
        `检测到非法会话分区（${decision.reason}），已对该会话强制默认拒绝`, '');
      return;
    }

    // 合法的非默认会话：全套默认拒绝基线 + 出向隐私头。
    try {
      ses.setPermissionRequestHandler((webContents, permission, callback) => {
        const origin = originOfPermissionRequest(webContents);
        recordSecurityEvent('permission-blocked', 'info',
          `隔离/访客会话中的权限请求已默认拒绝: ${permission}`, origin);
        try { callback(false); } catch {}
      });
      if (typeof ses.setPermissionCheckHandler === 'function') {
        ses.setPermissionCheckHandler(() => false);
      }
      if (typeof ses.setDevicePermissionHandler === 'function') {
        ses.setDevicePermissionHandler((details) => {
          let origin = '';
          try { origin = new URL((details && details.origin) || '').origin; } catch {}
          recordSecurityEvent('device-permission-blocked', 'info',
            `隔离/访客会话中的设备选择已默认拒绝（${details && details.permissionType ? details.permissionType : '未知'}）`,
            origin);
          return false;
        });
      }
    } catch {}
    applyOutgoingPrivacyHeaders(ses);

    const persist = decision && decision.classification && decision.classification.persist;
    recordSecurityEvent('session-hardened', 'info',
      `新建${persist ? '持久' : '临时'}会话已套用默认拒绝权限/设备策略与出向隐私头`, '');
  });

  // 先把 defaultSession 标记为“已加固”，真正的处理器由 setupPermissionHandlers /
  // setupSecurityHeaders 注册；这样 session-created 即便为默认会话触发也会被去重跳过。
  try {
    sessionGuard.decideSessionHarden(sessionGuardState, { partition: '' });
  } catch {}
}

function getTabLayout() {
  const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
  try {
    if (fsSync.existsSync(settingsPath)) {
      const settings = JSON.parse(fsSync.readFileSync(settingsPath, 'utf-8'));
      return settings.tabLayout || 'horizontal';
    }
  } catch (e) {
    console.error('读取设置失败:', e);
  }
  return 'horizontal';
}

function getDefaultTabUrl() {
  const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
  try {
    if (fsSync.existsSync(settingsPath)) {
      const settings = JSON.parse(fsSync.readFileSync(settingsPath, 'utf-8'));
      if (settings.defaultTab === 'bing') return 'https://www.bing.com';
      if (settings.defaultTab === 'custom' && settings.customUrl && isSafeUrl(settings.customUrl))
        return settings.customUrl;
    }
  } catch (e) {
    console.error('读取设置失败:', e);
  }
  return 'cosy://newtab';
}

function createWindow() {
  if (mainWindow && !mainWindow.isDestroyed()) return;

  // 主窗口 webPreferences 走统一安全基线（winpolicy）：强制关闭 Node 集成 /
  // 开启上下文隔离与沙箱 / 开启同源策略，并校验 preload 必须在应用目录内。
  const mainWinReview = winPolicy.harden({
    preload: path.join(__dirname, 'preload.js'),
    spellcheck: true,
  }, { preloadRoots: __dirname, requirePreload: true });
  if (winPolicy.hasCritical(mainWinReview.findings)) {
    for (const f of mainWinReview.findings.filter(x => x.severity === 'critical')) {
      try { recordSecurityEvent('window-policy', 'critical', `主窗口配置被拒绝: ${f.key}`, ''); } catch {}
    }
  }
  mainWindow = new BrowserWindow({
    width: DEFAULT_WINDOW_WIDTH, height: DEFAULT_WINDOW_HEIGHT,
    minWidth: MIN_WINDOW_WIDTH, minHeight: MIN_WINDOW_HEIGHT,
    webPreferences: mainWinReview.prefs,
    titleBarStyle: 'hidden', frame: false, show: false,
    icon: path.join(__dirname, 'ico.png')
  });

  const tabLayout = getTabLayout();
  const htmlFile = tabLayout === 'vertical' ? 'src/index_vertical.html' : 'src/index.html';
  mainWindow.loadFile(htmlFile);

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    if (fileToOpen) {
      createNewTab(fileToOpen);
      fileToOpen = null;
    } else {
      const savedSession = loadSession();
      if (savedSession && savedSession.length > 0) {
        savedSession.forEach((tab) => createNewTab(tab.url));
        clearSession();
      } else {
        createNewTab(getDefaultTabUrl());
      }
    }
  });

  mainWindow.on('resize', updateBrowserViewBounds);
  mainWindow.on('move', updateBrowserViewBounds);
  mainWindow.once('closed', () => {
    // 开启了“退出时清除浏览数据”就不要把本次标签会话落盘，避免下次又恢复出来。
    if (!clearOnExit) saveSession();
    mainWindow = null;
  });

  // 会话原先只在正常退出时落盘，一旦进程崩溃 / 被任务管理器结束，下次启动就
  // 无法恢复标签。这里周期性自动保存一次，崩溃最多丢失这 15 秒内新开/关闭的标签。
  const SESSION_AUTOSAVE_MS = 15000;
  const sessionAutosaveTimer = setInterval(() => {
    try { if (!clearOnExit) saveSession(); } catch {}
  }, SESSION_AUTOSAVE_MS);
  if (typeof sessionAutosaveTimer.unref === 'function') sessionAutosaveTimer.unref();

  // 关闭窗口时按顺序做两道确认，再按设置执行隐私清理：
  // 1) 开了“多标签退出确认”且仍有多个标签 → 二次确认；
  // 2) 有关键下载进行中 → 放弃下载确认；
  // 3) 开了“退出时清除浏览数据”→ 清理完成后才真正退出。
  let allowQuitWithDownloads = false;
  let multiTabConfirmed = false;
  let exitPurged = false;
  mainWindow.on('close', async (e) => {
    if (!mainWindow) return;

    if (!multiTabConfirmed && confirmCloseMultiple && tabs.length > 1) {
      e.preventDefault();
      const choice = dialog.showMessageBoxSync(mainWindow, {
        type: 'question',
        buttons: ['取消', '全部关闭'],
        defaultId: 0,
        cancelId: 0,
        title: '关闭所有标签页？',
        message: `当前还有 ${tabs.length} 个标签页打开，确定要退出 OpenCosy 吗？`,
        detail: '退出将结束本次浏览会话。',
      });
      if (choice !== 1) return;
      multiTabConfirmed = true;
      mainWindow.close();
      return;
    }

    if (!allowQuitWithDownloads) {
      const active = downloads.some(d => d && (d.status === 'downloading' || d.status === 'pending' || d.status === 'paused'));
      if (active) {
        e.preventDefault();
        const choice = dialog.showMessageBoxSync(mainWindow, {
          type: 'warning',
          buttons: ['继续下载，留在窗口', '放弃下载并退出'],
          defaultId: 0,
          cancelId: 0,
          title: '仍有下载进行中',
          message: '当前还有未完成的下载，确定要退出吗？',
          detail: '退出后正在进行的下载会被中断，已完成的文件不受影响。',
        });
        if (choice === 1) {
          allowQuitWithDownloads = true;
          mainWindow.close();
        }
        return;
      }
    }

    if (clearOnExit && !exitPurged) {
      e.preventDefault();
      exitPurged = true;
      try {
        await purgeBrowsingDataOnExit();
      } catch (err) {
        console.error('退出时清除浏览数据失败:', err);
      }
      mainWindow.close();
    }
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (isSafeUrl(url)) createNewTab(url);
    return { action: 'deny' };
  });

  registerShortcuts();
}

function registerShortcuts() {
  if (!mainWindow) return;
  mainWindow.webContents.on('before-input-event', (event, input) => {
    if (input.type !== 'keyDown') return;
    const ctrl = input.control || input.meta;
    const shift = input.shift;
    const alt = input.alt;
    const key = input.key.toLowerCase();

    if (ctrl && key === 't' && !shift) {
      createNewTab();
      event.preventDefault();
    } else if (ctrl && key === 't' && shift) {
      const lastClosedTab = getLastClosedTab();
      if (lastClosedTab) createNewTab(lastClosedTab.url);
      event.preventDefault();
    } else if (ctrl && key === 'w') {
      closeTab(currentTabIndex);
      event.preventDefault();
    } else if (ctrl && key === 'n') {
      createWindow();
      event.preventDefault();
    } else if (ctrl && key === 'k' && shift) {
      const tab = tabs[currentTabIndex];
      if (tab && isSafeUrl(tab.url)) createNewTab(tab.url);
      event.preventDefault();
    } else if (ctrl && key === 'b' && shift) {
      // Ctrl+Shift+B：切换书签栏（Chrome/Edge 惯例）
      sendToRenderer('toggle-bookmarks-bar');
      event.preventDefault();
    } else if (ctrl && key === 'd' && shift) {
      // Ctrl+Shift+D：把所有打开的标签一键加为书签
      const newBookmarks = tabs
        .filter(t => isSafeUrl(t.url) && !t.url.startsWith('cosy://'))
        .map(t => ({ url: t.url, title: t.title, addedDate: new Date().toISOString() }))
        .filter(b => !bookmarks.find(x => x.url === b.url));
      if (newBookmarks.length > 0) {
        bookmarks.push(...newBookmarks);
        saveBookmarks();
        sendToRenderer('bookmarks-updated', bookmarks);
        sendToRenderer('show-toast', `已收藏 ${newBookmarks.length} 个标签页`);
      } else {
        sendToRenderer('show-toast', '没有可收藏的标签页');
      }
      event.preventDefault();
    } else if (ctrl && key === 's' && shift) {
      // Ctrl+Shift+S：立即释放所有后台标签内存（Memory Saver 手动触发）
      const n = discardAllBackgroundTabs();
      sendToRenderer('show-toast', n > 0 ? `已休眠 ${n} 个后台标签页` : '没有需要休眠的后台标签页');
      event.preventDefault();
    } else if (ctrl && key === 'tab') {
      const nextIndex = shift
        ? (currentTabIndex - 1 + tabs.length) % tabs.length
        : (currentTabIndex + 1) % tabs.length;
      switchToTab(nextIndex);
      event.preventDefault();
    } else if (ctrl && key === 'l') {
      mainWindow.webContents.send('focus-address-bar');
      event.preventDefault();
    } else if (input.key === 'F6') {
      // F6：Chrome/Edge 惯例，聚焦地址栏
      mainWindow.webContents.send('focus-address-bar');
      event.preventDefault();
    } else if (ctrl && input.key === 'F4') {
      // Ctrl+F4：关闭当前标签页（与 Ctrl+W 等价的多标签窗口惯例）
      closeTab(currentTabIndex);
      event.preventDefault();
    } else if (ctrl && key === 'f') {
      mainWindow.webContents.send('show-find-bar');
      event.preventDefault();
    } else if (input.key === 'F3' || (ctrl && key === 'g')) {
      // F3 / Ctrl+G：继续查找下一个（Shift 反向），对齐 Chrome/Edge 惯例。
      applyFind(!shift);
      event.preventDefault();
    } else if (ctrl && key === 'j') {
      createNewTab('cosy://downloadlist');
      event.preventDefault();
    } else if (ctrl && key === 'p') {
      const wc = getCurrentTabWebContents();
      if (wc) wc.print({ silent: false, printBackground: true });
      event.preventDefault();
    } else if (ctrl && key === 'u') {
      const tab = tabs[currentTabIndex];
      if (tab && tab.view?.webContents && isSafeUrl(tab.url)) {
        tab.view.webContents.viewSource();
      }
      event.preventDefault();
    } else if (ctrl && key === 'o') {
      showOpenFileDialog();
      event.preventDefault();
    } else if (alt && input.key === 'Home') {
      goHome();
      event.preventDefault();
    } else if (ctrl && key === 'r' && !shift) {
      const wc = getCurrentTabWebContents();
      if (wc) wc.reload();
      event.preventDefault();
    } else if (ctrl && key === 'r' && shift) {
      const wc = getCurrentTabWebContents();
      if (wc) wc.reloadIgnoringCache();
      event.preventDefault();
    } else if (input.key === 'F5' && !shift) {
      const wc = getCurrentTabWebContents();
      if (wc) wc.reload();
      event.preventDefault();
    } else if (input.key === 'F5' && shift) {
      const wc = getCurrentTabWebContents();
      if (wc) wc.reloadIgnoringCache();
      event.preventDefault();
    } else if (input.key === 'F12') {
      toggleDevTools();
      event.preventDefault();
    } else if (input.key === 'Escape') {
      // 现代浏览器惯例：Esc 退出 HTML 全屏
      const wc = getCurrentTabWebContents();
      if (wc && wc.isFullScreen()) {
        wc.exitFullScreen();
        event.preventDefault();
      }
    } else if (ctrl && input.key === '=') {
      zoomIn();
      event.preventDefault();
    } else if (ctrl && input.key === '-') {
      zoomOut();
      event.preventDefault();
    } else if (ctrl && input.key === '0') {
      resetZoom();
      event.preventDefault();
    } else if (alt && input.key === 'ArrowLeft') {
      const wc = getCurrentTabWebContents();
      if (wc?.canGoBack()) wc.goBack();
      event.preventDefault();
    } else if (alt && input.key === 'ArrowRight') {
      const wc = getCurrentTabWebContents();
      if (wc?.canGoForward()) wc.goForward();
      event.preventDefault();
    } else if (ctrl && key === 'd' && !shift) {
      const tab = tabs[currentTabIndex];
      if (tab && isSafeUrl(tab.url) && !tab.url.startsWith('cosy://')) {
        const existing = bookmarks.findIndex(b => b.url === tab.url);
        if (existing === -1) {
          bookmarks.push({ url: tab.url, title: tab.title, addedDate: new Date().toISOString() });
          saveBookmarks();
          tab.bookmarked = true;
          sendToRenderer('bookmarks-updated', bookmarks);
          sendToRenderer('show-toast', '已添加书签');
        } else {
          bookmarks.splice(existing, 1);
          saveBookmarks();
          tab.bookmarked = false;
          sendToRenderer('bookmarks-updated', bookmarks);
          sendToRenderer('show-toast', '已移除书签');
        }
      }
      event.preventDefault();
    } else if (ctrl && key === 'h') {
      mainWindow.webContents.send('show-history');
      event.preventDefault();
    } else if (ctrl && key === 'delete' && shift) {
      sendToRenderer('show-clear-data-dialog');
      event.preventDefault();
    }
  });
}

function getUrlProtocol(url) {
  try { return new URL(url).protocol; } catch { return null; }
}

function createNewTab(url = 'cosy://newtab') {
  if (!isSafeUrl(url)) url = 'cosy://newtab';
  const tabId = Date.now().toString() + Math.random().toString(36).slice(2, 6);
  const tab = new Tab(tabId, url);

  if (getUrlProtocol(url) === 'cosy:') {
    tab.favicon = 'file://' + path.join(__dirname, 'ico.png');
  } else {
    tab.favicon = 'file://' + path.join(__dirname, 'src', 'loading.gif');
  }

  tabs.push(tab);
  currentTabIndex = tabs.length - 1;
  sendToRenderer('tab-created', { id: tab.id, url: tab.url, title: tab.title, favicon: tab.favicon });
  loadTabContent(tab);
  sendToRenderer('tab-switched', { id: tab.id, index: currentTabIndex });
  setTimeout(updateBrowserViewBounds, 0);
  return tab;
}

function showErrorPage(tab, errorCode, errorDescription, validatedURL) {
  const errorParams = new URLSearchParams({
    code: getHttpStatusCode(errorCode),
    message: getErrorMessage(errorCode),
    reason: errorDescription,
    url: validatedURL,
    browserCode: errorCode,
    browserMessage: getBrowserErrorText(errorCode)
  });
  const errorUrl = `file://${__dirname}/src/error.html?${errorParams.toString()}`;
  tab.view.webContents.loadURL(errorUrl);
  tab.url = validatedURL;
  tab.title = `错误 - ${getHttpStatusCode(errorCode)}`;
  sendToRenderer('tab-updated', { id: tab.id, url: validatedURL, title: tab.title });
}

// pushNavState 每次导航完成后同步 canGoBack/canGoForward，让 renderer 知道按钮该灰掉还是点亮
function pushNavState(tab) {
  if (!tab?.view?.webContents) return;
  tab.canGoBack = tab.view.webContents.canGoBack();
  tab.canGoForward = tab.view.webContents.canGoForward();
  sendToRenderer('tab-history-changed', {
    id: tab.id, canGoBack: tab.canGoBack, canGoForward: tab.canGoForward
  });
}

// ===== 渲染进程崩溃恢复 =====
// 渲染进程崩溃（OOM、被杀、完整性失败）后 WebContentsView 已不可用，
// 必须销毁旧视图、按 tab.url 重建；非活动标签不立即重载，切回时才恢复，
// 避免一个坏页面在后台无限崩溃-重载循环把 CPU 打满。
const CRASH_REASON_TEXT = {
  crashed: '页面崩溃',
  oom: '内存不足，页面被系统终止',
  killed: '渲染进程被终止',
  'launch-failed': '渲染进程启动失败',
  'integrity-failure': '渲染进程代码完整性校验失败',
};
const MAX_CRASH_AUTO_RECOVER = 3;   // 时间窗内自动恢复次数上限
const CRASH_WINDOW_MS = 60 * 1000; // 崩溃计数滑动窗口

function recordCrash(tab, details) {
  const now = Date.now();
  tab.crashEvents = (tab.crashEvents || []).filter(t => now - t < CRASH_WINDOW_MS);
  tab.crashEvents.push(now);
  tab.crashed = true;
  tab.crashReason = CRASH_REASON_TEXT[details?.reason]
    || `渲染进程异常退出（${details?.reason || 'unknown'}）`;
  sendToRenderer('tab-crashed', { id: tab.id, reason: tab.crashReason });
}

function canAutoRecover(tab) {
  return (tab.crashEvents || []).length <= MAX_CRASH_AUTO_RECOVER;
}

// 销毁已经死亡的视图；webContents 在崩溃后可能已被回收，全部容错。
function destroyTabView(tab) {
  if (!tab.view) return;
  try { mainWindow.contentView.removeChildView(tab.view); } catch {}
  try { tab.view.webContents.destroy(); } catch {}
  tab.view = null;
}

// 重建崩溃标签的视图；超过自动恢复上限时改显错误页，不再自动加载原 URL。
function rebuildCrashedTab(tab) {
  const reason = tab.crashReason;
  const overLimit = !canAutoRecover(tab);
  destroyTabView(tab);
  tab.crashed = false;
  tab.crashReason = null;
  loadTabContent(tab);
  if (overLimit) {
    showCosyError(tab, '500', reason || '页面崩溃', '该页面短时间内多次崩溃，已停止自动恢复，请手动刷新');
  }
}

function handleRenderProcessGone(tab, details) {
  if (!tab) return;
  recordCrash(tab, details);
  const idx = tabs.indexOf(tab);
  // 活动标签立即恢复；后台标签只清理死视图，等切回时再重建。
  if (idx === currentTabIndex) rebuildCrashedTab(tab);
  else destroyTabView(tab);
}

// ===== 内存节省（Memory Saver）：自动休眠后台标签 =====
// 对齐 Chrome "Memory Saver"：长时间不看的后台标签，其渲染进程（HTML/JS、
// 图片解码、定时器、网络等占用的内存可达几十~几百 MiB）会被回收，标签壳
// （URL / 标题 / 图标）保留；用户点回该标签时再按原 URL 重新加载。
// 这不是崩溃恢复，不弹错误页：tab.discarded 是正常的"已休眠"态。
let memorySaverEnabled = true;
const MEMORY_SAVER_IDLE_MS = 30 * 60 * 1000; // 后台连续不活动 30 分钟才休眠
const MEMORY_SAVER_SWEEP_MS = 60 * 1000;    // 每分钟扫描一次
let memorySaverTimer = null;

// tabKeepsAlive 判断标签是否必须常驻、不能被休眠。
function tabKeepsAlive(tab) {
  if (!tab) return true;
  const idx = tabs.indexOf(tab);
  if (idx === currentTabIndex) return true;            // 正在看的标签
  if (tab.discarded || tab.crashed || !tab.view) return true; // 已休眠/崩溃/无视图
  if (tab.isLoading) return true;                      // 正在加载，打断会留下半成品
  try {
    if (tab.view.webContents.isCurrentlyAudible() && !tab.muted) return true; // 正在放声音
  } catch {}
  try {
    if (tab.view.webContents.isBeingCaptured()) return true; // 正在录屏/共享标签
  } catch {}
  if (tab.url.startsWith('cosy://')) return true;      // 内置页面很轻且承载 UI 状态
  return false;
}

// discardTab 回收一个后台标签的渲染进程并保留标签壳。
function discardTab(tab, reason = 'idle') {
  if (tabKeepsAlive(tab)) return false;
  destroyTabView(tab);
  tab.discarded = true;
  tab.retry403 = false;
  sendToRenderer('tab-discarded', { id: tab.id, url: tab.url, reason });
  return true;
}

// reloadDiscardedTab 唤醒休眠标签：按记录的 URL 重建视图并重新加载。
function reloadDiscardedTab(tab) {
  if (!tab || !tab.discarded) return false;
  tab.discarded = false;
  tab.lastActiveAt = Date.now();
  loadTabContent(tab);
  sendToRenderer('tab-reloaded', { id: tab.id });
  setTimeout(updateBrowserViewBounds, 0);
  return true;
}

// sweepDiscardableTabs 把超过空闲阈值且无需常驻的后台标签休眠掉。
function sweepDiscardableTabs() {
  if (!memorySaverEnabled) return;
  const now = Date.now();
  for (const tab of tabs) {
    if (tabKeepsAlive(tab)) continue;
    if (now - (tab.lastActiveAt || 0) >= MEMORY_SAVER_IDLE_MS) discardTab(tab, 'idle');
  }
}

function startMemorySaver() {
  if (memorySaverTimer) return;
  memorySaverTimer = setInterval(sweepDiscardableTabs, MEMORY_SAVER_SWEEP_MS);
  if (typeof memorySaverTimer.unref === 'function') memorySaverTimer.unref();
}

// discardAllBackgroundTabs 立即休眠除活动标签外所有可休眠的后台标签，
// 返回成功休眠的数量，供快捷键 / 右键菜单给用户一个明确反馈。
function discardAllBackgroundTabs() {
  let n = 0;
  for (const tab of tabs) {
    if (tabKeepsAlive(tab)) continue;
    if (discardTab(tab, 'manual')) n++;
  }
  return n;
}

ipcMain.handle('discard-tab', (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false };
  const tab = (payload?.tabId === undefined)
    ? tabs[currentTabIndex]
    : tabs.find(t => String(t.id) === String(payload.tabId));
  if (!tab) return { success: false };
  return { success: discardTab(tab, 'manual') };
});

ipcMain.handle('discard-background-tabs', (event) => {
  if (!isMainSender(event)) return { success: false, count: 0 };
  return { success: true, count: discardAllBackgroundTabs() };
});

ipcMain.handle('get-memory-saver', (event) => {
  if (!isMainSender(event)) return { enabled: false, idleMs: MEMORY_SAVER_IDLE_MS, discarded: [] };
  return {
  enabled: !!memorySaverEnabled,
  idleMs: MEMORY_SAVER_IDLE_MS,
  discarded: tabs.filter(t => t.discarded).map(t => ({ id: t.id, url: t.url })),
  };
});

function loadTabContent(tab) {
  if (!tab.view) {
    // 标签视图与主窗口共用同一份 webPreferences 安全基线，杜绝两处配置漂移。
    const tabWinReview = winPolicy.harden({
      preload: path.join(__dirname, 'preload.js'),
      spellcheck: true,
    }, { preloadRoots: __dirname, requirePreload: true });
    if (winPolicy.hasCritical(tabWinReview.findings)) {
      for (const f of tabWinReview.findings.filter(x => x.severity === 'critical')) {
        try { recordSecurityEvent('window-policy', 'critical', `标签视图配置被拒绝: ${f.key}`, ''); } catch {}
      }
    }
    tab.view = new WebContentsView({
      webPreferences: tabWinReview.prefs
    });

    mainWindow.contentView.addChildView(tab.view);
    updateBrowserViewBounds();

    tab.view.webContents.setWindowOpenHandler(({ url, disposition }) => {
      // 页面用 window.open 唤起 mailto/tel 时不弹窗（没有新窗口的位置），
      // 直接走外部协议确认流；其它非 Web 协议照旧拒绝。
      const extScheme = normalizeExternalScheme(url);
      if (CONFIRMABLE_EXTERNAL_SCHEMES.has(extScheme)) {
        launchExternalWithPrompt(url, originOfContents(tab.view.webContents), true);
        return { action: 'deny' };
      }
      // 弹窗上下文额外拦截 javascript:/data:/vbscript:/file: 目标——这些协议在
      // 顶层地址栏另有处理，但绝不应在新浏览上下文里渲染/执行。
      const popupDecision = popupGuard.decidePopup({
        currentUrl: tab.url || '', targetUrl: url, disposition,
      });
      if (popupDecision.action === 'block') {
        recordSecurityEvent('popup-blocked', 'warn',
          `拦截危险协议弹窗: ${url}`, originOfContents(tab.view.webContents));
        sendToRenderer('popup-blocked', { url });
        return { action: 'deny' };
      }
      if (!isSafeUrl(url)) return { action: 'deny' };
      if (disposition === 'new-window' || disposition === 'foreground-tab') {
        // 弹窗轰炸限流：短时间内同一标签狂开窗口时拦截，只放行正常节奏的新窗口。
        if (!allowPopupForTab(tab.id)) {
          sendToRenderer('popup-blocked', { url });
          return { action: 'deny' };
        }
        const newTab = createNewTab(url);
        switchToTab(tabs.indexOf(newTab));
      } else {
        tab.url = url;
        tab.view.webContents.loadURL(url);
      }
      return { action: 'deny' };
    });

    tab.view.webContents.on('will-navigate', (event, navigationUrl) => {
      // 外部协议 / 危险协议的拦截与确认由全局 web-contents 钩子统一处理
      // （否则这里和全局各弹一次确认框）；这里只负责窗内导航的状态同步。
      if (classifyFrameNavigation(navigationUrl, true) !== 'in-pane') {
        event.preventDefault();
        return;
      }
      tab.url = navigationUrl;
      addToHistory(navigationUrl, tab.title);
      sendToRenderer('tab-updated', { id: tab.id, url: navigationUrl });
    });

    tab.view.webContents.on('did-navigate', () => { pushNavState(tab); applySavedZoom(tab); });
    tab.view.webContents.on('did-navigate-in-page', (inEvent, inPageUrl) => {
      // pushState/replaceState 洪泛与畸形 URL 收口：拒绝 / 冷却 / 重复地址时不压历史、
      // 不更新地址栏，避免历史劫持与广播风暴；主导航 did-navigate 会清零配额。
      const st = getContentsState(inpageStates, tab.view.webContents.id, inpageGuard.createInPageState);
      const v = inpageGuard.decideInPageNav(st, inPageUrl || tab.url, Date.now());
      if (v.decision === inpageGuard.INPAGE_REJECT) {
        recordSecurityEvent('inpage-flood', 'warn',
          inpageGuard.describeInPageReason(v.reason), tab.url);
        return;
      }
      if (v.decision === inpageGuard.INPAGE_HOLD && v.reason === inpageGuard.HOLD_BURST) {
        recordSecurityEvent('inpage-flood', 'warn',
          inpageGuard.describeInPageReason(v.reason), tab.url);
        return;
      }
      if (v.decision === inpageGuard.INPAGE_HOLD) return; // 重复地址/冷却：静默合并
      pushNavState(tab);
      applySavedZoom(tab);
    });
    tab.view.webContents.on('dom-ready', () => applySavedZoom(tab));

    tab.view.webContents.on('did-redirect-navigation', (event, url) => {
      if (!isSafeUrl(url)) return;
      tab.url = url;
      sendToRenderer('tab-updated', { id: tab.id, url });
    });

    tab.view.webContents.on('page-title-updated', (event, rawTitle) => {
      // 标题由页面完全控制：净化控制字符 / 折叠空白 / 代码点安全截断，并对高频翻转与
      // 极短重复上报做收敛，防止伪加载闪烁、标题注入以及 addToHistory+IPC 广播风暴。
      const tst = getContentsState(titleStates, tab.view.webContents.id, titleGuard.createTitleState);
      const tv = titleGuard.decideTitleUpdate(tst, rawTitle, Date.now());
      if (tv.decision === titleGuard.TITLE_HOLD) return;
      const title = tv.title;
      tab.title = title;
      addToHistory(tab.url, title);
      sendToRenderer('tab-updated', { id: tab.id, title });
      if (tv.sanitized) {
        recordSecurityEvent('title-abuse', 'info',
          titleGuard.describeTitleReason(titleGuard.TITLE_SANITIZED), tab.url);
      }
    });

    tab.view.webContents.on('did-start-loading', () => {
      tab.isLoading = true;
      sendToRenderer('tab-loading', { id: tab.id, loading: true });
    });

    tab.view.webContents.on('did-stop-loading', () => {
      tab.isLoading = false;
      sendToRenderer('tab-loading', { id: tab.id, loading: false });
    });

    // 音频播放状态变化：Electron 此事件不带状态参数，需主动查询
    // isCurrentlyAudible / isAudioMuted，再广播给渲染进程显示喇叭图标。
    tab.view.webContents.on('audio-state-changed', () => {
      try {
        tab.audible = !!tab.view.webContents.isCurrentlyAudible();
        tab.muted = !!tab.view.webContents.isAudioMuted();
      } catch {
        return;
      }
      sendToRenderer('tab-audio-changed', { id: tab.id, audible: tab.audible, muted: tab.muted });
    });

    tab.view.webContents.on('did-fail-load', (event, errorCode, errorDescription, validatedURL, isMainFrame) => {
      if (!isMainFrame) return;
      // ERR_ABORTED(-3) 不是真失败：下载触发的导航、用户手动取消、被 window.open
      // 拦截或重定向链中止都会带这个码，此时弹错误页只会把正常页面盖掉。
      if (errorCode === -3) return;
      const httpStatus = getHttpStatusCode(errorCode);
      if (httpStatus === '403' && !tab.retry403) {
        tab.retry403 = true;
        tab.view.webContents.loadURL(validatedURL).catch(() => {
          showErrorPage(tab, errorCode, errorDescription, validatedURL);
        });
        return;
      }
      showErrorPage(tab, errorCode, errorDescription, validatedURL);
    });

    tab.view.webContents.on('render-process-gone', (event, details) => {
      handleRenderProcessGone(tab, details);
    });

    tab.view.webContents.on('page-favicon-updated', (event, favicons) => {
      // 图标数组同样来自页面：限制数量与单个长度、只放行 http(s)/data，防止喂入超大
      // data: URL 或 file:/blob:/javascript: 来源；取净化后的第一个作为标签图标。
      const { favicons: safe, dropped } = titleGuard.sanitizeFavicons(favicons);
      if (dropped > 0) {
        recordSecurityEvent('title-abuse', 'info',
          `网站图标包含 ${dropped} 个非法或超长条目，已过滤`, tab.url);
      }
      if (safe.length === 0) return;
      const faviconUrl = titleGuard.resolveFaviconHref(safe[0], tab.url);
      if (faviconUrl && titleGuard.isAllowedFaviconScheme(faviconUrl)) {
        tab.favicon = faviconUrl;
        sendToRenderer('tab-updated', { id: tab.id, favicon: tab.favicon });
      }
    });

    tab.view.webContents.on('context-menu', (event, params) => {
      // r33：菜单入参完全来自网页，先经 menuguard 统一净化（危险链接协议、超长 /
      // 含 CR/LF 的选中文本、非法错词与超长建议），后续一律只用净化后的值建菜单，
      // 杜绝畸形 label 折行伪造条目与持久拼写词典投毒。
      const mp = menuGuard.evaluateContextMenu(params);
      if (mp.reasons.length > 0) {
        recordSecurityEvent('context-menu-sanitized', 'info',
          `右键菜单参数已净化（${mp.reasons.join('；')}）`, originOfContents(tab.view.webContents));
      }
      const menu = new Menu();
      // 拼写建议放在菜单最顶部，与 Chromium 浏览器一致。
      // misspelledWord / suggestions 已逐条校验，建议不离开本机。
      if (spellcheckEnabled && mp.isEditable && mp.misspelledWord) {
        if (mp.suggestions.length) {
          for (const word of mp.suggestions) {
            menu.append(new MenuItem({
              label: word,
              click: () => tab.view.webContents.replaceMisspelling(word)
            }));
          }
        } else {
          menu.append(new MenuItem({ label: '（无拼写建议）', enabled: false }));
        }
        menu.append(new MenuItem({
          label: '添加到词典',
          click: () => {
            try {
              // mp.misspelledWord 已确认是合法单词（无空白 / 控制字符 / 标记符）。
              tab.view.webContents.session.addWordToSpellCheckerDictionary(mp.misspelledWord);
            } catch (e) {
              console.error('添加自定义词典失败:', e);
            }
          }
        }));
        menu.append(new MenuItem({ type: 'separator' }));
      }
      if (mp.canUseLink && mp.linkUrl) {
        menu.append(new MenuItem({ label: '在新标签页中打开', click: () => createNewTab(mp.linkUrl) }));
        menu.append(new MenuItem({ label: '复制链接地址', click: () => clipboard.writeText(mp.linkUrl) }));
        menu.append(new MenuItem({ type: 'separator' }));
      }
      if (mp.hasSelection) {
        menu.append(new MenuItem({ label: '复制', role: 'copy' }));
        menu.append(new MenuItem({
          label: '搜索所选内容',
          click: () => createNewTab('https://www.bing.com/search?q=' + encodeURIComponent(mp.selectionText))
        }));
      }
      if (mp.hasSelection && mp.isEditable) menu.append(new MenuItem({ label: '剪切', role: 'cut' }));
      if (mp.isEditable) menu.append(new MenuItem({ label: '粘贴', role: 'paste' }));
      if (mp.isEditable) menu.append(new MenuItem({ label: '全选', role: 'selectAll' }));
      if (menu.items.length > 0) menu.append(new MenuItem({ type: 'separator' }));
      if (isDev) menu.append(new MenuItem({ label: '开发者工具', click: toggleDevTools }));
      menu.popup({ window: mainWindow });
    });

    tab.view.webContents.on('enter-html-full-screen', () => {
      tab.originalBounds = tab.view.bounds;
      const [width, height] = mainWindow.getSize();
      tab.view.setBounds({ x: 0, y: 0, width, height });
      sendToRenderer('html-fullscreen-changed', { isFullscreen: true });
    });

    tab.view.webContents.on('leave-html-full-screen', () => {
      if (tab.originalBounds) {
        tab.view.setBounds(tab.originalBounds);
        tab.originalBounds = null;
      }
      sendToRenderer('html-fullscreen-changed', { isFullscreen: false });
    });
  }

  const protocol = getUrlProtocol(tab.url);
  if (protocol === 'cosy:') {
    try {
      const urlObj = new URL(tab.url);
      const hostname = urlObj.hostname;
      const pageMap = {
        'setting': 'src/settings.html', 'newtab': 'src/newtab.html',
        'extensions': 'src/extensions.html', 'version': 'src/version.html',
        'sitedata': 'src/sitedata.html',
        'permissions': 'src/permissions.html',
        'security': 'src/security.html',
        'hashes': 'src/hashes.html',
        'download': 'src/download', 'downloadlist': 'src/downloadlist.html'
      };
      const filePath = pageMap[hostname];
      if (filePath) tab.view.webContents.loadFile(filePath);
      else showCosyError(tab, '404', '页面未找到', '未注册的cosy协议地址');
    } catch (e) {
      console.error('解析cosy协议URL失败:', e);
      showCosyError(tab, '400', '无效的URL', '无法解析cosy协议地址');
    }
  } else if (isSafeUrl(tab.url)) {
    tab.view.webContents.loadURL(tab.url);
  } else {
    showCosyError(tab, '400', '无效的URL', '不支持的协议');
  }
}

function showCosyError(tab, code, message, reason) {
  const errorParams = new URLSearchParams({ code, message, reason, url: tab.url, browserCode: -3, browserMessage: 'ERR_UNKNOWN_COSY_URL' });
  const errorUrl = `file://${__dirname}/src/error.html?${errorParams.toString()}`;
  tab.view.webContents.loadURL(errorUrl);
  tab.title = `错误 - ${code}`;
  tab.favicon = 'src/error.png';
  sendToRenderer('tab-updated', { id: tab.id, url: tab.url, title: tab.title });
}

function updateBrowserViewBounds() {
  if (tabs.length > 0 && currentTabIndex >= 0) {
    const tab = tabs[currentTabIndex];
    if (tab && tab.view) {
      const [width, height] = mainWindow.getSize();
      const tabLayout = getTabLayout();

      let x, y, w, h;
      if (tabLayout === 'vertical') {
        const tabBarWidth = isTabBarCollapsed ? COLLAPSED_TAB_BAR_WIDTH : DEFAULT_TAB_BAR_WIDTH_VERTICAL;
        x = tabBarWidth; y = 75; w = width - tabBarWidth; h = height - 75;
      } else {
        x = 0; y = DEFAULT_TAB_BAR_HEIGHT_HORIZONTAL; w = width; h = height - DEFAULT_TAB_BAR_HEIGHT_HORIZONTAL;
      }
      tab.view.setBounds({ x, y, width: w, height: h });
    }
  }
}

function switchToTab(tabIndex) {
  if (tabIndex >= 0 && tabIndex < tabs.length) {
    const prevContents = getCurrentTabWebContents();
    currentTabIndex = tabIndex;
    const tab = tabs[tabIndex];
    tab.lastActiveAt = Date.now();
    // 后台崩溃的标签在此刻才重建视图，避免坏页面在后台空转。
    if (tab.crashed) rebuildCrashedTab(tab);
    // 被内存节省休眠的标签切回时按原 URL 唤醒重载。
    if (tab.discarded) reloadDiscardedTab(tab);
    if (tab.view) {
      mainWindow.contentView.addChildView(tab.view);
      updateBrowserViewBounds();
    }
    sendToRenderer('tab-switched', { id: tab.id, index: tabIndex });
    pushNavState(tab);

    // 换标签时清掉旧标签上残留的查找高亮；若查找栏仍开着且有内容，
    // 在新标签上从头自动重查，保持“查找跟随当前标签”的浏览器惯例。
    const nextContents = getCurrentTabWebContents();
    if (prevContents && prevContents !== nextContents) {
      try { prevContents.stopFindInPage('clearSelection'); } catch (_) { /* 视图已销毁 */ }
    }
    if (findState.text && nextContents) applyFind(true);
  }
}

function closeTab(tabIndex) {
  if (tabIndex >= 0 && tabIndex < tabs.length) {
    const tab = tabs[tabIndex];
    addToRecentlyClosed(tab);
    popupOpenTimes.delete(tab.id);
    if (tab.view) tab.view.webContents.destroy();
    tabs.splice(tabIndex, 1);
    if (tabs.length === 0) {
      createNewTab(getDefaultTabUrl());
      currentTabIndex = 0;
    } else if (currentTabIndex >= tabs.length) {
      currentTabIndex = tabs.length - 1;
    }
    if (tabs.length > 0) switchToTab(currentTabIndex);
    sendToRenderer('tab-closed', tabIndex);
  }
}

// sanitizeDownloadFilename 防 Content-Disposition 路径穿越与视觉伪装：
// 服务端可能在 filename 里塞 "../../evil.exe"、RTL 反转符、结尾点空格或
// Windows 保留设备名。这里委托 dloadguard.sanitizeName：剥离目录组件与不可见
// 字符、剥掉结尾点空格、给保留名加前缀，返回可安全落盘的纯文件名。
function sanitizeDownloadFilename(name) {
  if (!name || typeof name !== 'string') return 'download';
  const res = dloadGuard.sanitizeName(name);
  if (res.rejected || !res.name) return 'download';
  // 双保险：dloadguard 已剥目录，这里再清一遍 Windows/Unix 保留字符。
  return res.name.replace(/[\\/:*?"<>|\x00-\x1f]/g, '_') || 'download';
}

// resolveUniqueDownloadPath 如果目标已存在，自动追加 (1)/(2)/... 避免覆盖
function resolveUniqueDownloadPath(dir, filename) {
  const ext = path.extname(filename);
  const stem = path.basename(filename, ext);
  let candidate = path.join(dir, filename);
  let counter = 1;
  while (fsSync.existsSync(candidate)) {
    candidate = path.join(dir, `${stem} (${counter})${ext}`);
    counter++;
  }
  return candidate;
}

// ===== 下载文件名伪装 / 危险类型台账（download-risk.json / cosy://security）=====
// 旧实现只看 path.extname 的最后一个扩展名，挡不住双扩展伪装（发票.exe.pdf）、
// RTL 反转、结尾点空格、MIME 与扩展名不符等手法。现在每次 will-download 都用
// dloadguard 做一次完整分析：confirm 的弹原生确认、reject 的直接取消、warn 的
// 保存但提示；全部命中写入本机台账供 cosy://security 审计。
const downloadRiskStorePath = path.join(app.getPath('userData'), 'download-risk.json');
const MAX_DOWNLOAD_RISK_RECORDS = 500;

// ===== 下载来源索引（内存）：savePath -> 来源 URL =====
// 仅供“打开文件”时判断是否需要对来自互联网的可执行文件二次确认；不落盘、
// 重启后清空（无来源信息的可执行文件同样会要求确认，宁严勿纵）。有界防膨胀。
const MAX_DOWNLOAD_ORIGIN_ENTRIES = 1000;
const downloadOriginByPath = new Map();
function rememberDownloadOrigin(savePath, originUrl) {
  if (!savePath || !originUrl) return;
  if (downloadOriginByPath.size >= MAX_DOWNLOAD_ORIGIN_ENTRIES) {
    const oldest = downloadOriginByPath.keys().next().value;
    downloadOriginByPath.delete(oldest);
  }
  downloadOriginByPath.set(savePath, originUrl);
}

const downloadRiskRecords = [];
let downloadRiskLoaded = false;
let downloadRiskSaveTimer = null;

function loadDownloadRisks() {
  if (downloadRiskLoaded) return;
  downloadRiskLoaded = true;
  try {
    const data = JSON.parse(fsSync.readFileSync(downloadRiskStorePath, 'utf8'));
    const entries = Array.isArray(data && data.records) ? data.records : null;
    if (!entries) return;
    for (const r of entries) {
      if (!r || typeof r !== 'object') continue;
      if (typeof r.filename !== 'string' || !r.filename) continue;
      downloadRiskRecords.push({
        time: Number(r.time) || Date.now(),
        filename: String(r.filename).slice(0, 255),
        host: typeof r.host === 'string' ? String(r.host).slice(0, 255) : '',
        decision: ['allow', 'warn', 'confirm', 'reject'].includes(r.decision) ? r.decision : 'warn',
        action: ['saved', 'confirmed', 'cancelled', 'rejected'].includes(r.action) ? r.action : 'saved',
        ext: typeof r.ext === 'string' ? String(r.ext).slice(0, 32) : '',
        risks: Array.isArray(r.risks) ? r.risks.slice(0, 20).map(x => ({
          id: typeof x.id === 'string' ? x.id : 'unknown',
          severity: ['allow', 'warn', 'confirm', 'reject'].includes(x.severity) ? x.severity : 'warn',
          message: typeof x.message === 'string' ? x.message.slice(0, 300) : '',
        })) : [],
      });
      if (downloadRiskRecords.length >= MAX_DOWNLOAD_RISK_RECORDS) break;
    }
  } catch {}
}

function persistDownloadRisks() {
  if (downloadRiskSaveTimer) clearTimeout(downloadRiskSaveTimer);
  downloadRiskSaveTimer = setTimeout(() => {
    try {
      const tmp = downloadRiskStorePath + '.tmp';
      fsSync.writeFileSync(tmp, JSON.stringify({ version: 1, records: downloadRiskRecords }), 'utf8');
      fsSync.renameSync(tmp, downloadRiskStorePath);
    } catch {}
  }, 300);
}

function recordDownloadRisk(entry) {
  loadDownloadRisks();
  downloadRiskRecords.push({
    time: Date.now(),
    filename: String(entry.filename || '').slice(0, 255),
    host: String(entry.host || '').slice(0, 255),
    decision: entry.decision || 'warn',
    action: entry.action || 'saved',
    ext: String(entry.ext || '').slice(0, 32),
    risks: Array.isArray(entry.risks) ? entry.risks.slice(0, 20) : [],
  });
  if (downloadRiskRecords.length > MAX_DOWNLOAD_RISK_RECORDS) {
    downloadRiskRecords.splice(0, downloadRiskRecords.length - MAX_DOWNLOAD_RISK_RECORDS);
  }
  persistDownloadRisks();
}

// listDownloadRisks 返回最近的风险记录（倒序，新的在前），供安全中心只读展示。
function listDownloadRisks(limit) {
  loadDownloadRisks();
  const max = Math.max(1, Math.min(500, Number(limit) || 200));
  return downloadRiskRecords.slice(-max).reverse().map(r => ({ ...r, risks: r.risks || [] }));
}

function clearDownloadRisks() {
  loadDownloadRisks();
  const n = downloadRiskRecords.length;
  downloadRiskRecords.length = 0;
  persistDownloadRisks();
  return n;
}

// 兼容旧调用名：现在基于 dloadguard 判断“是否需要用户确认/拒绝”。
// 返回 dloadguard 的完整分析结果（含原因链），供确认对话框展示。
function analyzeDownloadSafety(filename, mime) {
  return dloadGuard.analyzeDownloadName(filename, mime);
}

// confirmDownloadDecision 针对需要确认的下载弹出原生对话框，列出具体命中原因。
function confirmDownloadDecision(analysis, originUrl) {
  let host = '';
  try { host = new URL(originUrl).host; } catch { host = originUrl || '未知来源'; }
  const lines = analysis.risks
    .filter(r => r.severity === dloadGuard.DECISION.CONFIRM)
    .map(r => `• ${r.message}`)
    .slice(0, 6);
  const detail = [
    `文件：${analysis.displayName}`,
    `来源：${host}`,
    '',
    ...lines,
    '',
    '此文件可能会运行程序、更改系统设置，或经过伪装诱导打开。请仅在确认来源可信时保存。',
  ].join('\n');
  const choice = dialog.showMessageBoxSync(mainWindow, {
    type: 'warning',
    buttons: ['取消下载', '仍然保存'],
    defaultId: 0,
    cancelId: 0,
    title: '安全提示：存在风险的下载',
    message: '该下载可能会损害您的计算机或经过类型伪装，是否仍要保存？',
    detail,
    noLink: true,
  });
  return choice === 1;
}


function setupDownloadManager() {
  session.defaultSession.on('will-download', (event, item, webContents) => {
    const url = item.getURL();
    if (!isSafeUrl(url)) {
      recordSecurityEvent('download-blocked', 'critical',
        `阻止了来自不安全协议/地址的下载: ${url}`, originOfContents(webContents));
      event.preventDefault();
      return;
    }

    // 关键修复：不信任服务端给的 filename，先净化（路径穿越 + RTL/保留名/尾点）。
    const safeFilename = sanitizeDownloadFilename(item.getFilename());

    // 用 dloadguard 做完整伪装/类型分析，MIME 与文件名交叉比对。
    let mimeType = '';
    try { mimeType = typeof item.getMimeType === 'function' ? item.getMimeType() : ''; } catch { mimeType = ''; }
    const riskAnalysis = analyzeDownloadSafety(item.getFilename(), mimeType);
    // 净化后名字以分析内核给出的 displayName 为准（二者都已剥目录与不可见字符）。
    const finalFilename = riskAnalysis.displayName ? sanitizeDownloadFilename(riskAnalysis.displayName) : safeFilename;
    let dlHost = '';
    try { dlHost = new URL(url).host; } catch { dlHost = ''; }

    // reject：文件名无法净化成合法名字，直接取消。
    if (riskAnalysis.decision === dloadGuard.DECISION.REJECT) {
      try { item.cancel(); } catch {}
      recordSecurityEvent('download-blocked', 'critical',
        `拒绝保存文件名非法的下载: ${item.getFilename()}`, originOfContents(webContents));
      recordDownloadRisk({
        filename: item.getFilename(), host: dlHost, decision: 'reject', action: 'rejected',
        ext: riskAnalysis.finalExt, risks: riskAnalysis.risks,
      });
      sendToRenderer('show-toast', '下载文件名非法，已取消');
      return;
    }

    // confirm：可执行 / 伪装 / MIME 不符必须用户显式确认，阻断静默 drive-by 下载。
    if (riskAnalysis.decision === dloadGuard.DECISION.CONFIRM) {
      const allow = confirmDownloadDecision(riskAnalysis, url);
      if (!allow) {
        try { item.cancel(); } catch {}
        recordSecurityEvent('download-rejected', 'warn',
          `用户取消了存在风险的下载: ${finalFilename}`, originOfContents(webContents));
        recordDownloadRisk({
          filename: finalFilename, host: dlHost, decision: 'confirm', action: 'cancelled',
          ext: riskAnalysis.finalExt, risks: riskAnalysis.risks,
        });
        sendToRenderer('show-toast', `已取消存在风险的下载：${finalFilename}`);
        return;
      }
      recordSecurityEvent('download-confirmed', 'info',
        `用户确认保存存在风险的下载: ${finalFilename}`, originOfContents(webContents));
    }

    // warn：容器（内部文件不继承 MOTW）/ 本地 HTML 等，保存并轻提示。
    if (riskAnalysis.decision === dloadGuard.DECISION.WARN) {
      recordDownloadRisk({
        filename: finalFilename, host: dlHost, decision: 'warn',
        action: riskAnalysis.decision === dloadGuard.DECISION.CONFIRM ? 'confirmed' : 'saved',
        ext: riskAnalysis.finalExt, risks: riskAnalysis.risks,
      });
    }

    const totalBytes = item.getTotalBytes();
    let downloadInfo = downloads.find(d => d.url === url && d.item === null && d.isItemValid === false);
    if (downloadInfo) {
      downloadInfo.item = item;
      downloadInfo.filename = finalFilename;
      downloadInfo.totalBytes = totalBytes;
      downloadInfo.isItemValid = true;
      downloadInfo.status = 'downloading';
    } else {
      // 全新下载：不再 preventDefault + 新开下载页等用户确认，
      // 直接按现代浏览器行为自动保存到下载目录，由底部 shelf 展示进度。
      downloadInfo = {
        id: Date.now().toString(), url, filename: finalFilename, totalBytes,
        receivedBytes: 0, progress: 0, speed: '0 B/s', status: 'downloading',
        startTime: Date.now(), savePath: null, item,
        lastUpdate: Date.now(), lastReceivedBytes: 0, isItemValid: true,
        expectedHash: null
      };
      downloads.push(downloadInfo);
    }
    currentDownloadInfo = downloadInfo;
    if (downloadInfo.savePath) {
      item.setSavePath(downloadInfo.savePath);
    } else {
      const defaultSavePath = resolveUniqueDownloadPath(app.getPath('downloads'), finalFilename);
      item.setSavePath(defaultSavePath);
      downloadInfo.savePath = defaultSavePath;
    }
    sendShelf();
    sendToRenderer('download-status-changed', { id: downloadInfo.id, status: 'downloading' });
    item.on('updated', (event, state) => {
      if (state === 'progressing') {
        const receivedBytes = item.getReceivedBytes();
        const totalBytes = item.getTotalBytes();
        const progress = totalBytes > 0 ? ((receivedBytes / totalBytes) * 100).toFixed(2) : 0;
        const now = Date.now();
        const timeDiff = (now - downloadInfo.lastUpdate) / 1000;
        if (timeDiff > 0) {
          const bytesDiff = receivedBytes - downloadInfo.lastReceivedBytes;
          downloadInfo.speed = formatSpeed(bytesDiff / timeDiff);
        }
        downloadInfo.receivedBytes = receivedBytes;
        downloadInfo.progress = progress;
        downloadInfo.lastUpdate = now;
        downloadInfo.lastReceivedBytes = receivedBytes;
        downloadInfo.status = 'downloading';
        sendToRenderer('download-progress', { id: downloadInfo.id, receivedBytes, totalBytes, progress, speed: downloadInfo.speed });
        sendShelf();
      }
    });
    item.on('done', (event, state) => {
      downloadInfo.isItemValid = false;
      if (state === 'completed') {
        downloadInfo.status = 'complete';
        downloadInfo.savePath = item.getSavePath();
        sendToRenderer('download-complete', { id: downloadInfo.id, savePath: downloadInfo.savePath });
        // 登记来源，供“打开文件”时判断互联网可执行文件是否需要二次确认。
        const completedUrl = downloadInfo.url || url;
        rememberDownloadOrigin(downloadInfo.savePath, completedUrl);
        // 下载完成后排进串行摘要队列，异步算 SHA-256 并登记到 cosy://hashes；
        // 用净化后的文件名与来源 URL，不落完整本地路径。
        queueDownloadHashing({
          id: downloadInfo.id,
          savePath: downloadInfo.savePath,
          url: completedUrl,
          filename: downloadInfo.filename || safeFilename,
        });
        // 显式补写 Windows Mark-of-the-Web（Zone.Identifier ADS）。Chromium
        // 自定义落盘/跨盘移动/从压缩包解出都可能丢失 MOTW；best-effort，失败
        // （非 NTFS/权限）只审计，不影响已完成的下载。
        try {
          const motw = quarantine.applyMarkOfTheWeb(
            { platform: process.platform, appendFileSync: fsSync.appendFileSync },
            downloadInfo.savePath,
            { hostUrl: completedUrl, lastWriteTime: new Date().toISOString() }
          );
          if (motw.wrote === false && motw.reason !== 'not-internet' &&
              motw.reason !== 'unsupported-platform') {
            recordSecurityEvent('download-motw', 'info',
              `MOTW 标记未写入 (${motw.reason}): ${downloadInfo.filename || ''}`,
              originOfContents(webContents));
          }
        } catch (motwErr) {
          recordSecurityEvent('download-motw', 'info',
            `MOTW 标记异常: ${String(motwErr && motwErr.message || motwErr)}`,
            originOfContents(webContents));
        }
      } else {
        downloadInfo.status = 'error';
        sendToRenderer('download-error', { id: downloadInfo.id });
      }
      sendShelf();
    });
  });
}

function formatSpeed(bytesPerSecond) {
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  let speed = bytesPerSecond;
  let unitIndex = 0;
  while (speed >= 1024 && unitIndex < units.length - 1) { speed /= 1024; unitIndex++; }
  return speed.toFixed(2) + ' ' + units[unitIndex];
}

function generateUserAgent() {
  const platform = os.platform();
  const arch = os.arch();
  const release = os.release();
  const chromeVersion = process.versions.chrome;
  let osInfo;
  switch (platform) {
    case 'win32':
      if (release.startsWith('10.')) osInfo = 'Windows NT 10.0';
      else if (release.startsWith('6.3')) osInfo = 'Windows NT 6.3';
      else if (release.startsWith('6.2')) osInfo = 'Windows NT 6.2';
      else if (release.startsWith('6.1')) osInfo = 'Windows NT 6.1';
      else if (release.startsWith('6.0')) osInfo = 'Windows NT 6.0';
      else osInfo = 'Windows NT 10.0';
      osInfo += arch === 'x64' ? '; Win64; x64' : '; WOW64';
      break;
    case 'darwin':
      const macVersion = release.split('.').slice(0, 2).join('.');
      osInfo = `Macintosh; Intel Mac OS X ${macVersion.replace('.', '_')}`;
      break;
    case 'linux':
      if (arch === 'x64') osInfo = 'X11; Linux x86_64';
      else if (arch === 'arm64') osInfo = 'X11; Linux aarch64';
      else osInfo = 'X11; Linux i686';
      break;
    default: osInfo = 'X11; Unknown';
  }
  return `Mozilla/5.0 (${osInfo}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion} OpenCosyBrowser/1.0.0`;
}

// reviewToOpenUrl 把 deeplinkguard 的放行结论转成可打开 URL；本地文件需存在。
function reviewToOpenUrl(review) {
  if (!review || !review.ok) return null;
  if (review.kind === 'local-html') {
    if (!fsSync.existsSync(review.value)) return null;
    return pathToFileURL(review.value).href;
  }
  return review.value; // web / internal 均已是规范化 href
}

// resolveStartupDeepLink 把一条不可信入口参数（argv / open-file / open-url）
// 经 deeplinkguard 消毒后，统一转成可打开的目标 URL；不合法返回 null 并记审计。
function resolveStartupDeepLink(rawArg, source) {
  const review = deeplinkGuard.reviewStartupArg(rawArg);
  if (!review.ok) {
    recordSecurityEvent('deeplink-blocked', 'warn',
      `启动深链被拦截（来源:${source}，${deeplinkGuard.describeReason(review.reason)}）`, '');
    return null;
  }
  return reviewToOpenUrl(review);
}

// resolveStartupArgv 从整条命令行里找第一个合法深链（Windows 协议唤起位置不固定）。
function resolveStartupArgv(argv) {
  const review = deeplinkGuard.pickDeepLinkFromArgv(argv);
  return review ? reviewToOpenUrl(review) : null;
}

const startupTarget = resolveStartupArgv(process.argv);
if (startupTarget) fileToOpen = startupTarget;

app.on('open-file', (event, filePath) => {
  event.preventDefault();
  // 经 deeplinkguard 收口：只允许存在的本地 .html/.htm，挡 UNC / 穿越 / 开关样输入。
  const fileUrl = resolveStartupDeepLink(filePath, 'open-file');
  if (!fileUrl) return;
  if (mainWindow && mainWindow.isReady()) {
    const newTab = createNewTab(fileUrl);
    switchToTab(tabs.indexOf(newTab));
  } else {
    fileToOpen = fileUrl;
  }
});

app.whenReady().then(async () => {
  loadHistory();
  loadBookmarks();
  loadZoomFactors();

  // 启动时还原 darkMode / httpsOnly / memorySaver 等运行时状态
  const stored = readStoredSettings();
  applyDarkMode(!!stored.darkMode);
  httpsOnlyEnabled = stored.httpsOnly !== false;
  blockTrackers = stored.blockTrackers !== false;
  blockThirdPartyCookies = stored.blockThirdPartyCookies !== false;
  hardenCookies = stored.hardenCookies !== false;
  blockLocalNetworkAccess = stored.blockLocalNetworkAccess !== false;
  reduceClientHints = stored.reduceClientHints !== false;
  blockAdSignals = stored.blockAdSignals !== false;
  blockHyperlinkPing = stored.blockHyperlinkPing !== false;
  stripAcceptCh = stored.stripAcceptCh !== false;
  if ('webrtcMode' in stored) webrtcMode = fpGuard.normalizeWebRtcMode(stored.webrtcMode);
  dohMode = dohGuard.normalizeMode(stored.dohMode);
  if (typeof stored.dohProvider === 'string') dohProvider = stored.dohProvider;
  if (typeof stored.dohCustomUrl === 'string') dohCustomUrl = stored.dohCustomUrl;
  crashRecoveryEnabled = stored.crashRecovery !== false;
  stripTrackingParams = stored.stripTrackingParams !== false;
  if ('memorySaver' in stored) memorySaverEnabled = !!stored.memorySaver;
  if ('clearOnExit' in stored) clearOnExit = !!stored.clearOnExit;
  if ('confirmCloseMultiple' in stored) confirmCloseMultiple = !!stored.confirmCloseMultiple;
  startMemorySaver();

  if (process.platform === 'win32') app.setAsDefaultProtocolClient('cosy');

  protocol.registerFileProtocol('cosy', (request, callback) => {
    try {
      // host 白名单映射，path/query 一律不参与文件选择，杜绝 cosy: 路径穿越。
      const r = cosyScheme.resolveCosyFilePath(request.url, path.join(__dirname, 'src'));
      callback({ path: r.absolutePath });
    } catch (e) {
      console.error('注册cosy协议失败:', e);
      callback({ path: path.join(__dirname, 'src', 'newtab.html') });
    }
  });

  protocol.registerFileProtocol('file', (request, callback) => {
    try {
      // 用 WHATWG URL + fileURLToPath 归一，拒绝 file://server/share 远程/UNC host，
      // 并把可读路径严格收敛进 getSafeDirs() 允许目录。
      const verdict = cosyScheme.resolveAllowedFileUrl(request.url, getSafeDirs());
      if (verdict.ok) {
        callback({ path: verdict.path });
      } else {
        if (verdict.reason === 'remote-host') {
          recordSecurityEvent('file-remote-blocked', 'warn',
            '拒绝经 file: 协议访问远程/UNC 主机', request.url);
        }
        callback({ error: -3 });
      }
    } catch (e) {
      console.error('注册file协议失败:', e);
      callback({ error: -3 });
    }
  });

  setupPermissionHandlers();
  setupSecurityHeaders();
  // r34：注册 app 级 GPU/无障碍系统事件守卫，并为后续 fromPartition 新会话补齐默认
  // 拒绝权限/设备策略与出向隐私头（须在 defaultSession 加固之后，靠去重跳过默认会话）。
  setupSystemEventGuards();
  setupExtraSessionHardening();

  // 启动期解析到的降硬开关在 ready 前只能写 stderr；安全事件存储就绪后补登一条聚合
  // 记录，方便在安全页面板排查被篡改的快捷方式/启动器（critical 的已直接退出，到不了这）。
  if (launchSwitchAudit.warnFlags.length > 0) {
    const desc = launchSwitchAudit.warnFlags
      .map(f => `${f.flag.raw}(${f.source})`)
      .join(', ');
    recordSecurityEvent('launch-switch-warn', 'warn',
      `检测到 ${launchSwitchAudit.warnFlags.length} 个降硬启动开关：${desc}`, '');
  }
  applyWebRtcPolicy();
  applySecureDns();
  setupDownloadManager();
  setupGlobalWebContentsHooks();
  setupNetworkAuth();
  setupNetworkStatus();
  // 拼写检查开关与语言在首个页面加载前就按持久化设置生效。
  const persisted = readPersistedSettings();
  spellcheckEnabled = persisted.spellcheckEnabled !== false;
  spellcheckLanguages = sanitizeSpellcheckLanguages(persisted.spellcheckLanguages);
  applySpellcheckSettings();
  session.defaultSession.setUserAgent(generateUserAgent());
  createWindow();
  await loadEnabledExtensions();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('open-url', (event, url) => {
  event.preventDefault();
  // macOS 深链统一走 deeplinkguard：http(s) 严格解析，cosy: 主机必须白名单。
  const target = resolveStartupDeepLink(url, 'open-url');
  if (!target) return;
  if (!mainWindow || mainWindow.isDestroyed()) createWindow();
  setTimeout(() => {
    if (target.startsWith('cosy://') || target.startsWith('http://') || target.startsWith('https://')) {
      createNewTab(target);
    }
  }, 100);
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// child-process-gone 覆盖 GPU / utility / network 等非渲染子进程。
// Electron 通常会自动重启 GPU 进程，这里只记录并在异常退出（非正常清理）时
// 通知用户可能出现花屏/视频解码失效，提示重载标签，而不是静默吞掉。
app.on('child-process-gone', (event, details) => {
  console.error('子进程退出:', details?.type, details?.reason, details?.exitCode);
  try {
    if (mainWindow && !mainWindow.isDestroyed() && details?.reason !== 'clean-exit') {
      sendToRenderer('show-toast',
        `浏览器${details?.type || ''}进程异常（${details?.reason || 'unknown'}），如页面显示异常请按 Ctrl+R 重载`);
    }
  } catch {}
});

ipcMain.on('window-control', (event, action) => {
  if (!isMainSender(event)) return;
  switch (action) {
    case 'minimize': mainWindow.minimize(); break;
    case 'maximize': mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize(); break;
    case 'close': mainWindow.close(); break;
  }
});

ipcMain.on('toggle-tabbar-collapse', (event, collapsed) => {
  if (!isMainSender(event)) return;
  isTabBarCollapsed = collapsed;
  updateBrowserViewBounds();
});

ipcMain.handle('navigate-tab', (event, { tabId, url }) => {
  if (!isMainSender(event)) return { success: false, error: 'Unauthorized' };
  if (!isSafeUrl(url)) return { success: false, error: 'Unsafe URL' };
  const tab = tabs.find(t => t.id === tabId);
  if (tab) {
    tab.url = url;
    loadTabContent(tab);
    sendToRenderer('tab-updated', { id: tab.id, url });
    return { success: true };
  }
  return { success: false };
});

ipcMain.handle('navigate-back', (event) => {
  if (!isMainSender(event)) return { success: false };
  const wc = getCurrentTabWebContents();
  if (wc?.canGoBack()) { wc.goBack(); return { success: true }; }
  return { success: false };
});

ipcMain.handle('navigate-forward', (event) => {
  if (!isMainSender(event)) return { success: false };
  const wc = getCurrentTabWebContents();
  if (wc?.canGoForward()) { wc.goForward(); return { success: true }; }
  return { success: false };
});

ipcMain.handle('reload-tab', (event, hard) => {
  if (!isMainSender(event)) return { success: false };
  const wc = getCurrentTabWebContents();
  if (!wc) return { success: false };
  if (hard) wc.reloadIgnoringCache(); else wc.reload();
  return { success: true };
});

ipcMain.handle('stop-loading', (event) => {
  if (!isMainSender(event)) return { success: false };
  const wc = getCurrentTabWebContents();
  if (wc) wc.stop();
  return { success: true };
});

ipcMain.handle('duplicate-tab', (event, tabIndex) => {
  if (!isMainSender(event)) return { success: false };
  const idx = typeof tabIndex === 'number' && tabIndex >= 0 ? tabIndex : currentTabIndex;
  const tab = tabs[idx];
  if (!tab || !isSafeUrl(tab.url)) return { success: false };
  const newTab = createNewTab(tab.url);
  return { id: newTab.id, index: tabs.indexOf(newTab) };
});

// reopen-closed-tab 恢复最近关闭的标签（Ctrl+Shift+T）。
// recentlyClosedTabs 在入栈时已剔除 cosy:// 内置页，这里再做一次
// isSafeUrl 校验，防止历史数据被污染后恢复到危险协议。
ipcMain.handle('reopen-closed-tab', (event) => {
  if (!isMainSender(event)) return { success: false };
  while (recentlyClosedTabs.length > 0) {
    const last = getLastClosedTab();
    if (!last || !last.url) continue;
    if (!isSafeUrl(last.url) || last.url.startsWith('cosy://')) continue;
    const tab = createNewTab(last.url);
    return { success: true, id: tab.id, index: tabs.indexOf(tab), url: last.url };
  }
  return { success: false, empty: true };
});

ipcMain.handle('create-tab', (event, url) => {
  if (!isMainSender(event)) return { success: false };
  if (!isSafeUrl(url)) url = 'cosy://newtab';
  const tab = createNewTab(url);
  return { id: tab.id, index: tabs.length - 1 };
});

ipcMain.handle('close-tab', (event, tabIndex) => {
  if (!isMainSender(event)) return { success: false };
  closeTab(tabIndex);
  return { success: true };
});

ipcMain.handle('switch-tab', (event, tabIndex) => {
  if (!isMainSender(event)) return { success: false };
  switchToTab(tabIndex);
  return { success: true };
});

// set-tab-muted 静音 / 取消静音指定标签（默认当前标签）。
// tabId 由渲染进程传入，统一转字符串比较，避免类型不一致误判。
// 每个源（origin）记住一个缩放系数，导航 / 刷新后自动恢复，行为对齐 Chrome。
const zoomFactorsByOrigin = new Map();
const MIN_ZOOM_FACTOR = 0.25;
const MAX_ZOOM_FACTOR = 5;
const MAX_REMEMBERED_ORIGINS = 500;
const zoomStorePath = path.join(app.getPath('userData'), 'zoom-store.json');
let zoomSaveTimer = null;

function clampZoomFactor(f) {
  if (!Number.isFinite(f)) return 1;
  return Math.min(MAX_ZOOM_FACTOR, Math.max(MIN_ZOOM_FACTOR, f));
}

function originOfUrl(u) {
  try { return new URL(u).origin; } catch { return ''; }
}

// loadZoomFactors 启动时从 userData 读取按站点记忆的缩放（对齐 Chrome 跨重启保留缩放）。
// 文件损坏 / 被外部塞非法内容时静默丢弃，绝不因此影响浏览器启动。
function loadZoomFactors() {
  try {
    const raw = fsSync.readFileSync(zoomStorePath, 'utf8');
    const data = JSON.parse(raw);
    if (!data || typeof data !== 'object' || !data.origins || typeof data.origins !== 'object') return;
    for (const [origin, factor] of Object.entries(data.origins)) {
      if (typeof origin !== 'string' || !/^https?:|^cosy:/.test(origin)) continue;
      if (typeof factor !== 'number' || !Number.isFinite(factor)) continue;
      zoomFactorsByOrigin.set(origin, clampZoomFactor(factor));
      if (zoomFactorsByOrigin.size >= MAX_REMEMBERED_ORIGINS) break;
    }
  } catch {}
}

// persistZoomFactors 防抖落盘，避免连续放大缩小频繁写文件。
function persistZoomFactors() {
  if (zoomSaveTimer) clearTimeout(zoomSaveTimer);
  zoomSaveTimer = setTimeout(() => {
    try {
      const origins = {};
      for (const [origin, factor] of zoomFactorsByOrigin) origins[origin] = factor;
      const tmp = zoomStorePath + '.tmp';
      fsSync.writeFileSync(tmp, JSON.stringify({ version: 1, origins }), 'utf8');
      fsSync.renameSync(tmp, zoomStorePath);
    } catch {}
  }, 400);
}

function applySavedZoom(tab) {
  if (!tab || !tab.view || !tab.view.webContents) return;
  const origin = originOfUrl(tab.url);
  if (origin && zoomFactorsByOrigin.has(origin)) {
    tab.view.webContents.setZoomFactor(zoomFactorsByOrigin.get(origin));
  }
}

// adjustCurrentZoom 是菜单快捷键与 IPC 共用的唯一缩放入口：
// 统一用 setZoomFactor（不要混用 setZoomLevel，二者写同一底层值会互相覆盖），
// 计算结果按 origin 记忆、导航恢复、并持久化到磁盘。
function adjustCurrentZoom({ delta, factor: explicit } = {}) {
  const tab = tabs[currentTabIndex];
  if (!tab || !tab.view || !tab.view.webContents) return null;
  const wc = tab.view.webContents;
  const origin = originOfUrl(tab.url);
  let factor = 1;
  try { factor = wc.getZoomFactor(); } catch { factor = (origin && zoomFactorsByOrigin.get(origin)) || 1; }
  if (!Number.isFinite(factor) || factor <= 0) factor = 1;

  if (typeof explicit === 'number' && Number.isFinite(explicit)) {
    factor = explicit;
  } else if (delta === 'in') {
    factor *= 1.1;
  } else if (delta === 'out') {
    factor /= 1.1;
  }
  factor = clampZoomFactor(Math.round(factor * 1000) / 1000);
  wc.setZoomFactor(factor);
  if (origin) {
    zoomFactorsByOrigin.set(origin, factor);
    persistZoomFactors();
  }
  const percent = Math.round(factor * 100);
  // 通知渲染层显示缩放百分比浮层（对齐 Chrome 放大/缩小时的 OSD）。
  sendToRenderer('zoom-level-changed', { percent, factor });
  return { factor, percent };
}

ipcMain.handle('set-tab-muted', (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false };
  const { tabId, muted } = payload || {};
  const tab = (tabId === undefined || tabId === null)
    ? tabs[currentTabIndex]
    : tabs.find(t => String(t.id) === String(tabId));
  if (!tab || !tab.view || !tab.view.webContents) return { success: false };
  tab.muted = !!muted;
  tab.view.webContents.setAudioMuted(tab.muted);
  try { tab.audible = !!tab.view.webContents.isCurrentlyAudible(); } catch {}
  sendToRenderer('tab-audio-changed', { id: tab.id, audible: tab.audible, muted: tab.muted });
  return { success: true, muted: tab.muted };
});

// set-zoom 调整当前标签缩放。delta 为档位变化（Chrome 每档约 1.1/0.9 倍），
// factor 直接指定（Ctrl+0 复位为 1）。按 origin 记忆，导航后自动恢复。
ipcMain.handle('set-zoom', (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false };
  const result = adjustCurrentZoom(payload || {});
  if (!result) return { success: false };
  return { success: true, factor: result.factor, percent: result.percent };
});

ipcMain.on('navigate-to-url', (event, url) => {
  if (!isMainSender(event)) return;
  if (url && isSafeUrl(url)) createNewTab(url);
});

ipcMain.on('get-download-info', (event) => {
  // 只允许主界面查询当前下载信息，防止任何被攻陷的 webContents
  // 通过该通道读取本地保存路径等环境信息。
  if (!isMainSender(event)) return;
  if (currentDownloadInfo) {
    event.reply('download-info', {
      url: currentDownloadInfo.url,
      filename: currentDownloadInfo.filename,
      totalBytes: currentDownloadInfo.totalBytes || 0
    });
  }
});

ipcMain.on('start-download', (event, data) => {
  if (!isMainSender(event)) return;
  if (currentDownloadInfo) {
    try {
      let savePath;
      if (data.savePath) {
        savePath = path.resolve(data.savePath);
        if (!isInSafeDirs(savePath)) {
          savePath = path.join(app.getPath('downloads'), currentDownloadInfo.filename);
        }
      } else {
        savePath = path.join(app.getPath('downloads'), currentDownloadInfo.filename);
      }
      if (currentDownloadInfo.item && currentDownloadInfo.isItemValid) {
        currentDownloadInfo.item.setSavePath(savePath);
        currentDownloadInfo.savePath = savePath;
        currentDownloadInfo.status = 'downloading';
      } else {
        currentDownloadInfo.savePath = savePath;
        currentDownloadInfo.status = 'pending';
        currentDownloadInfo.item = null;
        currentDownloadInfo.isItemValid = false;
        session.defaultSession.downloadURL(currentDownloadInfo.url);
      }
      sendToRenderer('download-started', { id: currentDownloadInfo.id });
    } catch (e) {
      console.error('启动下载失败:', e);
      currentDownloadInfo.isItemValid = false;
      currentDownloadInfo.status = 'error';
    }
  }
});

ipcMain.on('show-save-dialog', (event, data) => {
  if (!isMainSender(event)) return;
  dialog.showSaveDialog(mainWindow, {
    defaultPath: path.join(app.getPath('downloads'), data.defaultName || 'download'),
    filters: [{ name: 'All Files', extensions: ['*'] }]
  }).then(result => {
    if (!result.canceled && result.filePath) {
      if (currentDownloadInfo && currentDownloadInfo.item && currentDownloadInfo.isItemValid) {
        try {
          const state = currentDownloadInfo.item.getState();
          if (state === 'progressing' || state === 'interrupted') currentDownloadInfo.item.cancel();
          currentDownloadInfo.isItemValid = false;
          currentDownloadInfo.status = 'error';
        } catch (e) { console.error('取消下载以另存为失败:', e); }
      }
      if (currentDownloadInfo) {
        currentDownloadInfo.savePath = result.filePath;
        currentDownloadInfo.status = 'pending';
        currentDownloadInfo.item = null;
        currentDownloadInfo.isItemValid = false;
      }
      if (data.url && isSafeUrl(data.url)) session.defaultSession.downloadURL(data.url);
      event.reply('download-started', { id: currentDownloadInfo ? currentDownloadInfo.id : null });
    }
  });
});

ipcMain.on('get-downloads', (event) => {
  if (!isMainSender(event)) return;
  const serializableDownloads = downloads.map(d => ({
    id: d.id, url: d.url, filename: d.filename, totalBytes: d.totalBytes,
    receivedBytes: d.receivedBytes, progress: d.progress, speed: d.speed,
    status: d.status, startTime: d.startTime, savePath: d.savePath
  }));
  event.reply('downloads-list', serializableDownloads);
});

// ===== 底部下载栏 IPC =====
ipcMain.handle('get-download-shelf', () => shelfSnapshot());

ipcMain.on('shelf-show-all', (event) => {
  if (!isMainSender(event)) return;
  createNewTab('cosy://downloadlist');
});

ipcMain.on('pause-download', (event, id) => {
  if (!isMainSender(event)) return;
  const download = downloads.find(d => d.id === id);
  if (download && download.item && download.isItemValid) {
    try {
      if (download.item.getState() === 'progressing') {
        download.item.pause();
        download.status = 'paused';
        sendToRenderer('download-status-changed', { id: download.id, status: 'paused' });
        sendShelf();
      }
    } catch (e) {
      console.error('暂停下载失败:', e);
      download.isItemValid = false; download.status = 'error';
      sendToRenderer('download-status-changed', { id: download.id, status: 'error' });
    }
  }
});

ipcMain.on('resume-download', (event, id) => {
  if (!isMainSender(event)) return;
  const download = downloads.find(d => d.id === id);
  if (download && download.item && download.isItemValid) {
    try {
      const state = download.item.getState();
      if (state === 'interrupted' || state === 'cancelled') {
        download.item.resume();
        download.status = 'downloading';
        sendToRenderer('download-status-changed', { id: download.id, status: 'downloading' });
        sendShelf();
      }
    } catch (e) {
      console.error('恢复下载失败:', e);
      download.isItemValid = false; download.status = 'error';
      sendToRenderer('download-status-changed', { id: download.id, status: 'downloading' });
    }
  }
});

ipcMain.on('cancel-download', (event, id) => {
  if (!isMainSender(event)) return;
  const download = downloads.find(d => d.id === id);
  if (download && download.item && download.isItemValid) {
    try {
      const state = download.item.getState();
      if (state === 'progressing' || state === 'interrupted') download.item.cancel();
      download.isItemValid = false; download.status = 'error';
      sendToRenderer('download-status-changed', { id: download.id, status: 'error' });
    } catch (e) {
      console.error('取消下载失败:', e);
      download.isItemValid = false; download.status = 'error';
      sendToRenderer('download-status-changed', { id: download.id, status: 'error' });
    }
  }
});

ipcMain.on('retry-download', (event, data) => {
  if (!isMainSender(event)) return;
  const { url } = data;
  if (url && isSafeUrl(url)) session.defaultSession.downloadURL(url);
});

ipcMain.on('remove-download', (event, id) => {
  if (!isMainSender(event)) return;
  const index = downloads.findIndex(d => d.id === id);
  if (index !== -1) {
    downloads.splice(index, 1);
    sendToRenderer('download-removed', { id });
    sendShelf();
  }
});

ipcMain.on('open-file', (event, filePath) => {
  if (!isMainSender(event)) return;
  const resolved = path.resolve(filePath);
  if (!isInSafeDirs(resolved) || !fsSync.existsSync(resolved)) return;

  // 打开“来自互联网（或来源未知）的可执行 / 脚本 / 安装包”前必须二次确认，
  // 防止用户在下载列表里误点直接运行 drive-by 下载的程序。
  const originUrl = downloadOriginByPath.has(resolved)
    ? downloadOriginByPath.get(resolved)
    : null;
  const exeDecision = quarantine.openDecision({ filePath: resolved, hostUrl: originUrl });
  // 容器类（压缩包 / 宏 Office / 磁盘镜像）：MOTW 不会随解压继承，来自互联网
  // （或来源未知）的容器打开前同样确认。
  const fromWeb = originUrl ? quarantine.isWebDownload(originUrl) : false;
  const baseName = path.basename(resolved);
  const containerClass = containerGuard.classifyContainer(baseName);
  const containerDecision = originUrl == null
    ? (containerClass.kind === containerGuard.KIND_NONE ? containerGuard.RISK_ALLOW : containerGuard.RISK_CONFIRM)
    : containerGuard.openContainerDecision({ filename: baseName, fromWeb });
  const needConfirm = exeDecision === 'confirm' ||
    containerDecision === 'confirm' || containerDecision === 'warn';

  if (needConfirm) {
    let host = '未知来源';
    if (originUrl) {
      try { host = new URL(originUrl).host; } catch { host = originUrl; }
    }
    const containerAdvice = containerGuard.describeContainerRisk(containerClass);
    const choice = dialog.showMessageBoxSync(mainWindow, {
      type: 'warning',
      buttons: ['取消', '仍然运行'],
      defaultId: 0,
      cancelId: 0,
      title: '安全提示：运行来自互联网的程序',
      message: `确定要打开 "${baseName}" 吗？`,
      detail: [
        `来源：${host}`,
        '',
        containerAdvice ||
          '该文件是可执行程序或脚本，来自互联网（或来源不明），可能会危害您的',
        containerAdvice ? '' : '计算机或更改系统设置。请仅在确认其来源可信时运行。',
      ].filter(l => l !== undefined).join('\n').replace(/\n{3,}/g, '\n\n'),
      noLink: true,
    });
    if (choice !== 1) {
      recordSecurityEvent('download-open-blocked', 'info',
        `用户取消运行来自互联网的文件: ${baseName}`, host);
      return;
    }
  }
  // 交给系统打开前再走一次路径消毒（控制字符 / UNC / 穿越）。可执行文件是否
  // 允许运行已由上面的来源确认决定，这里只挡畸形与越界路径。
  const launchReview = shellGuard.reviewLocalLaunchPath(resolved, true);
  if (!launchReview.ok) {
    recordSecurityEvent('download-blocked', 'warn',
      `打开本地文件被路径消毒拦截（${shellGuard.describeReason(launchReview.reason)}）`, '');
    sendToRenderer('show-toast', '已阻止打开：文件路径不安全');
    return;
  }
  shell.openPath(resolved);
});

ipcMain.on('open-folder', (event, filePath) => {
  if (!isMainSender(event)) return;
  const resolved = path.resolve(filePath);
  if (!isInSafeDirs(resolved) || !fsSync.existsSync(resolved)) return;
  const revealReview = shellGuard.reviewLocalLaunchPath(resolved, true);
  if (!revealReview.ok) {
    recordSecurityEvent('download-blocked', 'warn',
      `定位本地文件被路径消毒拦截（${shellGuard.describeReason(revealReview.reason)}）`, '');
    return;
  }
  shell.showItemInFolder(resolved);
});

// open-external-url renderer 统一入口：点 mailto:/tel: 走这里，
// 主进程做协议校验 + 按站点记忆 + 原生确认，再调 shell.openExternal。
ipcMain.handle('open-external-url', async (event, url) => {
  if (!isMainSender(event)) return { ok: false, reason: 'unauthorized' };
  let origin = '';
  try { origin = new URL(event.sender.getURL()).origin; } catch {}
  return await confirmAndOpenExternal(String(url || ''), origin);
});

// 供设置页读取 / 撤销"站点 -> 外部协议"的记忆决定。
ipcMain.handle('get-protocol-decisions', (event) => {
  if (!isMainSender(event)) return { ok: false, reason: 'unauthorized' };
  loadProtocolDecisions();
  const items = [];
  for (const [k, v] of protocolDecisions) {
    const sp = k.indexOf(' ');
    items.push({ origin: k.slice(0, sp), scheme: k.slice(sp + 1), decision: v.decision, updatedAt: v.updatedAt });
  }
  items.sort((a, b) => b.updatedAt - a.updatedAt);
  return { ok: true, items };
});

ipcMain.handle('clear-protocol-decision', (event, data) => {
  if (!isMainSender(event)) return { ok: false, reason: 'unauthorized' };
  const origin = data && typeof data.origin === 'string' ? data.origin : '';
  const scheme = data && typeof data.scheme === 'string' ? data.scheme : '';
  if (!isRememberableOrigin(origin) || !CONFIRMABLE_EXTERNAL_SCHEMES.has(scheme)) {
    return { ok: false, reason: 'invalid key' };
  }
  const deleted = protocolDecisions.delete(protocolDecisionKey(origin, scheme));
  if (deleted) persistProtocolDecisions();
  return { ok: true, deleted };
});

ipcMain.on('clear-downloads', (event) => {
  if (!isMainSender(event)) return;
  downloads = [];
  currentDownloadInfo = null;
  sendToRenderer('downloads-cleared');
  setTimeout(() => {
    sendToRenderer('clear-downloads-success', '下载列表已成功清空');
  }, 100);
});

ipcMain.handle('get-current-tab', (event) => {
  if (!isMainSender(event)) return null;
  if (tabs.length > 0 && currentTabIndex >= 0) {
    const tab = tabs[currentTabIndex];
    return {
      id: tab.id, url: tab.url, title: tab.title, favicon: tab.favicon,
      isLoading: tab.isLoading, canGoBack: tab.canGoBack, canGoForward: tab.canGoForward
    };
  }
  return null;
});

ipcMain.handle('get-all-tabs', (event) => {
  if (!isMainSender(event)) return [];
  return tabs.map(tab => ({
    id: tab.id, url: tab.url, title: tab.title, favicon: tab.favicon,
    isLoading: tab.isLoading, canGoBack: tab.canGoBack, canGoForward: tab.canGoForward,
    discarded: !!tab.discarded
  }));
});

ipcMain.on('close-current-tab', (event) => {
  if (!isMainSender(event)) return;
  if (tabs.length > 0) closeTab(currentTabIndex);
});

// 页内查找当前状态。查找栏输入会实时更新这里，供 F3 / Ctrl+G 继续查找、
// 以及切换标签后在新标签上自动重查使用。
let findState = { text: '', matchCase: false, wholeWord: false };
// 页内查找 IPC 的输入 / 频率守卫状态（查找栏全局唯一，用单实例即可）。
let findRateState = findGuard.createFindState(Date.now());

// applyFind 在当前活动标签上按 findState 执行一次查找。
function applyFind(forward = true) {
  const wc = getCurrentTabWebContents();
  if (!wc || !findState.text) return;
  wc.findInPage(findState.text, {
    forward,
    matchCase: !!findState.matchCase,
    wholeWord: !!findState.wholeWord,
  });
}

ipcMain.on('find-in-page', (event, payload) => {
  if (!isMainSender(event)) return;
  const { text, forward, matchCase, wholeWord } = payload || {};
  // 输入与频率全部过 findguard：拒非字符串 / 超长 / 控制字符，合并极短重复提交，
  // 按键洪泛时进入短暂冷却，避免超长 query 匹配与 found-in-page 广播拖慢渲染进程。
  const v = findGuard.decideFind(
    findRateState,
    { text, matchCase: !!matchCase, wholeWord: !!wholeWord },
    Date.now()
  );
  if (v.decision === findGuard.FIND_REJECT) {
    const severity = (v.reason === findGuard.HOLD_BURST || v.reason === findGuard.HOLD_COOLDOWN)
      ? 'info' : 'warn';
    recordSecurityEvent('find-rate-limited', severity, findGuard.describeFindReason(v.reason), '');
    return;
  }
  const wc = getCurrentTabWebContents();
  if (v.decision === findGuard.FIND_SKIP_EMPTY) {
    findState = { text: '', matchCase: !!matchCase, wholeWord: !!wholeWord };
    if (wc) wc.stopFindInPage('clearSelection');
    return;
  }
  if (v.decision === findGuard.FIND_COALESCE) return;

  // 选项变化（区分大小写 / 整词）时重新开始查找，而不是沿用上一次的匹配位置。
  const optionsChanged = findState.matchCase !== v.matchCase || findState.wholeWord !== v.wholeWord;
  findState = { text: v.text, matchCase: v.matchCase, wholeWord: v.wholeWord };
  if (!wc) return;
  wc.findInPage(v.text, {
    forward: forward !== false,
    matchCase: v.matchCase,
    wholeWord: v.wholeWord,
    ...(optionsChanged ? { findNext: false } : {}),
  });
});

ipcMain.on('stop-find', (event) => {
  if (!isMainSender(event)) return;
  findState.text = '';
  // 结束查找时同时清掉去重指纹，允许用户重新打开查找栏查找同一个词。
  findGuard.resetFind(findRateState);
  const wc = getCurrentTabWebContents();
  if (wc) wc.stopFindInPage('clearSelection');
});

ipcMain.on('show-more-options-menu', (event, position) => {
  if (!isMainSender(event)) return;
  const menu = new Menu();
  const wc = getCurrentTabWebContents();
  const currentZoomLevel = wc ? wc.getZoomLevel() : 0;
  const currentZoomPercent = Math.round(Math.pow(1.2, currentZoomLevel) * 100);
  menu.append(new MenuItem({ label: `重置缩放 (当前: ${currentZoomPercent}%)`, click: resetZoom }));
  menu.append(new MenuItem({ label: '放大', click: zoomIn }));
  menu.append(new MenuItem({ label: '缩小', click: zoomOut }));
  menu.append(new MenuItem({ type: 'separator' }));
  menu.append(new MenuItem({
    label: '重新打开已关闭的标签页 (Ctrl+Shift+T)',
    click: () => {
      const lastClosedTab = getLastClosedTab();
      if (lastClosedTab) createNewTab(lastClosedTab.url);
    }
  }));
  menu.append(new MenuItem({ type: 'separator' }));
  menu.append(new MenuItem({
    label: '休眠所有后台标签页 (Ctrl+Shift+S)',
    enabled: memorySaverEnabled,
    click: () => {
      const n = discardAllBackgroundTabs();
      sendToRenderer('show-toast', n > 0 ? `已休眠 ${n} 个后台标签页` : '没有需要休眠的后台标签页');
    }
  }));
  menu.popup({ window: mainWindow, x: position.x, y: position.y });
});

function createContextMenu(menuType, selectedText = '') {
  const menu = new Menu();
  if (menuType === 'selection') {
    if (selectedText) {
      menu.append(new MenuItem({ label: '复制', click: () => { if (mainWindow?.webContents) mainWindow.webContents.copy(); } }));
      menu.append(new MenuItem({ type: 'separator' }));
    }
    menu.append(new MenuItem({ label: '主页', click: goHome }));
    menu.append(new MenuItem({ label: '设置', click: () => createNewTab('cosy://setting') }));
    menu.append(new MenuItem({ type: 'separator' }));
    if (isDev) menu.append(new MenuItem({ label: '开发者工具', click: toggleDevTools }));
  } else {
    if (isDev) menu.append(new MenuItem({ label: '开发者工具', click: toggleDevTools }));
    menu.append(new MenuItem({ label: '返回主页', click: goHome }));
    menu.append(new MenuItem({ label: '设置', click: () => createNewTab('cosy://setting') }));
  }
  return menu;
}

const userDataPath = path.join(os.homedir(), 'AppData', 'Roaming', 'OpenCosy', 'browser', 'userdata');
const extensionsPath = path.join(userDataPath, 'extensions');
const configPath = path.join(extensionsPath, 'config.json');

async function ensureDirectories() {
  try {
    await fs.mkdir(userDataPath, { recursive: true });
    await fs.mkdir(extensionsPath, { recursive: true });
  } catch (e) { console.error('创建目录失败:', e); }
}

async function readExtensionsConfig() {
  try {
    await ensureDirectories();
    if (fsSync.existsSync(configPath)) return JSON.parse(await fs.readFile(configPath, 'utf8'));
  } catch (e) { console.error('读取插件配置失败:', e); }
  return { extensions: [] };
}

async function saveExtensionsConfig(config) {
  try {
    await ensureDirectories();
    await fs.writeFile(configPath, JSON.stringify(config, null, 2));
    return true;
  } catch (e) { console.error('保存插件配置失败:', e); return false; }
}

async function validateExtensionFolder(folderPath) {
  try {
    const manifestPath = path.join(folderPath, 'manifest.json');
    if (!fsSync.existsSync(manifestPath)) return { valid: false, error: '文件夹中未找到manifest.json文件' };
    const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
    if (!manifest.name) return { valid: false, error: 'manifest.json中缺少name字段' };
    if (!manifest.version) return { valid: false, error: 'manifest.json中缺少version字段' };
    if (!manifest.manifest_version) return { valid: false, error: 'manifest_version字段缺失' };
    if (manifest.permissions && Array.isArray(manifest.permissions)) {
      const dangerousPermissions = ['<all_urls>', 'tabs', 'history', 'bookmarks', 'cookies', 'webRequest', 'webRequestBlocking', 'proxy', 'management', 'debugger', 'nativeMessaging'];
      if (manifest.permissions.some(p => dangerousPermissions.includes(p))) {
        const requested = manifest.permissions
          .filter(p => dangerousPermissions.includes(p))
          .slice(0, 8).join(', ');
        recordSecurityEvent('extension-blocked', 'critical',
          `扩展 ${manifest.name || '(未命名)'} 请求危险权限被拒绝: ${requested}`,
          `extension:${manifestPath || ''}`);
        return { valid: false, error: '插件请求了危险权限，已被拒绝加载' };
      }
    }
    return { valid: true, manifest };
  } catch (e) {
    recordSecurityEvent('extension-blocked', 'warn',
      `扩展 manifest.json 读取或解析失败: ${e && e.message ? e.message : e}`,
      `extension:${folderPath || ''}`);
    return { valid: false, error: '读取manifest.json失败: ' + e.message };
  }
}

function isSafeEntryName(name) {
  return name && name !== '.' && name !== '..' && !name.includes('/') && !name.includes('\\') && !path.isAbsolute(name);
}

// copyExtensionToStorage 递归复制扩展文件到 extensionsPath。
// 安全关键：用 lstat 而不是 stat，并且跳过 symlink。否则一个恶意扩展包里塞个
// 符号链接指到 C:\Users\xxx\.ssh\id_rsa，我们会把私钥复制进扩展目录，
// renderer 里的扩展脚本就能直接读到。
async function copyExtensionToStorage(sourcePath, extensionId) {
  try {
    const targetPath = path.join(extensionsPath, extensionId);
    await fs.mkdir(targetPath, { recursive: true });
    const files = await fs.readdir(sourcePath);
    for (const file of files) {
      if (!isSafeEntryName(file)) continue;
      const sourceFile = path.join(sourcePath, file);
      const targetFile = path.join(targetPath, file);
      const stat = await fs.lstat(sourceFile);
      if (stat.IsSymbolicLink()) continue;
      if (stat.isDirectory()) await copyExtensionToStorage(sourceFile, path.join(extensionId, file));
      else await fs.copyFile(sourceFile, targetFile);
    }
    return true;
  } catch (e) { console.error('复制插件失败:', e); return false; }
}

async function loadEnabledExtensions() {
  try {
    const config = await readExtensionsConfig();
    for (const ext of config.extensions) {
      if (ext.enabled) await loadExtension(ext);
    }
  } catch (e) { console.error('加载插件失败:', e); }
}

async function loadExtension(extension) {
  try {
    const extensionPath = path.join(extensionsPath, extension.id);
    if (fsSync.existsSync(extensionPath)) {
      await session.defaultSession.loadExtension(extensionPath, { allowFileAccess: false });
      console.log('插件加载成功:', extension.name);
    }
  } catch (e) { console.error('加载插件失败:', extension.name, e); }
}

async function unloadExtension(extensionId) {
  try {
    const extensions = session.defaultSession.getAllExtensions();
    for (const ext of extensions) {
      if (ext.id === extensionId) { await session.defaultSession.removeExtension(extensionId); break; }
    }
  } catch (e) { console.error('卸载插件失败:', extensionId, e); }
}

ipcMain.handle('add-extension', async (event, folderPath) => {
  if (!isMainSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    const validation = await validateExtensionFolder(folderPath);
    if (!validation.valid) return { success: false, error: validation.error };
    const { manifest } = validation;
    const sanitizedName = manifest.name.replace(/[^a-zA-Z0-9]/g, '_');
    const sanitizedVersion = String(manifest.version).replace(/[^a-zA-Z0-9._-]/g, '_');
    const extensionId = `${sanitizedName}_${sanitizedVersion}`;
    const config = await readExtensionsConfig();
    if (config.extensions.find(ext => ext.id === extensionId)) return { success: false, error: '该插件已存在' };
    const copySuccess = await copyExtensionToStorage(folderPath, extensionId);
    if (!copySuccess) return { success: false, error: '复制插件文件失败' };
    let iconPath = '';
    if (manifest.icons) {
      const iconSizes = Object.keys(manifest.icons).sort((a, b) => parseInt(b) - parseInt(a));
      if (iconSizes.length > 0) {
        const iconName = manifest.icons[iconSizes[0]];
        if (isSafeEntryName(iconName)) iconPath = path.join(extensionsPath, extensionId, iconName);
      }
    }
    const newExtension = {
      id: extensionId, name: manifest.name, version: manifest.version,
      description: manifest.description || '', icon: iconPath,
      path: path.join(extensionsPath, extensionId), enabled: true, addedDate: new Date().toISOString()
    };
    config.extensions.push(newExtension);
    const saveSuccess = await saveExtensionsConfig(config);
    if (!saveSuccess) return { success: false, error: '保存配置失败' };
    return { success: true, extension: newExtension };
  } catch (e) { return { success: false, error: e.message }; }
});

ipcMain.handle('get-extensions', async (event) => {
  if (!isMainSender(event)) return { success: false, error: 'Unauthorized', extensions: [] };
  try {
    const config = await readExtensionsConfig();
    return { success: true, extensions: config.extensions };
  } catch (e) { return { success: false, error: e.message, extensions: [] }; }
});

ipcMain.handle('toggle-extension', async (event, { id, enabled }) => {
  if (!isMainSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    const config = await readExtensionsConfig();
    const extension = config.extensions.find(ext => ext.id === id);
    if (!extension) return { success: false, error: '插件未找到' };
    extension.enabled = enabled;
    const saveSuccess = await saveExtensionsConfig(config);
    if (!saveSuccess) return { success: false, error: '保存配置失败' };
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
});

ipcMain.handle('remove-extension', async (event, id) => {
  if (!isMainSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    const config = await readExtensionsConfig();
    const extensionIndex = config.extensions.findIndex(ext => ext.id === id);
    if (extensionIndex === -1) return { success: false, error: '插件未找到' };
    await unloadExtension(id);
    const extensionPath = path.join(extensionsPath, id);
    if (fsSync.existsSync(extensionPath)) await fs.rm(extensionPath, { recursive: true, force: true });
    config.extensions.splice(extensionIndex, 1);
    const saveSuccess = await saveExtensionsConfig(config);
    if (!saveSuccess) return { success: false, error: '保存配置失败' };
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
});

ipcMain.handle('browse-folder', async (event) => {
  if (!isMainSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    const result = await dialog.showOpenDialog(mainWindow, { title: '选择插件文件夹', properties: ['openDirectory'] });
    if (!result.canceled && result.filePaths.length > 0) return { success: true, path: result.filePaths[0] };
    return { success: false, error: '用户取消选择' };
  } catch (e) { return { success: false, error: e.message }; }
});

ipcMain.on('show-context-menu', (event, data) => {
  if (!isMainSender(event)) return;
  const menu = createContextMenu(data.menuType, data.selectedText);
  menu.popup();
});

const ALLOWED_SETTING_KEYS = {
  darkMode: v => typeof v === 'boolean',
  httpsOnly: v => typeof v === 'boolean',
  blockTrackers: v => typeof v === 'boolean',
  blockThirdPartyCookies: v => typeof v === 'boolean',
  hardenCookies: v => typeof v === 'boolean',
  blockLocalNetworkAccess: v => typeof v === 'boolean',
  reduceClientHints: v => typeof v === 'boolean',
  blockAdSignals: v => typeof v === 'boolean',
  blockHyperlinkPing: v => typeof v === 'boolean',
  stripAcceptCh: v => typeof v === 'boolean',
  webrtcMode: v => typeof v === 'string' &&
    Object.prototype.hasOwnProperty.call(fpGuard.WEBRTC_POLICIES, v),
  dohMode: v => typeof v === 'string' &&
    Object.prototype.hasOwnProperty.call(dohGuard.SECURE_DNS_MODES, v),
  dohProvider: v => typeof v === 'string' &&
    (v === 'custom' || dohGuard.getProviderById(v) !== null),
  dohCustomUrl: v => typeof v === 'string' && v.length <= 2048 &&
    (v.trim() === '' || dohGuard.validateDohServer(v).ok),
  crashRecovery: v => typeof v === 'boolean',
  stripTrackingParams: v => typeof v === 'boolean',
  themeColor: v => isValidColor(v),
  defaultTab: v => ['bing', 'custom', 'newtab'].includes(v),
  customUrl: v => typeof v === 'string' && isSafeUrl(v),
  tabLayout: v => ['horizontal', 'vertical'].includes(v),
  searchEngine: v => ['bing', 'google', 'baidu'].includes(v),
  memorySaver: v => typeof v === 'boolean',
  clearOnExit: v => typeof v === 'boolean',
  confirmCloseMultiple: v => typeof v === 'boolean',
  backgroundType: v => ['default', 'custom'].includes(v),
  customBackgroundUrl: v => typeof v === 'string' && isSafeUrl(v),
  spellcheckEnabled: v => typeof v === 'boolean',
  spellcheckLanguages: v => Array.isArray(v)
    && v.length <= MAX_SPELLCHECK_LANGUAGES
    && v.every(l => typeof l === 'string' && ALLOWED_SPELLCHECK_LANGUAGES.includes(l)),
};

function sanitizeSettings(raw) {
  if (!raw || typeof raw !== 'object') return {};
  const clean = {};
  for (const [key, validate] of Object.entries(ALLOWED_SETTING_KEYS)) {
    if (key in raw && validate(raw[key])) clean[key] = raw[key];
  }
  return clean;
}

ipcMain.on('save-settings', (event, settings) => {
  if (!isMainSender(event)) return;
  // r33：settings 是“整包序列化落盘”通道，先用 inputGuard 做形状与体量裁决：
  // 非普通对象 / 嵌套过深 / 键数过多 / 体量逼近磁盘上限（16MiB）一律拒绝，防止
  // 被攻陷渲染层用深层巨型对象打爆内存与 cosySettings.json。
  const objRes = inputGuard.asPlainObject(settings);
  if (!objRes.ok) {
    recordSecurityEvent('ipc-input-rejected', 'warn',
      'save-settings 收到非普通对象入参，已拒绝', originOfContents(event.sender));
    event.reply('settings-saved', { success: false, error: 'invalid settings payload' });
    return;
  }
  const measure = inputGuard.measureObject(settings);
  if (!measure.ok) {
    recordSecurityEvent('ipc-input-rejected', 'warn',
      `save-settings 整包体量异常已拒绝（${measure.reason}，keys=${measure.keys}，bytes=${measure.bytes}）`,
      originOfContents(event.sender));
    event.reply('settings-saved', { success: false, error: 'settings payload too large' });
    return;
  }
  try {
    const clean = sanitizeSettings(settings);
    const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
    fsSync.writeFileSync(settingsPath, JSON.stringify(clean, null, 2), 'utf-8');
    // 立即把 darkMode / httpsOnly / memorySaver 应用到运行时
    applyDarkMode(clean.darkMode);
    httpsOnlyEnabled = clean.httpsOnly !== false;
    blockTrackers = clean.blockTrackers !== false;
    blockThirdPartyCookies = clean.blockThirdPartyCookies !== false;
    hardenCookies = clean.hardenCookies !== false;
    blockLocalNetworkAccess = clean.blockLocalNetworkAccess !== false;
    reduceClientHints = clean.reduceClientHints !== false;
    blockAdSignals = clean.blockAdSignals !== false;
    blockHyperlinkPing = clean.blockHyperlinkPing !== false;
    stripAcceptCh = clean.stripAcceptCh !== false;
    if ('webrtcMode' in clean) webrtcMode = fpGuard.normalizeWebRtcMode(clean.webrtcMode);
    applyWebRtcPolicy();
    if ('dohMode' in clean) dohMode = dohGuard.normalizeMode(clean.dohMode);
    if ('dohProvider' in clean) dohProvider = clean.dohProvider;
    if ('dohCustomUrl' in clean) dohCustomUrl = clean.dohCustomUrl;
    applySecureDns();
    crashRecoveryEnabled = clean.crashRecovery !== false;
    stripTrackingParams = clean.stripTrackingParams !== false;
    if ('memorySaver' in clean) memorySaverEnabled = !!clean.memorySaver;
    if ('clearOnExit' in clean) clearOnExit = !!clean.clearOnExit;
    if ('confirmCloseMultiple' in clean) confirmCloseMultiple = !!clean.confirmCloseMultiple;
    if ('spellcheckEnabled' in clean) spellcheckEnabled = !!clean.spellcheckEnabled;
    if ('spellcheckLanguages' in clean) spellcheckLanguages = sanitizeSpellcheckLanguages(clean.spellcheckLanguages);
    applySpellcheckSettings();
    event.reply('settings-saved', { success: true });
  } catch (e) {
    console.error('保存设置失败:', e);
    event.reply('settings-saved', { success: false, error: e.message });
  }
});

ipcMain.on('update-theme-color', (event, color) => {
  if (!isMainSender(event)) return;
  if (!isValidColor(color)) return;
  sendToRenderer('update-theme-color', color);
  tabs.forEach(tab => {
    if (tab.view?.webContents) tab.view.webContents.send('update-theme-color', color);
  });
});

ipcMain.on('get-settings', (event) => {
  if (!isMainSender(event)) return;
  try {
    const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
    if (fsSync.existsSync(settingsPath)) event.reply('settings-loaded', JSON.parse(fsSync.readFileSync(settingsPath, 'utf-8')));
    else event.reply('settings-loaded', {});
  } catch (e) {
    console.error('读取设置失败:', e);
    event.reply('settings-loaded', {});
  }
});

// get-spellcheck-info 返回拼写检查当前状态与平台实际可用的语言列表，
// 设置页据此隐藏当前系统没有词典的语言，避免用户勾了一个永远不生效的选项。
ipcMain.handle('get-spellcheck-info', (event) => {
  if (!isMainSender(event)) return { success: false };
  let available = [];
  try {
    available = session.defaultSession.availableSpellCheckerLanguages || [];
  } catch (e) {
    console.error('读取可用拼写语言失败:', e);
  }
  const availableSet = new Set(available);
  return {
    success: true,
    enabled: spellcheckEnabled,
    languages: spellcheckLanguages,
    selectable: ALLOWED_SPELLCHECK_LANGUAGES.filter(l => availableSet.has(l))
  };
});

ipcMain.on('export-config', async (event, content) => {
  if (!isMainSender(event)) return;
  try {
    const result = await dialog.showSaveDialog(mainWindow, {
      title: '导出配置', defaultPath: 'cosy_config.inf',
      filters: [{ name: '配置文件', extensions: ['inf'] }, { name: '所有文件', extensions: ['*'] }]
    });
    if (!result.canceled && result.filePath) {
      fsSync.writeFileSync(result.filePath, content, 'utf-8');
      event.reply('export-config-success', '配置文件导出成功！');
    } else {
      event.reply('export-config-canceled', '导出操作已取消');
    }
  } catch (e) {
    console.error('导出配置失败:', e);
    event.reply('export-config-error', '导出配置失败: ' + e.message);
  }
});

ipcMain.handle('get-bookmarks', (event) => {
  if (!isMainSender(event)) return { success: false, bookmarks: [] };
  return { success: true, bookmarks };
});

// 导出书签：format=json 导 OpenCosy 自有 JSON，html 导 Netscape 格式
// （可直接被 Chrome / Edge / Firefox 导入）。
ipcMain.handle('export-bookmarks', async (event, format) => {
  if (!isMainSender(event)) return { success: false, error: '无权操作' };
  try {
    const useHTML = format === 'html';
    const stamp = new Date().toISOString().slice(0, 10);
    const result = await dialog.showSaveDialog(mainWindow, {
      title: '导出书签',
      defaultPath: useHTML ? `opencosy-bookmarks-${stamp}.html` : `opencosy-bookmarks-${stamp}.json`,
      filters: useHTML
        ? [{ name: 'Netscape 书签 HTML', extensions: ['html'] }, { name: '所有文件', extensions: ['*'] }]
        : [{ name: 'JSON 书签文件', extensions: ['json'] }, { name: '所有文件', extensions: ['*'] }],
    });
    if (result.canceled || !result.filePath) return { success: false, canceled: true };
    const content = useHTML ? bookmarkIO.buildExportHTML(bookmarks) : bookmarkIO.buildExportJSON(bookmarks);
    fsSync.writeFileSync(result.filePath, content, 'utf-8');
    return { success: true, count: bookmarks.length, format: useHTML ? 'html' : 'json' };
  } catch (e) {
    console.error('导出书签失败:', e);
    return { success: false, error: e.message };
  }
});

// 导入书签：弹原生选择框，按内容自动识别 JSON / Netscape HTML，
// 严格校验后合并去重落盘。整个解析发生在主进程，渲染层只拿到统计结果。
ipcMain.handle('import-bookmarks', async (event) => {
  if (!isMainSender(event)) return { success: false, error: '无权操作' };
  try {
    const result = await dialog.showOpenDialog(mainWindow, {
      title: '导入书签',
      properties: ['openFile'],
      filters: [
        { name: '书签文件', extensions: ['html', 'htm', 'json'] },
        { name: '所有文件', extensions: ['*'] },
      ],
    });
    if (result.canceled || !result.filePaths || result.filePaths.length === 0) {
      return { success: false, canceled: true };
    }
    const filePath = result.filePaths[0];
    const stat = fsSync.statSync(filePath);
    if (stat.size > bookmarkIO.MAX_IMPORT_FILE_BYTES) {
      return { success: false, error: '书签文件过大（上限 8MiB）' };
    }
    const buffer = fsSync.readFileSync(filePath);
    const { format: detectedFormat, bookmarks: incoming } = bookmarkIO.parseBookmarkFile(buffer);
    const before = bookmarks.length;
    const { merged, added } = bookmarkIO.mergeBookmarks(bookmarks, incoming);
    if (added === 0) {
      return { success: true, added: 0, total: before, format: detectedFormat, duplicated: incoming.length };
    }
    bookmarks = merged;
    saveBookmarks();
    sendToRenderer('bookmarks-updated', bookmarks);
    return { success: true, added, total: bookmarks.length, format: detectedFormat };
  } catch (e) {
    console.error('导入书签失败:', e);
    return { success: false, error: e.message };
  }
});

ipcMain.handle('get-history', (event) => {
  if (!isMainSender(event)) return { success: false, history: [] };
  return { success: true, history: history.slice(0, 100) };
});

ipcMain.handle('clear-history', (event) => {
  if (!isMainSender(event)) return { success: false };
  history = [];
  saveHistory();
  return { success: true };
});

ipcMain.handle('get-https-only', (event) => {
  if (!isMainSender(event)) return { success: false };
  return { success: true, enabled: httpsOnlyEnabled };
});

ipcMain.handle('get-network-status', (event) => {
  if (!isMainSender(event)) return { success: false };
  return { success: true, online: net.isOnline() };
});

ipcMain.handle('get-trackers', (event) => {
  if (!isMainSender(event)) return { success: false };
  return { success: true, enabled: blockTrackers, count: blockedTrackerCount, top: topBlockedHosts() };
});

ipcMain.on('reset-trackers', (event) => {
  if (!isMainSender(event)) return;
  blockedTrackerCount = 0;
  blockedTrackerByHost.clear();
  sendToRenderer('trackers-blocked', { count: 0, host: '', top: [] });
});

// 崩溃横幅上的“强制刷新”：按 tabId 找到对应标签重载（无响应 / 连续崩溃后由用户手动触发）。
ipcMain.on('reload-tab-by-id', (event, tabId) => {
  if (!isMainSender(event)) return;
  const id = Number(tabId);
  const tab = tabs.find(t => t.view && t.view.webContents.id === id);
  const wc = tab?.view?.webContents;
  if (wc && !wc.isDestroyed()) {
    crashReloadCounts.delete(id);
    wc.reload();
  }
});

// 崩溃横幅上的“重新打开”：连续崩溃不再自动重载时，让用户在全新标签里重试该 URL。
ipcMain.on('reopen-tab-url', (event, url) => {
  if (!isMainSender(event)) return;
  if (typeof url === 'string' && isSafeUrl(url)) createNewTab(url);
});

// purgeBrowsingDataOnExit 在用户开启“退出时清除浏览数据”时执行一次性彻底清理：
// 网络缓存、Cookie / localStorage / IndexedDB 等站点存储、历史与下载记录，
// 以及用于恢复标签的 session.json，保证下次启动是干净状态，不留本次痕迹。
async function purgeBrowsingDataOnExit() {
  const sessionObj = session.defaultSession;
  await Promise.all([
    sessionObj.clearCache(),
    sessionObj.clearStorageData({
      storages: [
        'cookies', 'filesystem', 'indexdb', 'localstorage',
        'shadercache', 'websql', 'serviceworkers', 'cachestorage',
      ],
    }),
  ]);
  history = [];
  saveHistory();
  downloads = [];
  currentDownloadInfo = null;
  clearSession();
}

ipcMain.handle('clear-browsing-data', async (event, options) => {
  if (!isMainSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    if (!options || typeof options !== 'object') return { success: false, error: 'Invalid options' };
    const promises = [];
    if (options.cache) promises.push(session.defaultSession.clearCache());
    if (options.cookies) promises.push(session.defaultSession.clearStorageData({ storages: ['cookies', 'localstorage', 'indexdb'] }));
    if (options.history) {
      history = [];
      saveHistory();
    }
    if (options.downloads) {
      downloads = [];
      currentDownloadInfo = null;
    }
    await Promise.all(promises);
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// 仅允许针对 http/https 站点按 origin 清理本地数据，拒绝把内置页/file 等传进来。
const SITE_DATA_STORAGES = [
  'cookies', 'filesystem', 'indexdb', 'localstorage',
  'shadercache', 'websql', 'serviceworkers', 'cachestorage',
];

ipcMain.handle('clear-site-data', async (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false, error: 'Unauthorized' };
  let origin = payload.origin;
  if (!origin || typeof origin !== 'string') return { success: false, error: 'Invalid origin' };
  let parsed;
  try {
    parsed = new URL(origin);
  } catch {
    return { success: false, error: 'Invalid origin' };
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { success: false, error: 'Only http/https sites are supported' };
  }
  origin = parsed.origin;
  try {
    await session.defaultSession.clearStorageData({ origin, storages: SITE_DATA_STORAGES });
    await session.defaultSession.clearCache();
    return { success: true, origin };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// ===== 站点数据 / Cookie 管理（cosy://sitedata）=====
// Cookie 属于较敏感的隐私数据，所有通道仅对内置页（isMainSender）开放，
// 返回字段做白名单裁剪，不把 expirationDate 之外的内部结构泄露给页面。
const SITE_DATA_MAX_ROWS = 500;
const SITE_DATA_MAX_NAMES = 10;
const SITE_DATA_SEARCH_MAX = 200;

function normalizeCookieDomain(domain) {
  if (typeof domain !== 'string' || !domain) return '';
  return domain.startsWith('.') ? domain.slice(1) : domain;
}

function cookieOriginSchemes(cookie) {
  // secure cookie 只能在 https 下删除；非 secure 的在两种 scheme 都试一次。
  return cookie.secure ? ['https'] : ['https', 'http'];
}

async function removeCookieEntry(cookie) {
  const host = normalizeCookieDomain(cookie.domain);
  const urlPath = cookie.path && cookie.path.startsWith('/') ? cookie.path : '/';
  let lastError = null;
  for (const scheme of cookieOriginSchemes(cookie)) {
    try {
      await session.defaultSession.cookies.remove(`${scheme}://${host}${urlPath}`, cookie.name);
      return;
    } catch (e) {
      lastError = e;
    }
  }
  throw lastError || new Error('删除 Cookie 失败');
}

function pickCookieFields(c) {
  return {
    name: c.name,
    value: c.value,
    domain: c.domain,
    path: c.path,
    secure: !!c.secure,
    httpOnly: !!c.httpOnly,
    session: !!c.session,
    hostOnly: !!c.hostOnly,
    sameSite: c.sameSite || 'unspecified',
    expirationDate: typeof c.expirationDate === 'number' ? c.expirationDate : null,
  };
}

// 汇总每个域名下的 Cookie 数量与名称样本，供管理页列表使用。
ipcMain.handle('list-site-data', async (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false, error: 'Unauthorized' };
  const query = typeof payload.query === 'string'
    ? payload.query.trim().toLowerCase().slice(0, SITE_DATA_SEARCH_MAX) : '';
  try {
    const cookies = await session.defaultSession.cookies.get({});
    const groups = new Map();
    for (const c of cookies) {
      const domain = normalizeCookieDomain(c.domain);
      if (!domain) continue;
      if (query && !domain.toLowerCase().includes(query)) continue;
      let row = groups.get(domain);
      if (!row) {
        row = { domain, count: 0, secureCount: 0, httpOnlyCount: 0, sessionCount: 0, names: [] };
        groups.set(domain, row);
      }
      row.count++;
      if (c.secure) row.secureCount++;
      if (c.httpOnly) row.httpOnlyCount++;
      if (c.session) row.sessionCount++;
      if (row.names.length < SITE_DATA_MAX_NAMES && !row.names.includes(c.name)) {
        row.names.push(c.name);
      }
    }
    const rows = Array.from(groups.values())
      .sort((a, b) => b.count - a.count || a.domain.localeCompare(b.domain))
      .slice(0, SITE_DATA_MAX_ROWS);
    return { success: true, rows, totalCookies: cookies.length, truncated: groups.size > rows.length };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// 查看某个域名（含其子域）下的全部 Cookie。
ipcMain.handle('get-site-cookies', async (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false, error: 'Unauthorized' };
  const domain = normalizeCookieDomain(payload.domain);
  if (!domain) return { success: false, error: 'Invalid domain' };
  try {
    const all = await session.defaultSession.cookies.get({});
    const matched = all.filter(c => {
      const d = normalizeCookieDomain(c.domain);
      return d === domain || d.endsWith('.' + domain);
    }).map(pickCookieFields);
    return { success: true, domain, cookies: matched };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// 删除单条 Cookie（按 name + domain + path 精确定位）。
ipcMain.handle('delete-site-cookie', async (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false, error: 'Unauthorized' };
  const name = payload.name;
  const domain = normalizeCookieDomain(payload.domain);
  if (typeof name !== 'string' || !name || !domain) {
    return { success: false, error: 'Invalid cookie' };
  }
  try {
    const all = await session.defaultSession.cookies.get({});
    const target = all.find(c => c.name === name &&
      normalizeCookieDomain(c.domain) === domain &&
      (!payload.path || c.path === payload.path));
    if (!target) return { success: false, error: 'Cookie 不存在或已过期' };
    await removeCookieEntry(target);
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// 删除某个域名及其全部子域下的 Cookie。
ipcMain.handle('delete-site-cookies', async (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false, error: 'Unauthorized' };
  const domain = normalizeCookieDomain(payload.domain);
  if (!domain) return { success: false, error: 'Invalid domain' };
  try {
    const all = await session.defaultSession.cookies.get({});
    const targets = all.filter(c => {
      const d = normalizeCookieDomain(c.domain);
      return d === domain || d.endsWith('.' + domain);
    });
    let removed = 0;
    for (const c of targets) {
      try { await removeCookieEntry(c); removed++; } catch { /* 过期/httponly 删除失败的跳过 */ }
    }
    return { success: true, removed };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// 清空某域名的本地存储（Cookie/LocalStorage/IndexedDB/ServiceWorker 等）。
ipcMain.handle('clear-site-storage', async (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false, error: 'Unauthorized' };
  const domain = normalizeCookieDomain(payload.domain);
  if (!domain || !/^[a-z0-9.-]+$/i.test(domain)) {
    return { success: false, error: 'Invalid domain' };
  }
  try {
    for (const scheme of ['https', 'http']) {
      await session.defaultSession.clearStorageData({
        origin: `${scheme}://${domain}`,
        storages: SITE_DATA_STORAGES,
      });
    }
    return { success: true, domain };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// 打印当前标签页（Ctrl+P）。只作用于活动标签的网页内容。
ipcMain.handle('print-current-tab', (event) => {
  if (!isMainSender(event)) return { success: false, error: 'Unauthorized' };
  const tab = tabs[currentTabIndex];
  const wc = tab && tab.view && tab.view.webContents;
  if (!wc || wc.isDestroyed()) return { success: false, error: 'No active page' };
  try {
    wc.print({ silent: false, printBackground: true }, () => {});
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// 地址栏搜索建议：固定走 Bing OpenSearch 建议接口（osjson），不接受 renderer
// 传入的任意 URL，避免被当成 SSRF 跳板。返回严格限定为字符串数组并限量。
const SUGGEST_ENDPOINT = 'https://api.bing.com/osjson.aspx?query=';
const SUGGEST_MAX_CHARS = 200;
const SUGGEST_MAX_ITEMS = 8;
const SUGGEST_TIMEOUT_MS = 2500;

function fetchSearchSuggestions(query) {
  return new Promise((resolve) => {
    const url = SUGGEST_ENDPOINT + encodeURIComponent(query);
    let settled = false;
    let request;
    try {
      request = net.request({ url, redirect: 'error' });
    } catch {
      return resolve([]);
    }
    const finish = (list) => {
      if (!settled) { settled = true; resolve(list); }
    };
    const timer = setTimeout(() => {
      try { request.abort(); } catch {}
      finish([]);
    }, SUGGEST_TIMEOUT_MS);

    const chunks = [];
    request.on('response', (response) => {
      const ct = (response.headers['content-type'] || []).join('').toLowerCase();
      // osjson 正常返回 json；跟随到别的类型直接丢弃。
      if (response.statusCode !== 200 || !ct.includes('json')) {
        clearTimeout(timer);
        try { response.destroy(); } catch {}
        return finish([]);
      }
      response.on('data', (c) => chunks.push(c));
      response.on('end', () => {
        clearTimeout(timer);
        try {
          const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (!Array.isArray(data) || !Array.isArray(data[1])) return finish([]);
          const out = [];
          for (const item of data[1]) {
            if (typeof item !== 'string') continue;
            const s = item.trim();
            if (!s || s.length > 100) continue;
            out.push(s);
            if (out.length >= SUGGEST_MAX_ITEMS) break;
          }
          finish(out);
        } catch {
          finish([]);
        }
      });
      response.on('error', () => { clearTimeout(timer); finish([]); });
    });
    request.on('error', () => { clearTimeout(timer); finish([]); });
    try { request.end(); } catch { clearTimeout(timer); finish([]); }
  });
}

ipcMain.handle('get-search-suggestions', async (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false, suggestions: [] };
  const q = typeof payload.q === 'string' ? payload.q.trim() : '';
  if (!q || q.length > SUGGEST_MAX_CHARS) return { success: false, suggestions: [] };
  // 已经是完整 URL / 内置协议时不给搜索建议，交给历史/书签补全。
  if (/^[a-z][a-z0-9+.-]*:/i.test(q) || q.startsWith('//')) return { success: true, suggestions: [] };
  const suggestions = await fetchSearchSuggestions(q);
  return { success: true, suggestions };
});
