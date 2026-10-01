const { app, BrowserWindow, WebContentsView, ipcMain, session, protocol, Menu, MenuItem, dialog, shell, globalShortcut, clipboard, net, nativeTheme } = require('electron');
const path = require('path');
const fs = require('fs').promises;
const fsSync = require('fs');
const os = require('os');
const bookmarkIO = require('./bookmarkio');
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
const MAX_RECENTLY_CLOSED = 10;
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
// crashRecovery：渲染进程崩溃 / OOM 时自动重载一次并弹横幅；可在设置关闭。
let crashRecoveryEnabled = true;
// 每个 webContents 的崩溃次数，用于阻止“崩溃→重载→又崩溃”的无限循环。
const crashReloadCounts = new Map();
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
  if (!isSafeUrl(url) || url.startsWith('cosy://')) return;
  const existingIndex = history.findIndex(h => h.url === url);
  if (existingIndex !== -1) history.splice(existingIndex, 1);
  history.unshift({ url, title, timestamp: Date.now() });
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
    if (fsSync.existsSync(historyPath)) {
      history = JSON.parse(fsSync.readFileSync(historyPath, 'utf-8'));
    }
  } catch (e) {
    console.error('读取历史记录失败:', e);
  }
}
function saveBookmarks() {
  const bookmarksPath = path.join(app.getPath('userData'), 'bookmarks.json');
  try {
    fsSync.writeFileSync(bookmarksPath, JSON.stringify(bookmarks, null, 2), 'utf-8');
  } catch (e) {
    console.error('保存书签失败:', e);
  }
}
function loadBookmarks() {
  const bookmarksPath = path.join(app.getPath('userData'), 'bookmarks.json');
  try {
    if (fsSync.existsSync(bookmarksPath)) {
      bookmarks = JSON.parse(fsSync.readFileSync(bookmarksPath, 'utf-8'));
    }
  } catch (e) {
    console.error('读取书签失败:', e);
  }
}
function saveSession() {
  try {
    const sessionPath = path.join(app.getPath('userData'), 'session.json');
    const sessionTabs = tabs
      .filter(tab => !tab.url.startsWith('cosy://') && isSafeUrl(tab.url))
      .map(tab => ({ url: tab.url, title: tab.title }));
    fsSync.writeFileSync(sessionPath, JSON.stringify(sessionTabs, null, 2), 'utf-8');
  } catch (e) {
    console.error('保存会话失败:', e);
  }
}
function loadSession() {
  try {
    const sessionPath = path.join(app.getPath('userData'), 'session.json');
    if (fsSync.existsSync(sessionPath)) {
      const sessionTabs = JSON.parse(fsSync.readFileSync(sessionPath, 'utf-8'));
      if (Array.isArray(sessionTabs) && sessionTabs.length > 0) {
        return sessionTabs.filter(tab => isSafeUrl(tab.url));
      }
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
  if (!tab || !tab.url || tab.url.startsWith('cosy://')) return;
  recentlyClosedTabs.push({ url: tab.url, title: tab.title, closedAt: Date.now() });
  if (recentlyClosedTabs.length > MAX_RECENTLY_CLOSED) recentlyClosedTabs.shift();
}
function getLastClosedTab() {
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
function setupSecurityHeaders() {
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    const headers = details.responseHeaders || {};
    const setIfMissing = (name, value) => {
      if (!headers[name] && !headers[name.toLowerCase()]) headers[name] = value;
    };
    setIfMissing('X-Content-Type-Options', ['nosniff']);
    setIfMissing('X-Frame-Options', ['SAMEORIGIN']);
    setIfMissing('Referrer-Policy', ['strict-origin-when-cross-origin']);
    // 关闭 FLoC / 广告兴趣组 / 隐私令牌等现代浏览器默认放开但我们不需要的特性
    setIfMissing('Permissions-Policy', [
      'interest-cohort=()', 'run-ad-auction=()',
      'private-state-token-issuance=()', 'private-state-token-redemption=()',
      'join-ad-interest-group=()'
    ]);
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
    callback({ responseHeaders: headers });
  });
  session.defaultSession.webRequest.onBeforeSendHeaders((details, callback) => {
    const headers = details.requestHeaders;
    headers['DNT'] = '1';
    headers['Sec-GPC'] = '1';
    headers['Upgrade-Insecure-Requests'] = '1';
    trimReferrerHeader(details, headers);
    callback({ requestHeaders: headers });
  });
  session.defaultSession.webRequest.onBeforeRequest((details, callback) => {
    const isHttpUrl = details.url.startsWith('http://') || details.url.startsWith('https://');
    // 第三方追踪 / 广告子资源：直接取消（不动顶层导航）。
    if (isHttpUrl && isTrackerRequest(details)) {
      recordBlockedTracker(details.url);
      return callback({ cancel: true });
    }
    // 顶层导航：剥离 utm_* 等追踪参数（只重定向一次，不动 fragment / 子资源）。
    let workingUrl = details.url;
    if (isHttpUrl && details.resourceType === 'mainFrame') {
      const stripped = stripTrackingFromUrl(details.url);
      if (stripped && stripped !== details.url) {
        return callback({ redirectURL: stripped });
      }
      // 同形异义 / IDN 反钓鱼提示（只提示，不阻断导航）。
      try {
        const spoof = analyzeHostForSpoof(new URL(details.url).hostname);
        if (spoof) sendToRenderer('spoof-warning', spoof);
      } catch { /* 无效主机名忽略 */ }
    }
    // HTTPS-only 模式：用户可在设置里关掉；私网/回环主机永远保留 http://
    if (httpsOnlyEnabled && workingUrl.startsWith('http://') && !isPrivateNetworkHost(workingUrl)) {
      callback({ redirectURL: 'https://' + workingUrl.slice(7) });
    } else {
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
        await shell.openExternal(url, { activate: true });
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
    message: `${siteLabel} 想要打开:\n${url}\n\n是否允许？`,
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
    await shell.openExternal(url, { activate: true });
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
  'extension-blocked',       // 扩展请求危险权限 / 校验未过
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
      });
      if (cspReports.length >= MAX_CSP_REPORDS) break;
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
  const report = {
    id: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
    time: Date.now(),
    documentUri: sanitizeCspField(frameUrl),
    directive,
    blockedUri: sanitizeCspField(payload && payload.blockedUri),
    sourceFile: sanitizeCspField(payload && payload.sourceFile),
    lineNumber: Math.max(0, Number(payload && payload.lineNumber) || 0),
    columnNumber: Math.max(0, Number(payload && payload.columnNumber) || 0),
    disposition: payload && payload.disposition === 'report' ? 'report' : 'enforce',
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
__TAIL_OK__