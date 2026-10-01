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
      headers['Content-Security-Policy'] = ["default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https:;"];
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

// SAFE_EXTERNAL_SCHEMES 是唯一允许 shell.openExternal 的外部协议白名单。
// mailto: / tel: 是用户点邮箱/电话链接时该有的行为；
// file: / smb: / ms-*: / vbscript: / javascript: 一律走弹窗拒绝。
const SAFE_EXTERNAL_SCHEMES = new Set(['mailto:', 'tel:']);

function isSafeExternalProtocol(url) {
  if (!url || typeof url !== 'string') return false;
  const lower = String(url).toLowerCase();
  for (const scheme of SAFE_EXTERNAL_SCHEMES) {
    if (lower.startsWith(scheme)) return true;
  }
  return false;
}

// confirmAndOpenExternal 统一入口：http(s) 开新标签，外部协议白名单 + 原生确认。
// renderer 想让浏览器"点 mailto:" 必须走这个 IPC，不许直接 shell.openExternal。
async function confirmAndOpenExternal(url) {
  if (!url || typeof url !== 'string') return { ok: false, reason: 'empty url' };
  if (url.startsWith('http://') || url.startsWith('https://')) {
    if (!isSafeUrl(url)) return { ok: false, reason: 'unsafe url' };
    createNewTab(url);
    return { ok: true };
  }
  if (!isSafeExternalProtocol(url)) {
    sendToRenderer('show-toast', `已阻止打开外部协议: ${url.slice(0, 60)}`);
    return { ok: false, reason: 'blocked scheme' };
  }
  const choice = dialog.showMessageBoxSync(mainWindow, {
    type: 'question',
    buttons: ['允许打开', '取消'],
    defaultId: 1,
    cancelId: 1,
    title: '网站想要打开外部应用',
    message: `当前页面尝试打开:\n${url}\n\n是否允许？`
  });
  if (choice !== 0) return { ok: false, reason: 'user denied' };
  try {
    await shell.openExternal(url, { activate: true });
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: String(e && e.message || e) };
  }
}

// ===== 按站点记忆的敏感权限决定（permission-decisions.json）=====
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
    callback(ALLOWED_PERMISSIONS.has(permission));
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

  app.on('web-contents-created', (_event, contents) => {
    // 主窗口 UI 自己管 navigation，跳过；只给页面 tab 兜底
    if (contents === mainWindow?.webContents) return;

    contents.setWindowOpenHandler(({ url }) => {
      if (!isSafeUrl(url)) return { action: 'deny' };
      // 从 tab 里点 _blank 的，统一丢回我们的 createNewTab
      setImmediate(() => createNewTab(url));
      return { action: 'deny' };
    });

    // 本浏览器用 WebContentsView 承载页面，从不使用 <webview> 标签。
    // 若有页面尝试 attach webview，一律阻止：webview 默认能携带自己的
    // webPreferences（nodeIntegration/disablewebsecurity），是常见提权通道。
    contents.on('will-attach-webview', (attachEvent, webPreferences, params) => {
      delete webPreferences.preload;
      webPreferences.nodeIntegration = false;
      webPreferences.contextIsolation = true;
      webPreferences.sandbox = true;
      webPreferences.webSecurity = true;
      webPreferences.allowRunningInsecureContent = false;
      if (!isSafeUrl(params.src)) {
        attachEvent.preventDefault();
      }
    });

    contents.on('will-navigate', (navEvent, url) => {
      if (!isSafeUrl(url)) {
        navEvent.preventDefault();
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

    contents.on('will-redirect', (redirectEvent, url) => {
      if (!isSafeUrl(url)) {
        redirectEvent.preventDefault();
      }
    });

    // ===== 渲染进程崩溃 / 卡死恢复 =====
    // 现代浏览器在某个标签的渲染进程崩溃后会给横幅而不是整窗静默死掉。
    // 崩溃 / OOM 自动重载“一次”（第二次不再自动，避免崩溃循环把 CPU 打满），
    // 被系统杀死(killed)不自动重载；无响应时给横幅让用户选“等待 / 强制刷新”。
    contents.on('render-process-gone', (_goneEvent, details) => {
      const tab = tabs.find(t => t.view && t.view.webContents === contents);
      const payload = {
        tabId: contents.id,
        reason: details.reason || 'unknown',
        exitCode: typeof details.exitCode === 'number' ? details.exitCode : null,
        url: tab?.url || '',
        title: tab?.title || '',
        autoReloaded: false,
      };
      const count = (crashReloadCounts.get(contents.id) || 0) + 1;
      crashReloadCounts.set(contents.id, count);
      if (crashRecoveryEnabled &&
          (details.reason === 'crashed' || details.reason === 'oom') &&
          count === 1 && !contents.isDestroyed()) {
        payload.autoReloaded = true;
        setTimeout(() => {
          if (!contents.isDestroyed()) contents.reload();
        }, 400);
      }
      sendToRenderer('renderer-gone', payload);
    });

    // 页面恢复正常后，把该标签的崩溃计数清零，给下次真正的崩溃留出自动重载机会。
    contents.on('did-finish-load', () => crashReloadCounts.delete(contents.id));

    contents.on('unresponsive', () => {
      sendToRenderer('renderer-unresponsive', { tabId: contents.id });
    });
    contents.on('responsive', () => {
      sendToRenderer('renderer-responsive', { tabId: contents.id });
    });

    // 页面调 window.close() 之前触发的 beforeunload，弹原生确认
    contents.on('will-prevent-unload', (event) => {
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

  mainWindow = new BrowserWindow({
    width: DEFAULT_WINDOW_WIDTH, height: DEFAULT_WINDOW_HEIGHT,
    minWidth: MIN_WINDOW_WIDTH, minHeight: MIN_WINDOW_HEIGHT,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      enableRemoteModule: false,
      preload: path.join(__dirname, 'preload.js'),
      worldSafeExecuteJavaScript: true,
      spellcheck: true,
    },
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
    tab.view = new WebContentsView({
      webPreferences: {
        nodeIntegration: false,
        contextIsolation: true,
        sandbox: true,
        webSecurity: true,
        allowRunningInsecureContent: false,
        enableRemoteModule: false,
        preload: path.join(__dirname, 'preload.js'),
        worldSafeExecuteJavaScript: true,
        spellcheck: true,
      }
    });

    mainWindow.contentView.addChildView(tab.view);
    updateBrowserViewBounds();

    tab.view.webContents.setWindowOpenHandler(({ url, disposition }) => {
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
      if (!isSafeUrl(navigationUrl)) { event.preventDefault(); return; }
      tab.url = navigationUrl;
      addToHistory(navigationUrl, tab.title);
      sendToRenderer('tab-updated', { id: tab.id, url: navigationUrl });
    });

    tab.view.webContents.on('did-navigate', () => { pushNavState(tab); applySavedZoom(tab); });
    tab.view.webContents.on('did-navigate-in-page', () => { pushNavState(tab); applySavedZoom(tab); });
    tab.view.webContents.on('dom-ready', () => applySavedZoom(tab));

    tab.view.webContents.on('did-redirect-navigation', (event, url) => {
      if (!isSafeUrl(url)) return;
      tab.url = url;
      sendToRenderer('tab-updated', { id: tab.id, url });
    });

    tab.view.webContents.on('page-title-updated', (event, title) => {
      tab.title = title;
      addToHistory(tab.url, title);
      sendToRenderer('tab-updated', { id: tab.id, title });
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
      if (favicons.length > 0) {
        let faviconUrl = favicons[0];
        if (faviconUrl.startsWith('/')) {
          try {
            const url = new URL(tab.url);
            faviconUrl = url.origin + faviconUrl;
          } catch { return; }
        }
        if (faviconUrl.startsWith('data:') || faviconUrl.startsWith('http')) {
          tab.favicon = faviconUrl;
          sendToRenderer('tab-updated', { id: tab.id, favicon: tab.favicon });
        }
      }
    });

    tab.view.webContents.on('context-menu', (event, params) => {
      const menu = new Menu();
      // 拼写建议放在菜单最顶部，与 Chromium 浏览器一致。
      // misspelledWord 来自 Chromium 本地词典匹配，建议不离开本机。
      if (spellcheckEnabled && params.isEditable && params.misspelledWord) {
        const suggestions = (params.dictionarySuggestions || []).slice(0, 6);
        if (suggestions.length) {
          for (const word of suggestions) {
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
              tab.view.webContents.session.addWordToSpellCheckerDictionary(params.misspelledWord);
            } catch (e) {
              console.error('添加自定义词典失败:', e);
            }
          }
        }));
        menu.append(new MenuItem({ type: 'separator' }));
      }
      if (params.linkURL && isSafeUrl(params.linkURL)) {
        menu.append(new MenuItem({ label: '在新标签页中打开', click: () => createNewTab(params.linkURL) }));
        menu.append(new MenuItem({ label: '复制链接地址', click: () => clipboard.writeText(params.linkURL) }));
        menu.append(new MenuItem({ type: 'separator' }));
      }
      if (params.selectionText) {
        menu.append(new MenuItem({ label: '复制', role: 'copy' }));
        menu.append(new MenuItem({
          label: '搜索所选内容',
          click: () => createNewTab('https://www.bing.com/search?q=' + encodeURIComponent(params.selectionText))
        }));
      }
      if (params.selectionText && params.isEditable) menu.append(new MenuItem({ label: '剪切', role: 'cut' }));
      if (params.isEditable) menu.append(new MenuItem({ label: '粘贴', role: 'paste' }));
      if (params.isEditable) menu.append(new MenuItem({ label: '全选', role: 'selectAll' }));
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

// sanitizeDownloadFilename 防 Content-Disposition 路径穿越：
// 服务端可能在 filename 里塞 "../../evil.exe"，直接拼到下载目录会写出目录。
// 这里只取 basename，并剥掉 Windows/Unix 保留字符。
function sanitizeDownloadFilename(name) {
  if (!name || typeof name !== 'string') return 'download';
  let base = path.basename(name.replace(/\\/g, '/'));
  base = base.replace(/[\\/:*?"<>|\x00-\x1f]/g, '_');
  base = base.replace(/^\.+$/, '');
  return base || 'download';
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

// DANGEROUS_DOWNLOAD_EXTS 是 Windows / 跨平台下可直接执行或能启动程序的扩展名。
// 现代浏览器对这类"可执行"下载会给出强提示；这里在自动保存前先弹原生确认，
// 防止 drive-by download（页面静默触发）把木马 .exe 直接放进下载目录。
const DANGEROUS_DOWNLOAD_EXTS = new Set([
  '.exe', '.msi', '.msix', '.appx', '.appxbundle', '.msixbundle',
  '.scr', '.bat', '.cmd', '.com', '.ps1', '.psm1', '.vbs', '.vbe',
  '.jse', '.wsf', '.wsh', '.jar', '.hta', '.cpl',
  '.dll', '.sys', '.drv', '.ocx', '.lnk', '.reg', '.inf',
  '.iso', '.vhd', '.vhdx',
]);

// 危险扩展名提示只按最终落盘文件名判断（URL 路径可能与 Content-Disposition 不一致）。
// .tar.gz / .zip 这类压缩包不在此列：它们不会被系统直接执行。
function isDangerousDownloadFilename(filename) {
  const lower = String(filename || '').toLowerCase();
  return DANGEROUS_DOWNLOAD_EXTS.has(path.extname(lower));
}

function confirmDangerousDownload(filename, originUrl) {
  let host = '';
  try { host = new URL(originUrl).host; } catch { host = originUrl || '未知来源'; }
  const choice = dialog.showMessageBoxSync(mainWindow, {
    type: 'warning',
    buttons: ['取消下载', '仍然保存'],
    defaultId: 0,
    cancelId: 0,
    title: '安全提示：可执行文件',
    message: `该文件可能会损害您的计算机，是否仍要保存？`,
    detail: `文件：${filename}\n来源：${host}\n\n此类型文件可以在您的电脑上运行程序或更改设置，请确认来源可信后再保存。`,
    noLink: true,
  });
  return choice === 1;
}

function setupDownloadManager() {
  session.defaultSession.on('will-download', (event, item, webContents) => {
    const url = item.getURL();
    if (!isSafeUrl(url)) { event.preventDefault(); return; }

    // 关键修复：不信任服务端给的 filename，先净化
    const safeFilename = sanitizeDownloadFilename(item.getFilename());

    // 可执行/脚本类文件在自动保存前必须让用户显式确认，阻断静默 drive-by 下载。
    if (isDangerousDownloadFilename(safeFilename)) {
      const allow = confirmDangerousDownload(safeFilename, url);
      if (!allow) {
        try { item.cancel(); } catch {}
        sendToRenderer('show-toast', `已取消下载可执行文件：${safeFilename}`);
        return;
      }
    }

    const totalBytes = item.getTotalBytes();
    let downloadInfo = downloads.find(d => d.url === url && d.item === null && d.isItemValid === false);
    if (downloadInfo) {
      downloadInfo.item = item;
      downloadInfo.filename = safeFilename;
      downloadInfo.totalBytes = totalBytes;
      downloadInfo.isItemValid = true;
      downloadInfo.status = 'downloading';
    } else {
      // 全新下载：不再 preventDefault + 新开下载页等用户确认，
      // 直接按现代浏览器行为自动保存到下载目录，由底部 shelf 展示进度。
      downloadInfo = {
        id: Date.now().toString(), url, filename: safeFilename, totalBytes,
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
      const defaultSavePath = resolveUniqueDownloadPath(app.getPath('downloads'), safeFilename);
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

if (process.argv.length > 1) {
  const arg = process.argv[1];
  if (arg && (arg.endsWith('.html') || arg.endsWith('.htm'))) fileToOpen = `file://${arg}`;
  if (arg && (arg.startsWith('http://') || arg.startsWith('https://') || arg.startsWith('cosy://'))) fileToOpen = arg;
}

app.on('open-file', (event, filePath) => {
  event.preventDefault();
  if (filePath && (filePath.endsWith('.html') || filePath.endsWith('.htm'))) {
    const fileUrl = `file://${filePath}`;
    if (mainWindow && mainWindow.isReady()) {
      const newTab = createNewTab(fileUrl);
      switchToTab(tabs.indexOf(newTab));
    } else {
      fileToOpen = fileUrl;
    }
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
  crashRecoveryEnabled = stored.crashRecovery !== false;
  stripTrackingParams = stored.stripTrackingParams !== false;
  if ('memorySaver' in stored) memorySaverEnabled = !!stored.memorySaver;
  if ('clearOnExit' in stored) clearOnExit = !!stored.clearOnExit;
  if ('confirmCloseMultiple' in stored) confirmCloseMultiple = !!stored.confirmCloseMultiple;
  startMemorySaver();

  if (process.platform === 'win32') app.setAsDefaultProtocolClient('cosy');

  protocol.registerFileProtocol('cosy', (request, callback) => {
    try {
      const urlObj = new URL(request.url);
      const hostname = urlObj.hostname;
      const pageMap = {
        'setting': path.join(__dirname, 'src', 'settings.html'),
        'newtab': path.join(__dirname, 'src', 'newtab.html'),
        'extensions': path.join(__dirname, 'src', 'extensions.html'),
        'version': path.join(__dirname, 'src', 'version.html'),
        'sitedata': path.join(__dirname, 'src', 'sitedata.html'),
        'permissions': path.join(__dirname, 'src', 'permissions.html'),
        'download': path.join(__dirname, 'src', 'download', 'index.html'),
        'downloadlist': path.join(__dirname, 'src', 'downloadlist.html')
      };
      const filePath = pageMap[hostname] || path.join(__dirname, 'src', 'newtab.html');
      callback({ path: filePath });
    } catch (e) {
      console.error('注册cosy协议失败:', e);
      callback({ path: path.join(__dirname, 'src', 'newtab.html') });
    }
  });

  protocol.registerFileProtocol('file', (request, callback) => {
    try {
      const requestedPath = decodeURIComponent(request.url.substr(7));
      const resolvedPath = path.resolve(requestedPath);
      if (getSafeDirs().some(dir => isPathInDir(resolvedPath, dir))) {
        callback({ path: resolvedPath });
      } else {
        callback({ error: -3 });
      }
    } catch (e) {
      console.error('注册file协议失败:', e);
      callback({ error: -3 });
    }
  });

  setupPermissionHandlers();
  setupSecurityHeaders();
  setupDownloadManager();
  setupGlobalWebContentsHooks();
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
  if (!isSafeUrl(url)) return;
  if (!mainWindow || mainWindow.isDestroyed()) createWindow();
  setTimeout(() => {
    if (url.startsWith('cosy://') || url.startsWith('http://') || url.startsWith('https://')) {
      createNewTab(url);
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
  if (isInSafeDirs(resolved) && fsSync.existsSync(resolved)) shell.openPath(resolved);
});

ipcMain.on('open-folder', (event, filePath) => {
  if (!isMainSender(event)) return;
  const resolved = path.resolve(filePath);
  if (isInSafeDirs(resolved) && fsSync.existsSync(resolved)) shell.showItemInFolder(resolved);
});

// open-external-url renderer 统一入口：点 mailto:/tel: 走这里，
// 主进程做 scheme 白名单 + 原生确认，再调 shell.openExternal。
ipcMain.handle('open-external-url', async (event, url) => {
  if (!isMainSender(event)) return { ok: false, reason: 'unauthorized' };
  return await confirmAndOpenExternal(String(url || ''));
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
  if (typeof text !== 'string') return;
  // 选项变化（区分大小写 / 整词）时重新开始查找，而不是沿用上一次的匹配位置。
  const optionsChanged = findState.matchCase !== !!matchCase || findState.wholeWord !== !!wholeWord;
  findState = { text, matchCase: !!matchCase, wholeWord: !!wholeWord };
  const wc = getCurrentTabWebContents();
  if (!wc || !text) return;
  wc.findInPage(text, {
    forward: forward !== false,
    matchCase: !!matchCase,
    wholeWord: !!wholeWord,
    ...(optionsChanged ? { findNext: false } : {}),
  });
});

ipcMain.on('stop-find', (event) => {
  if (!isMainSender(event)) return;
  findState.text = '';
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
        return { valid: false, error: '插件请求了危险权限，已被拒绝加载' };
      }
    }
    return { valid: true, manifest };
  } catch (e) { return { valid: false, error: '读取manifest.json失败: ' + e.message }; }
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
  try {
    const clean = sanitizeSettings(settings);
    const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
    fsSync.writeFileSync(settingsPath, JSON.stringify(clean, null, 2), 'utf-8');
    // 立即把 darkMode / httpsOnly / memorySaver 应用到运行时
    applyDarkMode(clean.darkMode);
    httpsOnlyEnabled = clean.httpsOnly !== false;
    blockTrackers = clean.blockTrackers !== false;
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
