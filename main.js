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
  fingerprint: [
    'fingerprint.com', 'api.fpjs.sh', 'fpcdn.io', 'fpjs.sh',
    'iovation.com', 'mpsnare.iesnare.com', 'first-party.iovation.com',
    'threatmetrix.com', 'h-sdk.online-metrix.net', 'online-metrix.net',
    'deviceidentify.com', 'deepintent.com', 'drawbrid.ge',
    'mediavoice.com', 'bidtheatre.com', 'streampixel.io',
    'bouncex.net', 'cdn.bouncex.net', 'addroplet.com',
  ],
};
const TRACKER_HOSTS = new Set(Object.values(TRACKER_DOMAIN_GROUPS).flat());
function hostMatchesTracker(hostname) {
  let h = String(hostname || '').toLowerCase().replace(/\.$/, '');
  if (!h) return false;
  if (TRACKER_HOSTS.has(h)) return true;
  for (const t of TRACKER_HOSTS) {
    if (h.endsWith('.' + t)) return true;
  }
  return false;
}
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
let stripTrackingParams = true;
const TRACKING_QUERY_KEYS = new Set([
  'fbclid', 'gclid', 'gbraid', 'wbraid', 'dclid', 'gclsrc', 'msclkid',
  'yclid', 'mc_cid', 'mc_eid', 'igshid', 'ttclid', 'twclid', 'li_fat_id',
  'vero_id', 'wickedid', 'hsCtaTracking', '_hsenc', '_hsmi', 'mkt_tok',
  'oly_anon_id', 'oly_enc_id', 'vero_conv', 'soc_src', 'soc_trk',
  'spm', 'scm', 'sourceFrom', 'fromSource',
]);
const TRACKING_QUERY_PREFIXES = ['utm_', 'pk_', 'piwik_', 'matomo_', 'ga_', 'oasid_'];
function isTrackingQueryKey(rawKey) {
  const key = String(rawKey || '').toLowerCase();
  if (!key) return false;
  if (TRACKING_QUERY_KEYS.has(key)) return true;
  return TRACKING_QUERY_PREFIXES.some(p => key.startsWith(p));
}
function stripTrackingFromUrl(rawUrl) {
  if (!stripTrackingParams) return null;
  if (!(rawUrl.startsWith('http://') || rawUrl.startsWith('https://'))) return null;
  let u;
  try { u = new URL(rawUrl); } catch { return null; }
  if (!u.search) return null;
  const params = u.searchParams;
  let removed = false;
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
const SKEW_LATIN_HOSTS = new Set([
  'google', 'youtube', 'facebook', 'amazon', 'apple', 'microsoft', 'github',
  'twitter', 'x', 'instagram', 'netflix', 'paypal', 'alibaba', 'taobao',
  'baidu', 'bing', 'office', 'live', 'steam', 'epicgames',
]);
function hostnameHasSuspiciousChars(hostname) {
  if (/[^\x00-\x7F]/.test(hostname)) return 'nonascii';
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
  if (/[^\x00-\x7F]/.test(registrable)) {
    const asciiOnly = registrable.replace(/[^\x21-\x7e]/g, '');
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
function originOf(u) {
  try { return new URL(u).origin; } catch { return null; }
}
function trimReferrerHeader(details, headers) {
  const referrer = headers['Referer'] || headers['referer'];
  if (!referrer) return;
  const fromOrigin = originOf(referrer);
  const toOrigin = originOf(details.url);
  if (!fromOrigin || !toOrigin) return;
  if (fromOrigin === toOrigin) return;
  const fromHttps = referrer.startsWith('https://');
  const toHttp = details.url.startsWith('http://');
  if (fromHttps && toHttp) {
    delete headers['Referer'];
    delete headers['referer'];
    return;
  }
  const trimmed = fromOrigin === 'null' ? '' : fromOrigin + '/';
  headers['Referer'] = trimmed;
  delete headers['referer'];
}
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
const DEFAULT_SPELLCHECK_LANGUAGES = ['en-US', 'zh-CN'];
const ALLOWED_SPELLCHECK_LANGUAGES = [
  'en-US', 'en-GB', 'en-AU', 'zh-CN', 'zh-TW', 'ja',
  'fr-FR', 'de-DE', 'es-ES', 'ru-RU', 'ko', 'pt-BR', 'it-IT'
];
const MAX_SPELLCHECK_LANGUAGES = 5;
let spellcheckEnabled = true;
let spellcheckLanguages = DEFAULT_SPELLCHECK_LANGUAGES.slice();
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
function zoomIn() { adjustCurrentZoom({ delta: 'in' }); }
function zoomOut() { adjustCurrentZoom({ delta: 'out' }); }
function resetZoom() { adjustCurrentZoom({ factor: 1 }); }
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
  try { fsSync.writeFileSync(historyPath, JSON.stringify(history, null, 2), 'utf-8'); }
  catch (e) { console.error('保存历史记录失败:', e); }
}
function loadHistory() {
  const historyPath = path.join(app.getPath('userData'), 'history.json');
  try {
    if (fsSync.existsSync(historyPath)) history = JSON.parse(fsSync.readFileSync(historyPath, 'utf-8'));
  } catch (e) { console.error('读取历史记录失败:', e); }
}
function saveBookmarks() {
  const bookmarksPath = path.join(app.getPath('userData'), 'bookmarks.json');
  try { fsSync.writeFileSync(bookmarksPath, JSON.stringify(bookmarks, null, 2), 'utf-8'); }
  catch (e) { console.error('保存书签失败:', e); }
}
function loadBookmarks() {
  const bookmarksPath = path.join(app.getPath('userData'), 'bookmarks.json');
  try {
    if (fsSync.existsSync(bookmarksPath)) bookmarks = JSON.parse(fsSync.readFileSync(bookmarksPath, 'utf-8'));
  } catch (e) { console.error('读取书签失败:', e); }
}
function saveSession() {
  try {
    const sessionPath = path.join(app.getPath('userData'), 'session.json');
    const sessionTabs = tabs
      .filter(tab => !tab.url.startsWith('cosy://') && isSafeUrl(tab.url))
      .map(tab => ({ url: tab.url, title: tab.title }));
    fsSync.writeFileSync(sessionPath, JSON.stringify(sessionTabs, null, 2), 'utf-8');
  } catch (e) { console.error('保存会话失败:', e); }
}
function loadSession() {
  try {
    const sessionPath = path.join(app.getPath('userData'), 'session.json');
    if (fsSync.existsSync(sessionPath)) {
      const sessionTabs = JSON.parse(fsSync.readFileSync(sessionPath, 'utf-8'));
      if (Array.isArray(sessionTabs) && sessionTabs.length > 0) return sessionTabs.filter(tab => isSafeUrl(tab.url));
    }
  } catch (e) { console.error('读取会话失败:', e); }
  return null;
}
function clearSession() {
  try {
    const sessionPath = path.join(app.getPath('userData'), 'session.json');
    if (fsSync.existsSync(sessionPath)) fsSync.unlinkSync(sessionPath);
  } catch (e) { console.error('清除会话失败:', e); }
}
function addToRecentlyClosed(tab) {
  if (!tab || !tab.url || tab.url.startsWith('cosy://')) return;
  recentlyClosedTabs.push({ url: tab.url, title: tab.title, closedAt: Date.now() });
  if (recentlyClosedTabs.length > MAX_RECENTLY_CLOSED) recentlyClosedTabs.shift();
}
function getLastClosedTab() { return recentlyClosedTabs.pop(); }
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
function readStoredSettings() {
  try {
    const p = path.join(app.getPath('userData'), 'cosySettings.json');
    if (fsSync.existsSync(p)) return JSON.parse(fsSync.readFileSync(p, 'utf-8'));
  } catch (e) { console.error('读取设置失败:', e); }
  return {};
}
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
    setIfMissing('Permissions-Policy', [
      'interest-cohort=()', 'run-ad-auction=()',
      'private-state-token-issuance=()', 'private-state-token-redemption=()',
      'join-ad-interest-group=()'
    ]);
    const isLocal = details.url.startsWith('cosy://') || details.url.startsWith('file://');
    if (isLocal && !headers['Content-Security-Policy'] && !headers['content-security-policy']) {
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
    if (isLocal) {
      headers['Cross-Origin-Opener-Policy'] = ['same-origin'];
      headers['Cross-Origin-Embedder-Policy'] = ['require-corp'];
      headers['Cross-Origin-Resource-Policy'] = ['same-origin'];
    }
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
    if (isHttpUrl && isTrackerRequest(details)) {
      recordBlockedTracker(details.url);
      return callback({ cancel: true });
    }
    let workingUrl = details.url;
    if (isHttpUrl && details.resourceType === 'mainFrame') {
      const stripped = stripTrackingFromUrl(details.url);
      if (stripped && stripped !== details.url) return callback({ redirectURL: stripped });
      try {
        const spoof = analyzeHostForSpoof(new URL(details.url).hostname);
        if (spoof) sendToRenderer('spoof-warning', spoof);
      } catch {}
    }
    if (httpsOnlyEnabled && workingUrl.startsWith('http://') && !isPrivateNetworkHost(workingUrl)) {
      callback({ redirectURL: 'https://' + workingUrl.slice(7) });
    } else {
      callback({});
    }
  });
}
const ALLOWED_PERMISSIONS = new Set([
  'media', 'geolocation', 'notifications', 'midi', 'midiSysex',
  'pointerLock', 'fullscreen', 'clipboard-sanitized-write',
  'pop-up'
]);
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
const protocolDecisionStorePath = path.join(app.getPath('userData'), 'protocol-decisions.json');
const MAX_PROTOCOL_DECISIONS = 500;
const CONFIRMABLE_EXTERNAL_SCHEMES = new Set(['mailto:', 'tel:']);
const SUBFRAME_WEB_SCHEMES = new Set(['http:', 'https:', 'blob:', 'data:', 'about:']);
const protocolDecisions = new Map();
let protocolDecisionsLoaded = false;
let protocolSaveTimer = null;
function protocolDecisionKey(origin, scheme) { return origin + ' ' + scheme; }
function normalizeExternalScheme(url) {
  try {
    const scheme = new URL(url).protocol.toLowerCase();
    if (!/^[a-z][a-z0-9+.-]{0,31}:$/.test(scheme)) return '';
    return scheme;
  } catch { return ''; }
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
      !protocolDecisions.has(protocolDecisionKey(origin, scheme))) return false;
  protocolDecisions.set(protocolDecisionKey(origin, scheme), { decision, updatedAt: Date.now() });
  persistProtocolDecisions();
  return true;
}
function classifyFrameNavigation(url, isMainFrame) {
  const scheme = normalizeExternalScheme(url);
  if (!scheme) return 'block';
  if (isMainFrame) {
    if (scheme === 'http:' || scheme === 'https:' || scheme === 'file:' || scheme === 'cosy:') return 'in-pane';
  } else if (SUBFRAME_WEB_SCHEMES.has(scheme)) {
    return 'in-pane';
  }
  if (CONFIRMABLE_EXTERNAL_SCHEMES.has(scheme)) return 'confirm';
  return 'block';
}
function originOfContents(contents) {
  try { return new URL(contents.getURL()).origin; } catch { return ''; }
}
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
      recordSecurityEvent('protocol-denied', 'info', `按记忆决定阻止 ${scheme} 协议唤起`, origin);
      sendToRenderer('show-toast', `已按记忆阻止 ${scheme} 协议（可在设置中撤销）`);
      return { ok: false, reason: 'remembered deny' };
    }
    if (known === 'allow') {
      try { await shell.openExternal(url, { activate: true }); return { ok: true, reason: 'remembered allow' }; }
      catch (e) { return { ok: false, reason: String(e && e.message || e) }; }
    }
  }
  const siteLabel = isRememberableOrigin(origin) ? origin : '当前页面';
  const choice = await dialog.showMessageBox(mainWindow, {
    type: 'question',
    buttons: ['允许打开', '拒绝'],
    defaultId: 1, cancelId: 1,
    title: '网站想要打开外部应用',
    message: `${siteLabel} 想要打开:\n${url}\n\n是否允许？`,
    checkboxLabel: '记住对此网站的选择（可在设置中撤销）',
    checkboxChecked: false
  });
  const checked = !!choice.checkboxChecked;
  const decision = choice.response === 0 ? 'allow' : 'deny';
  if (remember && checked && isRememberableOrigin(origin)) rememberProtocolDecision(origin, scheme, decision);
  if (decision !== 'allow') {
    recordSecurityEvent('protocol-denied', 'info', `用户拒绝了 ${scheme} 协议唤起`, origin);
    return { ok: false, reason: 'user denied' };
  }
  try { await shell.openExternal(url, { activate: true }); return { ok: true }; }
  catch (e) { return { ok: false, reason: String(e && e.message || e) }; }
}
function handleFrameNavigationAttempt(contents, url, isMainFrame) {
  const kind = classifyFrameNavigation(url, isMainFrame);
  if (kind === 'in-pane') return false;
  if (kind === 'confirm') {
    const origin = originOfContents(contents);
    launchExternalWithPrompt(url, origin, true);
    return true;
  }
  const scheme = normalizeExternalScheme(url) || '未知协议';
  recordSecurityEvent('protocol-blocked', isMainFrame ? 'warn' : 'info',
    `${isMainFrame ? '主框架' : '子框架'}外部协议导航被阻止: ${scheme} ${url}`,
    originOfContents(contents));
  if (isMainFrame) sendToRenderer('show-toast', `已阻止不安全的外部协议导航: ${scheme}`);
  else console.log(`[protocol-guard] 已阻止子框架外部协议导航: ${scheme}`);
  return true;
}
const securityEventStorePath = path.join(app.getPath('userData'), 'security-events.json');
const MAX_SECURITY_EVENTS = 1000;
const MAX_SECURITY_DETAIL_CHARS = 300;
const SECURITY_EVENT_TYPES = new Set([
  'protocol-blocked', 'protocol-denied', 'download-blocked', 'download-rejected',
  'permission-blocked', 'device-permission-blocked', 'extension-blocked',
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
function sanitizeSecurityDetail(s) {
  let str = String(s == null ? '' : s);
  str = str.replace(/[\x00-\x1f\x7f]/g, ' ').replace(/\s+/g, ' ').trim();
  if (str.length > MAX_SECURITY_DETAIL_CHARS) str = str.slice(0, MAX_SECURITY_DETAIL_CHARS) + '…';
  return str;
}
function recordSecurityEvent(type, severity, detail = '', origin = '') {
  if (!SECURITY_EVENT_TYPES.has(type)) return;
  if (severity !== 'info' && severity !== 'warn' && severity !== 'critical') return;
  loadSecurityEvents();
  const event = {
    id: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
    time: Date.now(), type, severity,
    origin: sanitizeSecurityDetail(origin),
    detail: sanitizeSecurityDetail(detail),
  };
  securityEvents.push(event);
  if (securityEvents.length > MAX_SECURITY_EVENTS) securityEvents.splice(0, securityEvents.length - MAX_SECURITY_EVENTS);
  persistSecurityEvents();
}
function listSecurityEvents(typeFilter = '', limit = 200) {
  loadSecurityEvents();
  let items = securityEvents;
  if (typeFilter && SECURITY_EVENT_TYPES.has(typeFilter)) items = securityEvents.filter(e => e.type === typeFilter);
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
const cspReportStorePath = path.join(app.getPath('userData'), 'csp-reports.json');
const MAX_CSP_REPORTS = 500;
const CSP_RATE_WINDOW_MS = 10_000;
const CSP_RATE_MAX_PER_WINDOW = 20;
const CSP_FIELD_MAX = 300;
const cspReports = [];
let cspReportsLoaded = false;
let cspReportSaveTimer = null;
const cspRateBuckets = new Map();
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
function recordCspViolationFromRenderer(senderFrame, payload) {
  if (!isInternalFrameSender(senderFrame)) return { accepted: false, reason: 'non-internal frame' };
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
  if (cspReports.length > MAX_CSP_REPORTS) cspReports.splice(0, cspReports.length - MAX_CSP_REPORTS);
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
const nodeCrypto = require('crypto');
const downloadHashStorePath = path.join(app.getPath('userData'), 'download-hashes.json');
const MAX_DOWNLOAD_HASH_RECORDS = 500;
const MAX_HASHABLE_DOWNLOAD_BYTES = 512 << 30;
const HASH_READ_CHUNK = 1024 * 1024;
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
function hashFileSha256(filePath) {
  return new Promise((resolve, reject) => {
    let stat;
    try { stat = fsSync.lstatSync(filePath); } catch (e) { reject(e); return; }
    if (!stat.isFile()) { reject(new Error('目标不是普通文件（拒绝摘要符号链接或特殊文件）')); return; }
    if (stat.size > MAX_HASHABLE_DOWNLOAD_BYTES) { reject(new Error('文件体积超过摘要安全上限')); return; }
    const hash = nodeCrypto.createHash('sha256');
    const input = fsSync.createReadStream(filePath, { highWaterMark: HASH_READ_CHUNK });
    let size = 0;
    input.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_HASHABLE_DOWNLOAD_BYTES) { input.destroy(new Error('文件体积超过摘要安全上限')); return; }
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
function queueDownloadHashing(task) {
  downloadHashChain = downloadHashChain.then(async () => {
    try {
      const { sha256, size } = await hashFileSha256(task.savePath);
      let host = '';
      try { host = new URL(task.url).host; } catch {}
      const record = {
        id: String(task.id), time: Date.now(),
        filename: String(task.filename || '').slice(0, 255) || 'download',
        size, sha256, host,
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
  let acc = 0;
  for (let i = 0; i < 64; i++) acc |= rec.sha256.charCodeAt(i) ^ want.charCodeAt(i);
  const match = acc === 0;
  return { ok: match, match, filename: rec.filename, actual: rec.sha256 };
}
async function hashLocalFileViaDialog() {
  const choice = await dialog.showOpenDialog(mainWindow, {
    title: '选择要计算 SHA-256 的文件',
    properties: ['openFile']
  });
  if (choice.canceled || !choice.filePaths || !choice.filePaths.length) return { ok: false, reason: 'canceled' };
  const filePath = choice.filePaths[0];
  const { sha256, size } = await hashFileSha256(filePath);
  return { ok: true, filename: path.basename(filePath), size, sha256 };
}
const REMEMBERED_PAGE_PERMISSIONS = new Set([
  'media', 'geolocation', 'notifications', 'midi', 'midiSysex', 'clipboard-read',
]);
const permissionStorePath = path.join(app.getPath('userData'), 'permission-decisions.json');
const MAX_PERMISSION_DECISIONS = 1000;
const permissionDecisions = new Map();
let permissionDecisionsLoaded = false;
let permissionSaveTimer = null;
function permissionStoreKey(origin, permission) { return origin + ' ' + permission; }
function isRememberableOrigin(origin) {
  if (typeof origin !== 'string' || origin.length === 0 || origin.length > 300) return false;
  try {
    const u = new URL(origin);
    return (u.protocol === 'https:' || u.protocol === 'http:') && !!u.hostname;
  } catch { return false; }
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
    out.push({ origin: k.slice(0, sp), permission: k.slice(sp + 1), decision: v.decision, updatedAt: v.updatedAt });
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
    if (k.startsWith(prefix)) { permissionDecisions.delete(k); n++; }
  }
  if (n) persistPermissionDecisions();
  return n;
}
function setupPermissionHandlers() {
  session.defaultSession.setPermissionCheckHandler((wc, permission, requestingOrigin, details) => {
    const isMedia = permission === 'media';
    if (details && details.securityOrigin === 'file://') return false;
    if (isMedia) {
      const mediaOrigin = (requestingOrigin || '').replace(/^https?:\/\//, '');
      return mediaOrigin === 'localhost' || mediaOrigin.startsWith('127.0.0.1') || mediaOrigin.startsWith('192.168.') || mediaOrigin.startsWith('10.') || mediaOrigin.startsWith('172.');
    }
    return false;
  });
  session.defaultSession.setPermissionRequestHandler((wc, permission, callback, details) => {
    if (!ALLOWED_PERMISSIONS.has(permission)) {
      recordSecurityEvent('permission-blocked', 'critical', `阻止未授权权限请求: ${permission}`, wc.getURL());
      return callback(false);
    }
    const origin = (details && (details.requestingUrl || details.securityOrigin)) || wc.getURL();
    const remembered = getRememberedPermission(origin.replace(/\/$/, ''), permission);
    if (remembered) return callback(remembered === 'allow');
    if (permission === 'pointerLock' || permission === 'fullscreen') {
      recordSecurityEvent('permission-blocked', 'info', `允许低风险权限请求: ${permission}`, wc.getURL());
      return callback(true);
    }
    dialog.showMessageBox(mainWindow, {
      type: 'question',
      buttons: ['允许', '阻止'],
      defaultId: 0,
      cancelId: 1,
      title: '权限请求',
      message: `网站请求权限: ${permission}\n来源: ${origin}\n是否允许？`,
      checkboxLabel: '记住对此网站的选择（可在设置中撤销）',
      checkboxChecked: false
    }).then(result => {
      const granted = result.response === 0;
      if (result.checkboxChecked) rememberPermission(origin.replace(/\/$/, ''), permission, granted ? 'allow' : 'deny');
      recordSecurityEvent('permission-blocked', granted ? 'info' : 'warn',
        `${granted ? '已授予' : '已阻止'}权限: ${permission}`, origin);
      callback(granted);
    });
  });
}
function setupWebRequestBlocking() {
  session.defaultSession.webRequest.onBeforeRequest({ urls: ['<all_urls>'] }, (details, callback) => {
    if (details.resourceType === 'subFrame' || details.resourceType === 'mainFrame') {
      const tab = tabs.find(t => t.view && t.view.webContents && t.view.webContents.id === details.webContentsId);
      if (tab && tab.view && tab.view.webContents) {
        const blocked = handleFrameNavigationAttempt(tab.view.webContents, details.url, details.resourceType === 'mainFrame');
        if (blocked) return callback({ cancel: true });
      }
    }
    callback({});
  });
}
function createWindow() {
  const savedSettings = readStoredSettings();
  if (typeof savedSettings.httpsOnlyEnabled === 'boolean') httpsOnlyEnabled = savedSettings.httpsOnlyEnabled;
  if (typeof savedSettings.blockTrackers === 'boolean') blockTrackers = savedSettings.blockTrackers;
  if (typeof savedSettings.crashRecoveryEnabled === 'boolean') crashRecoveryEnabled = savedSettings.crashRecoveryEnabled;
  if (typeof savedSettings.clearOnExit === 'boolean') clearOnExit = savedSettings.clearOnExit;
  if (typeof savedSettings.confirmCloseMultiple === 'boolean') confirmCloseMultiple = savedSettings.confirmCloseMultiple;
  if (typeof savedSettings.spellcheckEnabled === 'boolean') spellcheckEnabled = savedSettings.spellcheckEnabled;
  if (Array.isArray(savedSettings.spellcheckLanguages)) spellcheckLanguages = sanitizeSpellcheckLanguages(savedSettings.spellcheckLanguages);
  if (savedSettings.darkMode === true) nativeTheme.themeSource = 'dark';
  mainWindow = new BrowserWindow({
    width: DEFAULT_WINDOW_WIDTH,
    height: DEFAULT_WINDOW_HEIGHT,
    minWidth: MIN_WINDOW_WIDTH,
    minHeight: MIN_WINDOW_HEIGHT,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      webviewTag: false,
      sandbox: true,
      spellcheck: spellcheckEnabled
    }
  });
  mainWindow.loadFile('index.html');
  if (isDev) mainWindow.webContents.openDevTools({ mode: 'detach' });
  mainWindow.on('close', async (event) => {
    const tabCount = tabs.length;
    if (confirmCloseMultiple && tabCount > 1) {
      const result = await dialog.showMessageBox(mainWindow, {
        type: 'question',
        buttons: ['关闭全部', '取消'],
        defaultId: 1,
        cancelId: 1,
        title: '确认关闭',
        message: `当前有 ${tabCount} 个标签页，确定要关闭窗口吗？`
      });
      if (result.response !== 0) { event.preventDefault(); return; }
    }
    saveSession();
    if (clearOnExit) {
      try { await session.defaultSession.clearStorageData({ storages: ['cookies', 'shadercache', 'cachestorage', 'serviceworkers', 'indexdb', 'localstorage'] }); } catch {}
    }
  });
  mainWindow.on('closed', () => { mainWindow = null; });
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (isSafeUrl(url)) {
      const tab = tabs[currentTabIndex];
      if (tab && !allowPopupForTab(tab.id)) {
        sendToRenderer('show-toast', '已拦截短时间内的连续弹窗（疑似弹窗轰炸）');
        return { action: 'deny' };
      }
      createNewTab(url);
    } else {
      recordSecurityEvent('protocol-blocked', 'warn', `窗口打开处理器阻止了不安全地址: ${url}`);
    }
    return { action: 'deny' };
  });
  mainWindow.webContents.on('will-navigate', (event, url) => {
    const blocked = handleFrameNavigationAttempt(mainWindow.webContents, url, true);
    if (blocked) event.preventDefault();
  });
  mainWindow.webContents.session.on('will-download', (event, item, webContents) => {
    const downloadUrl = item.getURL();
    if (!isSafeUrl(downloadUrl)) {
      event.preventDefault();
      recordSecurityEvent('download-blocked', 'critical', `阻止不安全协议的下载: ${downloadUrl}`, webContents.getURL());
      dialog.showErrorBox('下载已阻止', '该下载地址使用了不安全或不允许的协议。');
      return;
    }
    if (downloadUrl.startsWith('file://')) {
      event.preventDefault();
      recordSecurityEvent('download-blocked', 'warn', 'file:// 下载被阻止', webContents.getURL());
      return;
    }
    const totalBytes = item.getTotalBytes();
    const knownSize = Number.isFinite(totalBytes) && totalBytes > 0;
    const dangerous = /\.(exe|msi|bat|cmd|com|scr|ps1|reg|jar|app|dmg|deb|rpm|apk)$/i.test(item.getFilename());
    dialog.showMessageBox(mainWindow, {
      type: dangerous ? 'warning' : 'question',
      buttons: ['保留', '放弃下载'],
      defaultId: dangerous ? 1 : 0,
      cancelId: 1,
      title: dangerous ? '危险下载确认' : '下载确认',
      message: `即将下载文件：${item.getFilename()}\n来源：${downloadUrl}\n${knownSize ? `大小：${formatBytes(totalBytes)}\n` : ''}${dangerous ? '\n这是可执行文件，可能危害你的电脑。确定保留吗？' : '是否保留此下载？'}`
    }).then(choice => {
      if (choice.response !== 0) {
        item.cancel();
        recordSecurityEvent('download-rejected', 'info', `用户放弃下载: ${item.getFilename()}`, downloadUrl);
        return;
      }
      beginTrackedDownload(event, item, webContents, downloadUrl);
    });
    event.preventDefault();
  });
  mainWindow.webContents.on('render-process-gone', (event, details) => {
    if (!crashRecoveryEnabled) return;
    const wc = mainWindow.webContents;
    const n = (crashReloadCounts.get(wc.id) || 0) + 1;
    if (n > 2) {
      sendToRenderer('renderer-gone', { reason: details.reason, retries: n - 1, gaveUp: true });
      return;
    }
    crashReloadCounts.set(wc.id, n);
    sendToRenderer('renderer-gone', { reason: details.reason, retries: n - 1, gaveUp: false });
    if (!wc.isDestroyed()) {
      setTimeout(() => { if (!wc.isDestroyed() && wc.isLoading() === false) wc.reload(); }, 600);
    }
  });
  setupSecurityHeaders();
  setupPermissionHandlers();
  setupWebRequestBlocking();
  registerIpcHandlers();
  registerGlobalShortcuts();
  registerBookmarkAndHistoryIpc();
  registerNewtabIpc();
  setupDownloadIpc();
  const savedSession = loadSession();
  if (savedSession && savedSession.length > 0) {
    for (const t of savedSession) createNewTab(t.url, { restore: true, title: t.title });
  } else {
    createNewTab();
  }
  app.on('web-contents-created', (event, contents) => {
    if (contents.getType() === 'webview' || contents.getType() === 'remote') contents.setWindowOpenHandler(() => ({ action: 'deny' }));
  });
}
function registerGlobalShortcuts() {
  globalShortcut.register('CmdOrCtrl+T', () => createNewTab());
  globalShortcut.register('CmdOrCtrl+W', () => closeCurrentTab());
  globalShortcut.register('CmdOrCtrl+R', () => reloadCurrentTab());
  globalShortcut.register('F5', () => reloadCurrentTab());
  globalShortcut.register('CmdOrCtrl+L', () => sendToRenderer('focus-address-bar'));
  globalShortcut.register('CmdOrCtrl+Plus', () => zoomIn());
  globalShortcut.register('CmdOrCtrl+=', () => zoomIn());
  globalShortcut.register('CmdOrCtrl+-', () => zoomOut());
  globalShortcut.register('CmdOrCtrl+0', () => resetZoom());
  globalShortcut.register('F12', () => toggleDevTools());
  globalShortcut.register('CmdOrCtrl+O', () => showOpenFileDialog());
  globalShortcut.register('Alt+Home', () => goHome());
  globalShortcut.register('CmdOrCtrl+Shift+T', () => restoreLastClosedTab());
}
function restoreLastClosedTab() {
  const last = getLastClosedTab();
  if (last) createNewTab(last.url);
}
function adjustCurrentZoom({ delta, factor }) {
  const tab = tabs[currentTabIndex];
  if (!tab || !tab.view) return;
  const wc = tab.view.webContents;
  const zoomFactor = typeof factor === 'number' ? factor : (wc.getZoomFactor() + (delta === 'in' ? 0.1 : -0.1));
  wc.setZoomFactor(Math.max(0.25, Math.min(5, zoomFactor)));
  sendToRenderer('zoom-changed', wc.getZoomFactor());
}
function reloadCurrentTab() {
  const tab = tabs[currentTabIndex];
  if (tab && tab.view) tab.view.webContents.reload();
}
function closeCurrentTab() {
  if (tabs.length > 0) {
    const closed = tabs[currentTabIndex];
    addToRecentlyClosed(closed);
    const removed = tabs.splice(currentTabIndex, 1)[0];
    if (removed && removed.view) mainWindow.contentView.removeChildView(removed.view);
    if (currentTabIndex >= tabs.length) currentTabIndex = tabs.length - 1;
    if (tabs.length === 0) {
      createNewTab();
    } else {
      switchToTab(currentTabIndex);
    }
  }
}
function createNewTab(url = 'cosy://newtab', options = {}) {
  const tab = new Tab(Date.now() + Math.random(), url);
  tabs.push(tab);
  const view = new WebContentsView({
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true,
      sandbox: true,
      spellcheck: spellcheckEnabled
    }
  });
  tab.view = view;
  setupTabView(tab, options);
  if (currentTabIndex === tabs.length - 2) currentTabIndex = tabs.length - 1;
  switchToTab(tabs.length - 1);
  return tab;
}
function setupTabView(tab, options = {}) {
  const wc = tab.view.webContents;
  wc.on('page-title-updated', (event, title) => {
    tab.title = title;
    updateTabBadge(tab);
  });
  wc.on('page-favicon-updated', (event, favicons) => {
    if (favicons && favicons.length > 0) {
      tab.favicon = favicons[0];
      updateTabBadge(tab);
    }
  });
  wc.on('did-start-loading', () => {
    tab.isLoading = true;
    updateTabBadge(tab);
  });
  wc.on('did-stop-loading', () => {
    tab.isLoading = false;
    updateTabBadge(tab);
  });
  wc.on('did-navigate', (event, url) => {
    tab.url = url;
    tab.canGoBack = wc.navigationHistory.canGoBack();
    tab.canGoForward = wc.navigationHistory.canGoForward();
    tab.bookmarked = bookmarks.some(b => b.url === url);
    updateTabBadge(tab);
    if (!options.restore) addToHistory(url, wc.getTitle());
  });
  wc.on('did-navigate-in-page', (event, url) => {
    tab.url = url;
    updateTabBadge(tab);
  });
  wc.on('media-started-playing', () => { tab.audible = true; updateTabBadge(tab); });
  wc.on('media-paused', () => { tab.audible = false; updateTabBadge(tab); });
  wc.setWindowOpenHandler(({ url }) => {
    if (isSafeUrl(url)) {
      if (!allowPopupForTab(tab.id)) {
        sendToRenderer('show-toast', '已拦截短时间内的连续弹窗（疑似弹窗轰炸）');
        return { action: 'deny' };
      }
      createNewTab(url);
    } else {
      recordSecurityEvent('protocol-blocked', 'warn', `标签窗口处理器阻止了不安全地址: ${url}`, wc.getURL());
    }
    return { action: 'deny' };
  });
  wc.on('will-navigate', (event, url) => {
    if (handleFrameNavigationAttempt(wc, url, true)) event.preventDefault();
  });
  wc.on('render-process-gone', (event, details) => {
    if (!crashRecoveryEnabled) return;
    const n = (crashReloadCounts.get(wc.id) || 0) + 1;
    if (n > 2) {
      sendToRenderer('renderer-gone-tab', { tabId: tab.id, reason: details.reason, gaveUp: true });
      return;
    }
    crashReloadCounts.set(wc.id, n);
    sendToRenderer('renderer-gone-tab', { tabId: tab.id, reason: details.reason, gaveUp: false });
  });
  loadTabContent(tab, options);
}
function updateTabBadge(tab) {
  sendToRenderer('tab-updated', {
    id: tab.id,
    title: tab.title,
    url: tab.url,
    favicon: tab.favicon,
    isLoading: tab.isLoading,
    audible: tab.audible,
    muted: tab.muted,
    bookmarked: tab.bookmarked
  });
}
function loadTabContent(tab, options = {}) {
  if (!tab.view) return;
  if (tab.url.startsWith('cosy://')) {
    const pageMap = {
      'cosy://newtab': 'src/newtab.html',
      'cosy://history': 'src/history.html',
      'cosy://bookmarks': 'src/bookmarks.html',
      'cosy://settings': 'src/settings.html',
      'cosy://permissions': 'src/permissions.html',
      'cosy://security': 'src/security.html'
    };
    const page = pageMap[tab.url.split('?')[0]];
    if (page) tab.view.webContents.loadFile(page);
    else tab.view.webContents.loadFile('src/newtab.html');
  } else {
    tab.view.webContents.loadURL(tab.url);
  }
  if (options.title) tab.title = options.title;
}
function switchToTab(index) {
  currentTabIndex = index;
  tabs.forEach((tab, i) => {
    if (tab.view) tab.view.setVisible(i === index);
  });
  updateTabLayout();
  const tab = tabs[index];
  if (tab) {
    sendToRenderer('tab-switched', {
      index,
      canGoBack: tab.canGoBack,
      canGoForward: tab.canGoForward,
      url: tab.url,
      title: tab.title
    });
  }
}
function updateTabLayout() {
  if (!mainWindow || !mainWindow.contentView) return;
  const { width, height } = mainWindow.getContentBounds();
  const isVertical = width > height;
  const tabBarHeight = isTabBarCollapsed
    ? (isVertical ? 0 : COLLAPSED_TAB_BAR_WIDTH)
    : (isVertical ? DEFAULT_TAB_BAR_HEIGHT_HORIZONTAL : DEFAULT_TAB_BAR_WIDTH_VERTICAL);
  tabs.forEach(tab => {
    if (tab.view) {
      tab.view.setBounds({ x: 0, y: isVertical ? tabBarHeight : 0, width: isVertical ? width : width - tabBarHeight, height: isVertical ? height - tabBarHeight : height });
    }
  });
}
function registerIpcHandlers() {
  ipcMain.handle('new-tab', (event, url) => {
    if (!isMainSender(event)) return;
    createNewTab(url || 'cosy://newtab');
  });
  ipcMain.handle('close-tab', (event, tabId) => {
    if (!isMainSender(event)) return;
    const idx = tabs.findIndex(t => t.id === tabId);
    if (idx !== -1) {
      const closed = tabs[idx];
      addToRecentlyClosed(closed);
      const removed = tabs.splice(idx, 1)[0];
      if (removed && removed.view) mainWindow.contentView.removeChildView(removed.view);
      if (currentTabIndex >= tabs.length) currentTabIndex = tabs.length - 1;
      if (tabs.length === 0) createNewTab();
      else switchToTab(currentTabIndex);
    }
  });
  ipcMain.handle('switch-tab', (event, index) => {
    if (!isMainSender(event)) return;
    if (index >= 0 && index < tabs.length) switchToTab(index);
  });
  ipcMain.handle('navigate', (event, url) => {
    if (!isMainSender(event)) return;
    if (isSafeUrl(url)) {
      const tab = tabs[currentTabIndex];
      if (tab) { tab.url = url; loadTabContent(tab); }
    }
  });
  ipcMain.handle('go-back', event => { if (!isMainSender(event)) return; const tab = tabs[currentTabIndex]; if (tab?.view) tab.view.webContents.navigationHistory.goBack(); });
  ipcMain.handle('go-forward', event => { if (!isMainSender(event)) return; const tab = tabs[currentTabIndex]; if (tab?.view) tab.view.webContents.navigationHistory.goForward(); });
  ipcMain.handle('reload', event => { if (!isMainSender(event)) return; reloadCurrentTab(); });
  ipcMain.handle('go-home', event => { if (!isMainSender(event)) return; goHome(); });
  ipcMain.handle('zoom-in', event => { if (!isMainSender(event)) return; zoomIn(); });
  ipcMain.handle('zoom-out', event => { if (!isMainSender(event)) return; zoomOut(); });
  ipcMain.handle('zoom-reset', event => { if (!isMainSender(event)) return; resetZoom(); });
  ipcMain.handle('toggle-devtools', event => { if (!isMainSender(event)) return; toggleDevTools(); }
  );
  ipcMain.handle('open-file', event => { if (!isMainSender(event)) return; showOpenFileDialog(); });
  ipcMain.handle('toggle-tab-mute', (event, tabId) => {
    if (!isMainSender(event)) return;
    const tab = tabs.find(t => t.id === tabId);
    if (tab?.view) {
      tab.muted = !tab.muted;
      tab.view.webContents.setAudioMuted(tab.muted);
      updateTabBadge(tab);
    }
  });
  ipcMain.handle('discard-tab', (event, tabId) => {
    if (!isMainSender(event)) return { ok: false };
    const tab = tabs.find(t => t.id === tabId);
    if (!tab?.view || tabs[currentTabIndex]?.id === tabId) return { ok: false, reason: 'active' };
    const wc = tab.view.webContents;
    try {
      const pid = wc.getOSProcessId();
      wc.close();
      tab.discarded = true;
      tab.view = null;
      mainWindow.contentView.removeChildView(tab.view);
    } catch (e) { return { ok: false, reason: String(e && e.message || e) }; }
    return { ok: true };
  });
  ipcMain.handle('restore-discarded-tab', (event, tabId) => {
    if (!isMainSender(event)) return { ok: false };
    const tab = tabs.find(t => t.id === tabId);
    if (!tab || !tab.discarded) return { ok: false, reason: 'not-discarded' };
    const view = new WebContentsView({
      webPreferences: {
        preload: path.join(__dirname, 'preload.js'),
        contextIsolation: true, nodeIntegration: false, sandbox: true, spellcheck: spellcheckEnabled
      }
    });
    tab.view = view;
    tab.discarded = false;
    mainWindow.contentView.addChildView(view);
    setupTabView(tab);
    switchToTab(tabs.indexOf(tab));
    return { ok: true };
  });
  ipcMain.handle('set-https-only', (event, enabled) => {
    if (!isMainSender(event)) return { success: false };
    httpsOnlyEnabled = !!enabled;
    persistSettings({ httpsOnlyEnabled });
    return { success: true, httpsOnlyEnabled };
  });
  ipcMain.handle('set-block-trackers', (event, enabled) => {
    if (!isMainSender(event)) return { success: false };
    blockTrackers = !!enabled;
    persistSettings({ blockTrackers });
    return { success: true, blockTrackers };
  });
  ipcMain.handle('set-crash-recovery', (event, enabled) => {
    if (!isMainSender(event)) return { success: false };
    crashRecoveryEnabled = !!enabled;
    persistSettings({ crashRecoveryEnabled });
    return { success: true, crashRecoveryEnabled };
  });
  ipcMain.handle('set-clear-on-exit', (event, enabled) => {
    if (!isMainSender(event)) return { success: false };
    clearOnExit = !!enabled;
    persistSettings({ clearOnExit });
    return { success: true, clearOnExit };
  });
  ipcMain.handle('set-confirm-close-multiple', (event, enabled) => {
    if (!isMainSender(event)) return { success: false };
    confirmCloseMultiple = !!enabled;
    persistSettings({ confirmCloseMultiple });
    return { success: true, confirmCloseMultiple };
  });
  ipcMain.handle('set-spellcheck', (event, payload) => {
    if (!isMainSender(event)) return { success: false };
    if (payload && typeof payload === 'object') {
      if (typeof payload.enabled === 'boolean') spellcheckEnabled = payload.enabled;
      if (Array.isArray(payload.languages)) spellcheckLanguages = sanitizeSpellcheckLanguages(payload.languages);
      applySpellcheckSettings();
      persistSettings({ spellcheckEnabled, spellcheckLanguages });
    }
    return { success: true, spellcheckEnabled, spellcheckLanguages };
  });
  ipcMain.handle('get-spellcheck-info', event => {
    if (!isMainSender(event)) return { success: false };
    let available = [];
    try { available = session.defaultSession.availableSpellCheckerLanguages || []; } catch {}
    return { success: true, enabled: spellcheckEnabled, languages: spellcheckLanguages, available };
  });
  ipcMain.handle('set-dark-mode', (event, dark) => {
    if (!isMainSender(event)) return { success: false };
    applyDarkMode(!!dark);
    persistSettings({ darkMode: !!dark });
    return { success: true, darkMode: !!dark };
  });
  ipcMain.handle('get-settings', event => {
    if (!isMainSender(event)) return { success: false };
    return {
      success: true,
      httpsOnlyEnabled, blockTrackers, crashRecoveryEnabled,
      clearOnExit, confirmCloseMultiple, spellcheckEnabled,
      spellcheckLanguages,
      darkMode: nativeTheme.shouldUseDarkColors
    };
  });
  ipcMain.handle('get-tracker-stats', event => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, count: blockedTrackerCount, top: topBlockedHosts() };
  });
  ipcMain.handle('open-external', async (event, url, origin) => {
    if (!isMainSender(event)) return { ok: false, reason: 'untrusted' };
    return await confirmAndOpenExternal(url, origin);
  });
  ipcMain.handle('open-tab-external', async (event, url) => {
    if (!isMainSender(event)) return { ok: false, reason: 'untrusted' };
    if (!isSafeUrl(url)) {
      recordSecurityEvent('protocol-blocked', 'critical', `外部打开入口拒绝不安全地址: ${url}`);
      return { ok: false, reason: 'unsafe url' };
    }
    try { await shell.openExternal(url, { activate: true }); return { ok: true }; }
    catch (e) { return { ok: false, reason: String(e && e.message || e) }; }
  });
  ipcMain.handle('clear-site-data', async event => {
    if (!isMainSender(event)) return { success: false };
    try {
      await session.defaultSession.clearStorageData({
        storages: ['cookies', 'filesystem', 'indexdb', 'localstorage', 'shadercache', 'websql', 'serviceworkers', 'cachestorage']
      });
      await session.defaultSession.clearCache();
      return { success: true };
    } catch (e) { return { success: false, error: String(e && e.message || e) }; }
  });
}
function persistSettings(patch) {
  try {
    const p = path.join(app.getPath('userData'), 'cosySettings.json');
    const current = fsSync.existsSync(p) ? JSON.parse(fsSync.readFileSync(p, 'utf-8')) : {};
    Object.assign(current, patch);
    fsSync.writeFileSync(p, JSON.stringify(current, null, 2), 'utf-8');
  } catch (e) { console.error('保存设置失败:', e); }
}
function registerBookmarkAndHistoryIpc() {
  ipcMain.handle('get-bookmarks', event => { if (!isMainSender(event)) return []; return bookmarks; });
  ipcMain.handle('add-bookmark', (event, { url, title }) => {
    if (!isMainSender(event)) return { success: false };
    if (!isSafeUrl(url)) return { success: false, error: 'unsafe url' };
    if (!bookmarks.some(b => b.url === url)) {
      bookmarks.push({ url, title: title || url, addedAt: Date.now() });
      saveBookmarks();
      const tab = tabs.find(t => t.url === url);
      if (tab) { tab.bookmarked = true; updateTabBadge(tab); }
    }
    return { success: true, bookmarks };
  });
  ipcMain.handle('remove-bookmark', (event, url) => {
    if (!isMainSender(event)) return { success: false };
    const before = bookmarks.length;
    bookmarks = bookmarks.filter(b => b.url !== url);
    if (bookmarks.length !== before) {
      saveBookmarks();
      const tab = tabs.find(t => t.url === url);
      if (tab) { tab.bookmarked = false; updateTabBadge(tab); }
    }
    return { success: true, bookmarks };
  });
  ipcMain.handle('is-bookmarked', (event, url) => {
    if (!isMainSender(event)) return false;
    return bookmarks.some(b => b.url === url);
  });
  ipcMain.handle('export-bookmarks', async event => {
    if (!isMainSender(event)) return { success: false };
    try {
      const result = await dialog.showSaveDialog(mainWindow, {
        title: '导出书签',
        defaultPath: path.join(app.getPath('downloads'), 'cosy-bookmarks.html'),
        filters: [{ name: 'HTML 书签', extensions: ['html', 'htm'] }]
      });
      if (result.canceled || !result.filePath) return { success: false, canceled: true };
      const html = bookmarkIO.buildNetscapeBookmarkHTML(bookmarks);
      await fs.writeFile(result.filePath, html, 'utf-8');
      return { success: true, path: result.filePath };
    } catch (e) { return { success: false, error: String(e && e.message || e) }; }
  });
  ipcMain.handle('import-bookmarks', async event => {
    if (!isMainSender(event)) return { success: false };
    try {
      const result = await dialog.showOpenDialog(mainWindow, {
        title: '导入书签',
        properties: ['openFile'],
        filters: [{ name: 'HTML 书签', extensions: ['html', 'htm'] }]
      });
      if (result.canceled || !result.filePaths.length) return { success: false, canceled: true };
      const raw = await fs.readFile(result.filePaths[0], 'utf-8');
      const imported = bookmarkIO.parseNetscapeBookmarkHTML(raw);
      let added = 0;
      for (const item of imported) {
        if (!isSafeUrl(item.url)) continue;
        if (!bookmarks.some(b => b.url === item.url)) {
          bookmarks.push({ url: item.url, title: item.title || item.url, addedAt: Date.now() });
          added += 1;
        }
      }
      if (added > 0) saveBookmarks();
      return { success: true, added, total: bookmarks.length };
    } catch (e) { return { success: false, error: String(e && e.message || e) }; }
  });
  ipcMain.handle('get-history', event => {
    if (!isMainSender(event)) return [];
    return history;
  });
  ipcMain.handle('clear-history', event => {
    if (!isMainSender(event)) return { success: false };
    history = [];
    saveHistory();
    return { success: true };
  });
  ipcMain.handle('remove-history-entry', (event, url) => {
    if (!isMainSender(event)) return { success: false };
    const before = history.length;
    history = history.filter(h => h.url !== url);
    if (history.length !== before) saveHistory();
    return { success: true };
  });
}
const DEFAULT_TILES = [
  { name: '热土工作室', url: 'https://rtstu.com', color: '#ff7043' },
  { name: 'BHA (PyPI)', url: 'https://pypi.org/project/bool-hybrid-array/', color: '#006dad' },
  { name: 'BK · GitHub', url: 'https://github.com/BKsell', color: '#24292f' },
  { name: 'BHA · Gitee', url: 'https://gitee.com/BKsell/bool-hybrid-array', color: '#c71d23' },
  { name: 'BHA · GitCode', url: 'https://gitcode.com/BKsell/bool-hybrid-array', color: '#e34d3a' },
  { name: 'BK · CSDN', url: 'https://blog.csdn.net/BKsell', color: '#fc5531' },
  { name: 'BK · 知乎', url: 'https://www.zhihu.com/people/50-78-41-74', color: '#0066ff' },
  { name: 'Bing', url: 'https://www.bing.com', color: '#00897b' },
  { name: '百度', url: 'https://www.baidu.com', color: '#2932e1' },
  { name: '哔哩哔哩', url: 'https://www.bilibili.com', color: '#00a1d6' },
  { name: '维基百科', url: 'https://www.wikipedia.org', color: '#636c72' },
  { name: 'YouTube', url: 'https://www.youtube.com', color: '#ff0000' },
  { name: '淘宝', url: 'https://www.taobao.com', color: '#ff5000' },
  { name: 'Gmail', url: 'https://mail.google.com', color: '#ea4335' },
  { name: 'Outlook', url: 'https://outlook.live.com', color: '#0078d4' }
];
const tileStorePath = path.join(app.getPath('userData'), 'newtab-tiles.json');
function loadTiles() {
  try {
    if (!fsSync.existsSync(tileStorePath)) return DEFAULT_TILES.map(t => ({ ...t }));
    const data = JSON.parse(fsSync.readFileSync(tileStorePath, 'utf8'));
    if (!Array.isArray(data)) return DEFAULT_TILES.map(t => ({ ...t }));
    const out = [];
    for (const t of data) {
      if (!t || typeof t !== 'object') continue;
      if (typeof t.url !== 'string' || !isSafeUrl(t.url)) continue;
      out.push({
        name: typeof t.name === 'string' ? t.name.slice(0, 60) : t.url,
        url: t.url,
        color: isValidColor(t.color) ? t.color : '#455a64'
      });
      if (out.length >= 48) break;
    }
    return out.length ? out : DEFAULT_TILES.map(t => ({ ...t }));
  } catch { return DEFAULT_TILES.map(t => ({ ...t })); }
}
function saveTiles(tiles) {
  const safe = [];
  for (const t of Array.isArray(tiles) ? tiles : []) {
    if (!t || typeof t !== 'object') continue;
    if (typeof t.url !== 'string' || !isSafeUrl(t.url)) continue;
    safe.push({
      name: typeof t.name === 'string' ? t.name.slice(0, 60) : t.url,
      url: t.url,
      color: isValidColor(t.color) ? t.color : '#455a64'
    });
    if (safe.length >= 48) break;
  }
  try { fsSync.writeFileSync(tileStorePath, JSON.stringify(safe, null, 2), 'utf8'); } catch (e) { console.error('保存磁贴失败:', e); }
  return safe;
}
function registerNewtabIpc() {
  ipcMain.handle('get-tiles', event => { if (!isMainSender(event)) return []; return loadTiles(); });
  ipcMain.handle('save-tiles', (event, tiles) => {
    if (!isMainSender(event)) return { success: false };
    const safe = saveTiles(tiles);
    return { success: true, tiles: safe };
  });
}
function formatBytes(n) {
  if (!Number.isFinite(n) || n < 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = n, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}
function getDownloadFilenameFromUrl(url) {
  try {
    const u = new URL(url);
    const last = u.pathname.split('/').filter(Boolean).pop();
    return last ? decodeURIComponent(last) : 'download';
  } catch { return 'download'; }
}
function setupDownloadIpc() {
  ipcMain.handle('choose-download-path', async (event, payload) => {
    if (!isMainSender(event)) return { ok: false, reason: 'untrusted' };
    const filename = typeof payload?.filename === 'string' && payload.filename
      ? path.basename(payload.filename)
      : 'download';
    const result = await dialog.showSaveDialog(mainWindow, {
      title: '选择保存位置',
      defaultPath: path.join(app.getPath('downloads'), filename)
    });
    if (result.canceled || !result.filePath) return { ok: false, reason: 'canceled' };
    return { ok: true, path: result.filePath };
  });
  ipcMain.handle('download-resume', (event, id) => {
    if (!isMainSender(event)) return { ok: false };
    const rec = downloads.find(d => String(d.id) === String(id));
    if (!rec) return { ok: false, reason: 'not-found' };
    if (rec.status === 'completed' && rec.savePath) shell.showItemInFolder(rec.savePath);
    return { ok: true };
  });
  ipcMain.handle('download-cancel', (event, id) => {
    if (!isMainSender(event)) return { ok: false };
    const rec = downloads.find(d => String(d.id) === String(id));
    if (!rec) return { ok: false, reason: 'not-found' };
    if (rec.item && typeof rec.item.cancel === 'function') {
      try { rec.item.cancel(); } catch {}
    }
    rec.status = 'canceled';
    sendShelf();
    return { ok: true };
  });
  ipcMain.handle('download-show', (event, id) => {
    if (!isMainSender(event)) return { ok: false };
    const rec = downloads.find(d => String(d.id) === String(id));
    if (!rec || !rec.savePath) return { ok: false, reason: 'not-found' };
    shell.showItemInFolder(rec.savePath);
    return { ok: true };
  });
  ipcMain.handle('download-open', async (event, id) => {
    if (!isMainSender(event)) return { ok: false };
    const rec = downloads.find(d => String(d.id) === String(id));
    if (!rec || rec.status !== 'completed' || !rec.savePath) return { ok: false, reason: 'not-ready' };
    const dangerous = /\.(exe|msi|bat|cmd|com|scr|ps1|reg|jar|app|dmg|deb|rpm|apk)$/i.test(rec.filename || '');
    if (dangerous) {
      const choice = await dialog.showMessageBox(mainWindow, {
        type: 'warning', buttons: ['打开', '取消'], defaultId: 1, cancelId: 1,
        title: '打开可执行文件',
        message: `文件 ${rec.filename} 是可执行文件，仍要打开吗？`
      });
      if (choice.response !== 0) return { ok: false, reason: 'user-cancel' };
    }
    const err = await shell.openPath(rec.savePath);
    return err ? { ok: false, reason: err } : { ok: true };
  });
  ipcMain.handle('download-shelf-list', event => {
    if (!isMainSender(event)) return [];
    return shelfSnapshot();
  });
  ipcMain.handle('list-download-hashes', (event, limit) => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, records: listDownloadHashes(limit) };
  });
  ipcMain.handle('remove-download-hash', (event, id) => {
    if (!isMainSender(event)) return { success: false };
    const removed = removeDownloadHashRecord(id);
    return { success: true, removed };
  });
  ipcMain.handle('clear-download-hashes', event => {
    if (!isMainSender(event)) return { success: false };
    clearDownloadHashes();
    return { success: true };
  });
  ipcMain.handle('verify-download-hash', (event, id, expected) => {
    if (!isMainSender(event)) return { ok: false, reason: 'untrusted' };
    return verifyDownloadHashById(id, expected);
  });
  ipcMain.handle('hash-local-file', event => {
    if (!isMainSender(event)) return { ok: false, reason: 'untrusted' };
    return hashLocalFileViaDialog();
  });
  ipcMain.handle('list-permission-decisions', event => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, decisions: listPermissionDecisions() };
  });
  ipcMain.handle('forget-permission', (event, origin, permission) => {
    if (!isMainSender(event)) return { success: false };
    const ok = forgetPermission(String(origin || ''), String(permission || ''));
    return { success: true, forgotten: ok };
  });
  ipcMain.handle('clear-permissions-for-origin', (event, origin) => {
    if (!isMainSender(event)) return { success: false };
    const n = clearPermissionDecisionsForOrigin(String(origin || ''));
    return { success: true, removed: n };
  });
  ipcMain.handle('list-security-events', (event, type, limit) => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, events: listSecurityEvents(type, limit) };
  });
  ipcMain.handle('clear-security-events', event => {
    if (!isMainSender(event)) return { success: false };
    clearSecurityEvents();
    return { success: true };
  });
  ipcMain.handle('list-csp-reports', (event, limit) => {
    if (!isMainSender(event)) return { success: false };
    return { success: true, reports: listCspReports(limit) };
  });
  ipcMain.handle('clear-csp-reports', event => {
    if (!isMainSender(event)) return { success: false };
    clearCspReports();
    return { success: true };
  });
}
function beginTrackedDownload(event, item, webContents, downloadUrl) {
  const downloadId = `dl-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const downloadInfo = {
    id: downloadId,
    filename: item.getFilename(),
    url: downloadUrl,
    totalBytes: item.getTotalBytes(),
    receivedBytes: 0,
    progress: 0,
    speed: '0 B/s',
    status: 'progressing',
    startTime: Date.now(), savePath: null, item,
    lastUpdate: Date.now(), lastReceivedBytes: 0, isItemValid: true,
        expectedHash: null
      };
      downloads.push(downloadInfo);
  currentDownloadInfo = downloadInfo;
  sendShelf();
  item.on('updated', (e, state) => {
    if (state === 'interrupted') downloadInfo.status = 'paused';
    if (state === 'progressing') {
      downloadInfo.status = item.isPaused() ? 'paused' : 'progressing';
      downloadInfo.receivedBytes = item.getReceivedBytes();
      downloadInfo.totalBytes = item.getTotalBytes();
      downloadInfo.progress = downloadInfo.totalBytes > 0 ? (downloadInfo.receivedBytes / downloadInfo.totalBytes) : 0;
      const now = Date.now();
      const dt = (now - downloadInfo.lastUpdate) / 1000;
      if (dt >= 0.5) {
        const diff = downloadInfo.receivedBytes - downloadInfo.lastReceivedBytes;
        downloadInfo.speed = `${formatBytes(diff / dt)}/s`;
        downloadInfo.lastUpdate = now;
        downloadInfo.lastReceivedBytes = downloadInfo.receivedBytes;
      }
      sendShelf();
    }
  });
  item.once('done', (e, state) => {
    downloadInfo.receivedBytes = item.getReceivedBytes();
    downloadInfo.totalBytes = item.getTotalBytes();
    downloadInfo.savePath = item.getSavePath();
    if (state === 'completed') {
      downloadInfo.status = 'completed';
      downloadInfo.progress = 1;
      downloadInfo.speed = '';
      sendShelf();
      if (downloadInfo.savePath) queueDownloadHashing(downloadInfo);
    } else if (state === 'interrupted') {
      downloadInfo.status = 'interrupted';
      sendShelf();
    } else {
      downloadInfo.status = 'canceled';
      sendShelf();
    }
  });
}
app.whenReady().then(() => {
  loadHistory();
  loadBookmarks();
  applySpellcheckSettings();
  protocol.registerSchemesAsPrivileged([
    { scheme: 'cosy', privileges: { standard: true, secure: true, supportFetchAPI: true } }
  ]);
  protocol.handle('cosy', request => {
    const url = new URL(request.url);
    const map = {
      '/newtab': path.join(__dirname, 'src/newtab.html'),
      '/history': path.join(__dirname, 'src/history.html'),
      '/bookmarks': path.join(__dirname, 'src/bookmarks.html'),
      '/settings': path.join(__dirname, 'src/settings.html'),
      '/permissions': path.join(__dirname, 'src/permissions.html'),
      '/security': path.join(__dirname, 'src/security.html')
    };
    const file = map[url.pathname];
    if (file) return new Response(fsSync.createReadStream(file)) ;
    return new Response('Not found', { status: 404 });
  });
  ipcMain.handle('csp-violation', (event, payload) => {
    if (!isMainSender(event)) return { accepted: false, reason: 'untrusted' };
    return recordCspViolationFromRenderer(event.senderFrame, payload);
  });
  createWindow();
});
app.on('window-all-closed', () => {
  globalShortcut.unregisterAll();
  if (process.platform !== 'darwin') app.quit();
});
app.on('will-quit', () => { globalShortcut.unregisterAll(); });
app.on('web-contents-created', (event, contents) => {
  contents.on('will-attach-webview', (e, webPreferences, params) => {
    e.preventDefault();
  });
});
ipcMain.handle('get-current-tab-info', event => {
  if (!isMainSender(event)) return null;
  const tab = tabs[currentTabIndex];
  return tab ? { id: tab.id, url: tab.url, title: tab.title, canGoBack: tab.canGoBack, canGoForward: tab.canGoForward } : null;
});
ipcMain.handle('find-in-page', (event, text, options = {}) => {
  if (!isMainSender(event)) return { success: false };
  const wc = getCurrentTabWebContents();
  if (!wc || !text) return { success: false, matches: 0 };
  const result = wc.findInPage(text, { forward: options.forward !== false, findNext: !!options.findNext });
  return { success: true, matches: result.result, activeMatch: result.activeMatchOrdinal };
});
ipcMain.handle('stop-find-in-page', event => {
  if (!isMainSender(event)) return { success: false };
  const wc = getCurrentTabWebContents();
  if (wc) wc.stopFindInPage('clearSelection');
  return { success: true };
});
function fetchSearchSuggestions(query) {
  return new Promise(resolve => {
    try {
      const url = `https://suggestionquay.com/suggestions?query=${encodeURIComponent(query)}`;
      const request = net.request(url);
      let body = '';
      const timer = setTimeout(() => { try { request.abort(); } catch {} resolve([]); }, 4000);
      request.on('response', response => {
        if (response.statusCode !== 200) { clearTimeout(timer); resolve([]); return; }
        response.on('data', chunk => { body += chunk.toString('utf8'); });
        response.on('end', () => {
          clearTimeout(timer);
          try {
            const data = JSON.parse(body);
            const suggestions = Array.isArray(data.suggestions) ? data.suggestions.slice(0, 10).filter(s => typeof s === 'string') : [];
            resolve(suggestions);
          } catch { resolve([]); }
        });
      });
      request.on('error', () => { clearTimeout(timer); resolve([]); });
      request.end();
    } catch { resolve([]); }
  });
}
ipcMain.handle('get-search-suggestions', async (event, query) => {
  if (!isMainSender(event)) return { success: false, suggestions: [] };
  const q = String(query || '').trim();
  if (!q) return { success: true, suggestions: [] };
  const suggestions = await fetchSearchSuggestions(q);
  return { success: true, suggestions };
});
