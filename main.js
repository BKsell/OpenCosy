const { app, BrowserWindow, WebContentsView, ipcMain, session, protocol, Menu, MenuItem, dialog, shell, globalShortcut, clipboard, net, nativeTheme, webContents, safeStorage } = require('electron');
const path = require('path');
const fs = require('fs').promises;
const fsSync = require('fs');
const crypto = require('crypto');
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

function noteGuardResult(label, result, url, shouldLog) {
  if (result.changed && shouldLog) {
    recordSecurityEvent('mixed-content-blocked', 'warn', `${label}:${result.reason}`, fpGuard.hostOf(url));
  }
  return result;
}

function noteGuardDenied(label, result, url, shouldLog) {
  if (!result.allowed && shouldLog) {
    recordSecurityEvent('mixed-content-blocked', 'warn', `${label}:${result.reason}`, fpGuard.hostOf(url));
  }
  return result;
}

const corsGuard = require('./corsmisconfigguard');
const authChallengeGuard = require('./httpauthchallengeguard');
const mimeExecGuard = require('./mimetypeexecguard');
const cacheVaryGuard = require('./cachevaryguard');
const cookieJarGuard = require('./cookiejarhardening');
const downloadNameGuard = require('./downloadnameextguard');
const refreshGuard = require('./httpequivrefreshguard');
const serverTimingGuard = require('./servertimingguard');
const contentRangeGuard = require('./contentrangeguard');
const charsetGuard = require('./charsetguard');
const proxyAuthGuard = require('./proxyauthguard');
const altSvcGuard = require('./altsvcguard');
const nelReportGuard = require('./nelreportguard');
const linkPreloadGuard = require('./linkpreloadguard');
const digestGuard = require('./digestguard');
const contentLocationGuard = require('./contentlocationguard');
const serverBannerGuard = require('./serverbannerstripguard');
const legacyPinGuard = require('./legacypinninguard');
const contentEncodingGuard = require('./contentencodingguard');
const referrerPolicyGuard = require('./referrerpolicyguard');
const crossOriginPolicyGuard = require('./crossoriginpolicyguard');
const setCookiePrefixGuard = require('./setcookieprefixguard');
const retryAfterGuard = require('./retryafterguard');
const xContentTypeOptionsGuard = require('./xcontenttypeoptionsguard');
const wwwAuthenticateGuard = require('./wwwauthenticateguard');
const timingAllowOriginGuard = require('./timingalloworiginpolicyguard');
const headerInjectionGuard = require('./headerinjectionguard');
const hstsGuard = require('./hstsguard');
const exposeHeadersGuard = require('./exposeheadersguard');
const maxAgeGuard = require('./maxageguard');
const allowMethodsGuard = require('./allowmethodsguard');
const allowHeadersGuard = require('./allowheadersguard');
const coopGuard = require('./coopguard');
const secFetchModeGuard = require('./secfetchmodeguard');
const secFetchDestGuard = require('./secfetchdestguard');
const secFetchUserGuard = require('./secfetchuserguard');
const chPlatformGuard = require('./chplatformguard');
const chMobileGuard = require('./chmobileguard');
const ifMatchGuard = require('./ifmatchguard');
const ifRangeGuard = require('./ifrangeguard');
const ifModifiedSinceGuard = require('./ifmodifiedsinceguard');
const ifUnmodifiedSinceGuard = require('./ifunmodifiedsinceguard');
const contentTypeGuard = require('./contenttypeguard');
const allowHeaderGuard = require('./allowguard');
const expiresGuard = require('./expiresguard');
const earlyHintGuard = require('./earlyhintguard');
const traceStateGuard = require('./tracestateguard');
const baggageGuard = require('./baggagguard');
const xfwdProtoGuard = require('./xfwdprotoguard');
const xfwdHostGuard = require('./xfwdhostguard');
const xfwdForGuard = require('./xfwdforguard');
const featurePolicyGuard = require('./featurepolicyguard');
const criticalChGuard = require('./criticalchguard');
const wantDigestGuard = require('./wantdigestguard');
const xMethodOverrideGuard = require('./xhttpmethodoverrideguard');
const xOriginalUrlGuard = require('./xoriginalurlguard');
const corpGuard = require('./corpguard');
const xfwdPortGuard = require('./xfwdportguard');
const taoOriginGuard = require('./taoguard');
const proxyAuthenticateGuard = require('./proxyauthenticateguard');
const xRequestedWithGuard = require('./xrequestedwithguard');
const xRobotsGuard = require('./xrobotsguard');
const coepGuard = require('./coepguard');
const cspReportOnlyGuard = require('./cspreportonlyguard');
const xpcdpGuard = require('./xpcdpguard');
const acacGuard = require('./acacguard');
const contentDispositionGuard = require('./contentdispositionguard');
const secGpcGuard = require('./secgpcguard');
const dntGuard = require('./dntguard');
const acceptLanguageGuard = require('./acceptlanguageguard');
const ifNoneMatchGuard = require('./ifnonematchguard');
const rangeGuard = require('./rangeguard');
const connectionGuard = require('./connectionguard');
const teGuard = require('./teguard');
const viaGuard = require('./viaguard');
const forwardedGuard = require('./forwardedguard');
const secFetchSiteGuard = require('./secfetchsiteguard');
const sourceMapGuard = require('./sourcedmapguard');
const attributionGuard = require('./attributionguard');
const reportingEndpointsGuard = require('./reportingendpointsguard');
const noSniffGuard = require('./nosniffguard');
const xRequestIdGuard = require('./xrequestidguard');
const traceparentGuard = require('./traceparentguard');
const saveDataGuard = require('./savedataguard');
const trueClientIpGuard = require('./trueclientipguard');
const xRealIpGuard = require('./xrealipguard');
const acceptEncodingGuard = require('./acceptencodingguard');
const priorityGuard = require('./priorityguard');
const linkResponseGuard = require('./linkresponseguard');
const acceptPatchGuard = require('./acceptpatchguard');
const speculationRulesGuard = require('./speculationrulesguard');
const proxyStatusGuard = require('./proxystatusguard');
const acceptCharsetGuard = require('./acceptcharsetguard');
const reportingGuard = require('./reporttoguard');
const upgradeGuard = require('./upgradeguard');
const expectCtGuard = require('./expectctguard');
const publicKeyPinsGuard = require('./publickeypinsguard');
const originTrialGuard = require('./origintrialguard');
const documentPolicyGuard = require('./documentpolicyguard');
const contentDigestGuard = require('./contentdigestguard');
const cacheStatusGuard = require('./cachestatusguard');
const etagGuard = require('./etagguard');
const trailerFieldGuard = require('./trailerfieldguard');
const secWebSocketGuard = require('./wsacceptguard');
const xDownloadOptionsGuard = require('./xdownloadoptionsguard');
const fileSystemAccessGuard = require('./filesystemaccessguard');
const credentialRequestGuard = require('./credentialrequestguard');
const acceptChLifetimeGuard = require('./acceptchlifetimeguard');
const xuaCompatibleGuard = require('./xuacompatibleguard');
const acceptRangesGuard = require('./acceptrangesguard');
const contentBaseGuard = require('./contentbaseguard');
const contentMd5Guard = require('./contentmd5guard');
const pragmaCacheGuard = require('./pragmacacheguard');
const surrogateControlGuard = require('./surrogatecontrolguard');
const setCookie2Guard = require('./setcookie2guard');
const xWebKitCspGuard = require('./xwebkitcspguard');
const authenticationInfoGuard = require('./authenticationinfoguard');
const originAgentClusterGuard = require('./originagentcluster');
const ageClockGuard = require('./ageclockguard');
const warningHeaderGuard = require('./warningheaderguard');
const contentLanguageGuard = require('./contentlanguageguard');
const lastModifiedGuard = require('./lastmodifiedguard');
const dnsPrefetchGuard = require('./xdnsprefetchguard');
const headerBudgetGuard = require('./headerbudgetguard');
const acceptChGuard = require('./acceptchpolicyguard');
const keepAliveGuard = require('./keepaliveguard');
const crossDomainPolicyGuard = require('./xpermittedcrossdomainguard');
const transferEncodingGuard = require('./contenttransferencodingguard');
const permissionsPolicyGuard = require('./permissionspolicyguard');
const frameOptionsGuard = require('./frameoptionsguard');
const cacheAuthGuard = require('./cacheauthguard');
const xssProtectionGuard = require('./xssprotectionguard');
const clearSiteDataGuard = require('./clearsitedataguard');
const serviceWorkerAllowedGuard = require('./serviceworkerallowedguard');
const hopByHopGuard = require('./hopbyhopguard');
const requestPipeline = require('./requestpipeline');
const downloadAdmission = require('./downloadadmission');
const downloadNotify = require('./downloadnotify');
const downloadShelf = require('./downloadshelf');
const extensionStore = require('./extensionstore');
const suggestionGuard = require('./suggestionguard');
const hostMatch = require('./hostmatch');
const urlResolve = require('./urlresolve');
const pointerLockFrame = require('./pointerlockframe');
const clipboardFrame = require('./clipboardframe');
const fullscreenFrame = require('./fullscreenframe');
const permissionDenyLedger = require('./permissiondenyledger');
const createDenyLedger = permissionDenyLedger.createDenyLedger;
const popupOpenerFrame = require('./popupopenerframe');
const notificationFrame = require('./notificationframe');
const pathContain = require('./pathcontain');
const shortcutKeys = require('./shortcutkeys');
const taskManagerCore = require('./taskmanager');
const dohGuard = require('./dohguard');const permPolicy = require('./permpolicy');
const dloadGuard = require('./dloadguard');
const downloadName = require('./downloadname');
const downloadChain = require('./downloadchain');
const downloadChainLive = require('./downloadchainlive');
const downloadQuotaCore = require('./downloadquota');
const downloadSaveTarget = require('./downloadsavetarget');
const downloadByteQuota = new downloadQuotaCore.DownloadQuota();
const downloadRateGuard = require('./downloadratelimit');
const downloadFreqLimiter = new downloadRateGuard.DownloadRateLimiter();
const dloadOpen = require('./dloadopen');
const urlClean = require('./urlclean');
const downloadJournalModule = require('./downloadjournal');
const downloadReconcileModule = require('./downloadreconcile');
const permissionGrants = require('./permissiongrants');
const securityPosture = require('./securityposture');
const downloadJournalExport = require('./downloadjournalexport');
const permissionRiskReport = require('./permissionriskreport');
const downloadDiskSpace = require('./downloaddiskspace');
const downloadDiskMonitorModule = require('./downloaddiskmonitor');
const downloadPathCollision = require('./downloadpathcollision');
const downloadSizeGuard = require('./downloadsizeguard');
const downloadHostGuard = require('./downloadhostguard');
const downloadSlotReservation = require('./downloadslotreservation');
const downloadFinishGuard = require('./downloadfinishguard');
const downloadContentMagic = require('./downloadcontentmagic');
let downloadJournal = null;
const popupGuard = require('./popupguard');
const quarantine = require('./quarantine');
const navGuard = require('./navguard');
const httpsOnlyCore = require('./httpsonly');
const readerCore = require('./reader');
const vaultCore = require('./vault');
const cleanerCore = require('./cleaner');
const uaPolicyCore = require('./uapolicy');
const searchProvider = require('./searchprovider');
const containerGuard = require('./container');
const schemeOrigin = require('./schemeorigin');
const webviewHarden = require('./webviewharden');
const internalFrame = require('./internalframe');
const winPolicy = require('./winpolicy');
const goneGuard = require('./goneguard');
const shellGuard = require('./shellguard');
const externalProtocolBudget = require('./externalprotocolbudget');
const clipboardReadOrigin = require('./clipboardreadorigin');
const requestMethodGuard = require('./requestmethodguard');
const pluginResourceGuard = require('./pluginresourceguard');
const externalBudget = externalProtocolBudget.createExternalBudget();
const deeplinkGuard = require('./deeplinkguard');
const ipcGuard = require('./ipcguard');
const channelPolicy = require('./channelpolicy');
const displayGuard = require('./displayguard');
const redirectGuard = require('./redirectguard');
const switchGuard = require('./switchguard');
const blockRules = require('./blockrules');
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
const pinTabs = require('./pintabs');
const tabSearch = require('./tabsearch');
const tabGroups = require('./tabgroups');
const tabOrderDiff = require('./taborderdiff');
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
const securityBoundaryHub = require('./securityboundaryhub');
const ledgerStore = require('./ledgerstore');
const securityHeadersGuard = require('./securityheadersguard');
const downloadSourceTrustGuard = require('./downloadsourcetrustguard');
const navigationTimeoutGuard = require('./navigationtimeoutguard');
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
// 稍后读列表：{ url, title, addedDate }，纯本机数据，不参与同步。
let readingList = [];
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

// bookmarkBarVisible：顶栏书签栏显隐（Ctrl+Shift+B 切换）。持久化在 cosySettings.json，
// 跨重启保留用户偏好，与书签管理面板（始终可开）互不影响。
let bookmarkBarVisible = true;

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
// allowPictureInPicture：是否允许网页进入画中画（Permissions-Policy:
// picture-in-picture）。默认放开以保留现代浏览器能力，用户可在隐私设置里全局关闭，
// 防止视频站点用悬浮小窗持续跟踪 / 离开页面后继续播放。
let allowPictureInPicture = true;
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

// ===== 自定义拦截规则（用户可管理，优先于内置列表）=====
// 内置追踪域列表无法覆盖用户特定场景；blockRules 内核提供 host / glob / path
// 三类规则、持久化与导入导出。customRules 为内存态规则集，compiledCustomRules
// 为预编译正则，rulesFile 为持久化路径（userData/blockrules.json）。
const customRules = blockRules.createEmptyRules();
let compiledCustomRules = blockRules.compileRules(customRules);
let customRulesLoaded = false;
let customRulesFile = '';

function reloadCustomRules() {
  compiledCustomRules = blockRules.compileRules(customRules);
}

function loadCustomRulesFromDisk(filePath) {
  customRulesFile = filePath;
  if (!customRulesLoaded) {
    const loaded = blockRules.loadRules(filePath);
    customRules.host = loaded.host;
    customRules.glob = loaded.glob;
    customRules.path = loaded.path;
    customRulesLoaded = true;
    reloadCustomRules();
  }
}

function persistCustomRules() {
  if (!customRulesFile) return { ok: false, reason: 'no-file' };
  const r = blockRules.saveRules(customRulesFile, customRules);
  reloadCustomRules();
  return r;
}

// hostMatchesTracker 判断主机是否为已知追踪域（精确或其子域）。
// 归一化（小写/去尾点）与精确-子域边界判断统一由 hostmatch 内核负责，
// 避免与 Cookie 归属、私网判定各写一套口径。
function hostMatchesTracker(hostname) {
  return hostMatch.hostMatchesList(hostname, TRACKER_HOSTS);
}

// isTrackerRequest 只拦子资源，顶层框架 / iframe 框架文档一律放行，避免误伤导航。
// 自定义规则优先（decideBlocked 先查 host/glob/path），内置列表兜底。
function isTrackerRequest(details) {
  if (!blockTrackers) return false;
  const rt = details.resourceType;
  if (rt === 'mainFrame' || rt === 'subFrame') return false;
  let host = '';
  try { host = new URL(details.url).hostname; } catch { return false; }
  const decision = blockRules.decideBlocked(details.url, compiledCustomRules, TRACKER_HOSTS);
  if (decision) return true;
  return hostMatchesTracker(host);
}

function recordBlockedTracker(url) {
  blockedTrackerCount += 1;
  const host = urlResolve.safeHostname(url, '(unknown)');
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
  // Referer 收敛需要用 null 表达"无法解析/无同源源"，保持原语义。
  return urlResolve.safeOrigin(u, null);
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
    return ledgerStore.readJSONStore(p, {});
  } catch (e) {
    console.error('启动时读取设置失败:', e);
  }
  return {};
}

const isDev = !app.isPackaged;

function isMainSender(event) {
  if (!mainWindow || !event || event.sender !== mainWindow.webContents) return false;
  const frame = event.senderFrame;
  if (!frame) return false;
  try {
    return frame.parent === null && frame.top === frame;
  } catch {
    return false;
  }
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
// 快照构建与字段净化收口到 downloadshelf 内核：剥控制字符/ANSI、按字节截断、
// 状态白名单、进度 clamp、savePath 只留存在性标记、附带整张台账的统计角标。
const MAX_SHELF_ITEMS = 3;

function shelfSnapshot() {
  return downloadShelf.buildShelfSnapshot(downloads, downloadShelf.ShelfLimits).items;
}

function sendShelf() {
  persistDownloads();
  sendToRenderer('download-shelf', downloadShelf.buildShelfSnapshot(downloads, downloadShelf.ShelfLimits));
}

// ===== 下载记录持久化（downloads.json）=====
// 下载台账此前只活在内存里，重启即丢。这里落盘到 userData/downloads.json：
// 写入前每条记录过 downloadshelf 内核净化（剥控制字符/ANSI、字段白名单、
// savePath 显式校验），读取时同源净化并约束条数，防止被外部程序写坏的
// 文件把危险字段灌回运行时。落盘走 ledgerStore 原子写，失败只记审计事件，
// 不阻断下载流程。
const MAX_PERSISTED_DOWNLOADS = 500;

function downloadsStorePath() {
  return path.join(app.getPath('userData'), 'downloads.json');
}

function persistDownloads() {
  try {
    const items = (downloads || []).slice(0, MAX_PERSISTED_DOWNLOADS)
      .map(d => downloadShelf.sanitizeDownloadRecord(d, downloadShelf.ShelfLimits));
    ledgerStore.writeJSONStore(downloadsStorePath(), items, { pretty: true });
  } catch (e) {
    recordSecurityEvent('downloads-persist', 'error',
      '下载台账落盘失败: ' + String((e && e.message) || e).slice(0, 160), '');
  }
}



// ===== 下载系统通知（downloadnotify 内核的 Electron 接线）=====
// 窗口最小化 / 失焦时用户看不到底部下载栏，完成与失败都要弹系统通知（Chrome、
// Edge 同款行为）。通知内容已由 downloadnotify 内核净化：剥控制字符与 CSI 序列、
// 按字节截断、不落完整本地路径、失败不给原始异常，这里只把内核产出接到 Electron
// Notification 与点击动作上（完成点开文件，失败只聚焦窗口并留给用户显式重试）。


// notifyDownloadResult 把一次下载结果接成系统通知；通知失败只审计，不打断下载流程。
function notifyDownloadResult(kind, info) {
  try {
    downloadNotify.notifyDownload(kind, downloadNotifyDeps(), info);
  } catch (notifyErr) {
    recordSecurityEvent('download-notify', 'info',
      `系统通知失败: ${String(notifyErr && notifyErr.message || notifyErr)}`,
      originOfContents(webContents));
  }
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
    // 固定标签（Pinned Tab）：固定后收窄成图标、排在标签栏最前、不参与任何
    // 批量关闭，并跨重启按 URL 重水合。权威集合由 pintabs 内核统一维护。
    this.pinned = false;
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
  return pathContain.isContained(dir, filePath, { realpath: realpathForContainment }).ok;
}

function realpathForContainment(p) {
  try {
    return fsSync.realpathSync.native(p);
  } catch {
    return null;
  }
}

function isValidColor(str) {
  return typeof str === 'string' && /^#[0-9a-fA-F]{3,8}$/.test(str);
}

function getCurrentTabWebContents() {
  const tab = tabs[currentTabIndex];
  return tab?.view?.webContents || null;
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
    ledgerStore.writeJSONStore(historyPath, history, { pretty: true });
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
    // 有界读取：损坏 / 被撑大的文件回落为 null，下面按“非数组”清空，绝不整读撑爆主进程。
    const parsed = ledgerStore.readJSONStore(historyPath, null);
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
    ledgerStore.writeJSONStore(bookmarksPath, bookmarks, { pretty: true });
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
      const parsed = ledgerStore.readJSONStore(bookmarksPath, null);
      if (parsed !== null) bookmarks = bookmarkGuard.sanitizeBookmarkList(parsed, Date.now()).items;
    }
  } catch (e) {
    console.error('读取书签失败:', e);
  }
}

// saveReadingList 写稍后读列表：复用 bookmarkGuard 的净化口径（仅 http/https、
// title 去控制字符并限长、按 url 去重），与书签同款有界落盘。
function saveReadingList() {
  const rlPath = path.join(app.getPath('userData'), 'readinglist.json');
  try {
    const cleaned = bookmarkGuard.sanitizeBookmarkList(readingList, Date.now());
    readingList = cleaned.items;
    ledgerStore.writeJSONStore(rlPath, readingList, { pretty: true });
  } catch (e) {
    console.error('保存稍后读失败:', e);
  }
}

function loadReadingList() {
  const rlPath = path.join(app.getPath('userData'), 'readinglist.json');
  try {
    if (fsSync.existsSync(rlPath)) {
      const parsed = ledgerStore.readJSONStore(rlPath, null);
      if (parsed !== null) readingList = bookmarkGuard.sanitizeBookmarkList(parsed, Date.now()).items;
    }
  } catch (e) {
    console.error('读取稍后读失败:', e);
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
    ledgerStore.writeJSONStore(sessionPath, sessionTabs, { pretty: true });
  } catch (e) {
    console.error('保存会话失败:', e);
  }
}

function loadSession() {
  try {
    const sessionPath = path.join(app.getPath('userData'), 'session.json');
    if (fsSync.existsSync(sessionPath)) {
      const parsed = ledgerStore.readJSONStore(sessionPath, null);
      if (parsed === null) return null;
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

function isPrivateNetworkHost(url) {
  try {
    // 主机名归一、IPv4 分段与私网段判断统一走 hostmatch 内核（无正则）。
    return hostMatch.isPrivateHostname(new URL(url).hostname);
  } catch { return false; }
}

// readStoredSettings 只读不校验，启动时用来还原 darkMode / httpsOnly 等运行时状态。
// 校验交给 save-settings 里的 sanitizeSettings。
function readStoredSettings() {
  try {
    const p = path.join(app.getPath('userData'), 'cosySettings.json');
    return ledgerStore.readJSONStore(p, {});
  } catch (e) { console.error('读取设置失败:', e); }
  return {};
}

// ===== HTTPS-Only 站点例外（https-exceptions.json / cosy://httpsonly 面板）=====
// HTTPS-Only 默认把公网 http 主动升级到 https；但确实存在只有明文 HTTP 的老站点 /
// 内网系统。升级失败时，只有在错误码属于“对端根本没在做 TLS”的强信号、且用户在
// 原生确认框里明确同意后，才把该主机登记为例外并回退一次 http。该集合持久化，
// 下次访问同一站点直接保留 http（仍受私网判定与开关约束）。主机名经内核净化，
// 容量受限，写盘防抖，避免被刷爆。
const httpsExceptionStorePath = path.join(app.getPath('userData'), 'https-exceptions.json');
const httpsExceptions = new httpsOnlyCore.HttpExceptionStore(500);
let httpsExceptionsLoaded = false;
let httpsExceptionSaveTimer = null;

function loadHttpsExceptions() {
  if (httpsExceptionsLoaded) return;
  httpsExceptionsLoaded = true;
  try {
    httpsExceptions.load(ledgerStore.readJSONStore(httpsExceptionStorePath, {}));
  } catch (e) { console.error('读取 HTTPS 例外失败:', e); }
}

function persistHttpsExceptions() {
  if (httpsExceptionSaveTimer) clearTimeout(httpsExceptionSaveTimer);
  httpsExceptionSaveTimer = setTimeout(() => {
    try {
      ledgerStore.writeJSONStore(httpsExceptionStorePath, httpsExceptions.toJSON());
    } catch (e) { console.error('写入 HTTPS 例外失败:', e); }
  }, 300);
}

// isHttpExceptionHost 供请求管道与回退逻辑共用，输入可以是 URL 或主机名。
function isHttpExceptionHost(urlOrHost) {
  try {
    const host = String(urlOrHost || '').indexOf('://') >= 0
      ? new URL(urlOrHost).hostname
      : httpsOnlyCore.normalizeExceptionHost(urlOrHost);
    return !!host && httpsExceptions.has(host);
  } catch { return false; }
}

// ===== 加密保险库（vault）与站点数据清理（cleaner）=====
// 保险库：主密钥由 safeStorage（OS 级加密）保护后落盘 vault-key.bin；vault.json
// 只存密文。safeStorage 可用时启动自动解锁；不可用（无 keychain）则保持锁定，
// 由用户输入主密码解锁。清理中心：先枚举 session 存储数据 → 纯内核规划 →
// 用户确认 → 执行 → 审计落盘。
const vaultStorePath = path.join(app.getPath('userData'), 'vault.json');
const vaultKeyPath = path.join(app.getPath('userData'), 'vault-key.bin');
const cleanAuditPath = path.join(app.getPath('userData'), 'clean-audit.json');
let vaultState = null;   // 持久化状态（密文 + 元数据），未解锁时也存在
let vaultHandle = null;  // 已解锁句柄；锁定态为 null
let vaultUsePasswordMode = false;
let cleanAuditLog = [];

// ===== UA 覆盖策略（uapolicy）与下载限速 =====
// UA 策略由 uapolicy.js 纯内核判定（default / custom / chrome-random），这里只
// 负责持久化与把结果灌进 webRequest。改写计数仅统计“真的改了”的请求，供
// cosy://privacy 页展示。下载限速是全局设置（字节/秒，0 表示不限），在
// will-download 里对每个新下载项 setRate 生效。
const uaPolicyPath = path.join(app.getPath('userData'), 'ua-policy.json');
const rateLimitPath = path.join(app.getPath('userData'), 'download-rate-limit.json');
let uaPolicyState = { ...uaPolicyCore.DEFAULT_POLICY };
let uaOverrideCount = 0;
let uaLastOverrideAt = 0;
let downloadRateLimit = 0; // 字节/秒；0 = 不限速
let downloadMaxBytes = downloadSizeGuard.DEFAULT_LIMIT_BYTES; // 单次下载体积上限；0 = 不限
const downloadDiskMonitor = downloadDiskMonitorModule.createDiskMonitor({ minFreeBytes: downloadDiskSpace.MIN_FREE_BYTES });
const downloadSlotGuard = downloadSlotReservation.createSlotReservation();

function loadUaPolicyStateFromDisk() {
  try {
    if (fsSync.existsSync(uaPolicyPath)) {
      const raw = JSON.parse(fsSync.readFileSync(uaPolicyPath, 'utf8'));
      uaPolicyState = uaPolicyCore.sanitizePolicy(raw);
    }
  } catch (e) { console.error('读取 UA 策略失败:', e); }
  try {
    if (fsSync.existsSync(rateLimitPath)) {
      const raw = JSON.parse(fsSync.readFileSync(rateLimitPath, 'utf8'));
      if (raw && Number.isFinite(raw.bytesPerSecond) && raw.bytesPerSecond >= 0) {
        downloadRateLimit = Math.floor(raw.bytesPerSecond);
      }
    }
  } catch (e) { console.error('读取下载限速失败:', e); }
}

function persistUaPolicyState() {
  try { atomicWriteJSON(uaPolicyPath, uaPolicyState); } catch (e) { console.error('写入 UA 策略失败:', e); }
}

function persistRateLimitState() {
  try { atomicWriteJSON(rateLimitPath, { bytesPerSecond: downloadRateLimit }); } catch (e) { console.error('写入下载限速失败:', e); }
}

// applyUaPolicyToSession：把当前策略应用到目标 session（导航级 UA）。
// webRequest 层的按请求改写由 applyOutboundHeaderHardening 负责；这里只在
// 启动与策略变更时调用，让导航请求也吃到最新 UA。
function applyUaPolicyToSession(targetSession) {
  try {
    const effective = uaPolicyCore.resolveUa(uaPolicyState, generateUserAgent());
    targetSession.setUserAgent(effective);
  } catch (e) { console.error('应用 UA 策略失败:', e); }
}

// resolveEffectiveUa 是 webRequest 层每次请求都读取的 UA 取值器。
function resolveEffectiveUa() {
  return uaPolicyCore.resolveUa(uaPolicyState, generateUserAgent());
}

// applyRateLimitToItem：对新下载项套限速（0 表示不限，setRate 无效时不抛）。
function applyRateLimitToItem(item) {
  if (!item || !downloadRateLimit) return;
  try { item.setRate(downloadRateLimit); } catch {}
}

let atomicWriteSeq = 0;

function atomicWriteJSON(filePath, obj) {
  const dir = path.dirname(filePath);
  const tmp = path.join(dir, '.' + path.basename(filePath) + '.tmp-' + process.pid + '-'
    + (atomicWriteSeq += 1) + '-' + Date.now().toString(36));
  let fd = null;
  try {
    fd = fsSync.openSync(tmp, 'wx', 0o600);
    fsSync.writeFileSync(fd, JSON.stringify(obj), 'utf8');
    fsSync.fsyncSync(fd);
    fsSync.closeSync(fd);
    fd = null;
    fsSync.renameSync(tmp, filePath);
  } catch (e) {
    if (fd !== null) { try { fsSync.closeSync(fd); } catch {} }
    try { fsSync.unlinkSync(tmp); } catch {}
    throw e;
  }
}

function loadVaultStateFromDisk() {
  try {
    if (fsSync.existsSync(vaultStorePath)) {
      vaultState = JSON.parse(fsSync.readFileSync(vaultStorePath, 'utf8'));
    }
  } catch (e) { console.error('读取保险库失败:', e); }
  try {
    if (fsSync.existsSync(cleanAuditPath)) {
      cleanAuditLog = JSON.parse(fsSync.readFileSync(cleanAuditPath, 'utf8'));
      if (!Array.isArray(cleanAuditLog)) cleanAuditLog = [];
    }
  } catch (e) { console.error('读取清理审计失败:', e); }
}

function persistVaultState() {
  if (!vaultState) return;
  try { atomicWriteJSON(vaultStorePath, vaultState); } catch (e) { console.error('写入保险库失败:', e); }
}

function persistCleanAudit() {
  try { atomicWriteJSON(cleanAuditPath, cleanAuditLog); } catch (e) { console.error('写入清理审计失败:', e); }
}

function persistVaultKey(keyBuf) {
  if (!safeStorage.isEncryptionAvailable()) {
    recordSecurityEvent('vault-key', 'critical',
      '系统加密不可用，拒绝以明文形式落盘保险库主密钥', 'vault');
    return false;
  }
  try {
    const wrapped = safeStorage.encryptString(keyBuf.toString('hex'));
    atomicWriteJSON(vaultKeyPath, { v: 1, s: 'safe', wrapped: wrapped.toString('base64') });
    return true;
  } catch (e) { console.error('写入保险库密钥失败:', e); return false; }
}

// initVaultOnStartup：启动时尝试用 safeStorage 包层自动解锁；无 keychain 时
// 保留锁定态（vault:status 会报告 locked，由 UI 引导用户输主密码）。


// vaultStatusSnapshot 给 UI 的只读快照；绝不外泄条目密文 / 主密钥。


// createNewVault(masterPassword)：全新创建（或强制重建）。主密钥优先用
// safeStorage 随机密钥；自设密码模式用 PBKDF2 慢化。返回结果不包含密钥。


// unlockVault(masterPassword)：用自设主密码解锁（safeStorage 模式由启动自动解锁）。


// executeCleanPlan：按已确认的计划执行清理。返回摘要；失败项记入审计。
// 安全设计：不信任渲染进程传来的 targets 白名单（防 UI 被篡改后越权清理），
// 而是按计划条件（mode/host/since/storageTypes）在 main 侧重新枚举 + 纯内核
// 过滤生成权威目标集，再与计划摘要（sites/targetCount）核对一致才执行。


// enumerateSiteStorage：枚举默认会话全部 origin 的存储占用（粗略字节）。
// cookies 无 API 可枚举 origin 级，用 session.cookies 逐个列举（受限）。


// maybeFallbackAfterUpgradeFailure 在“HTTPS-Only 升级后加载失败”时，判断并执行
// 一次性的、用户知情的 http 回退。返回 true 表示已接手（弹过框 / 已回退），调用方
// 不再显示通用错误页；false 表示不属于可回退场景，交给正常错误页。
function maybeFallbackAfterUpgradeFailure(tab, errorCode, validatedURL) {
  if (!httpsOnlyEnabled) return false;
  if (!httpsOnlyCore.isFallbackableUpgradeError(errorCode)) return false;
  if (typeof validatedURL !== 'string' || !validatedURL.startsWith('https://')) return false;
  const httpUrl = httpsOnlyCore.downgradeHttpsUrlForFallback(validatedURL);
  if (!httpUrl) return false;
  let host = '';
  try {
    host = new URL(validatedURL).hostname.toLowerCase();
  } catch { return false; }
  if (!host || httpsExceptions.has(host)) return false;
  // 只有“该 http 地址确实会被我们升级成当前这个 https 地址”才允许回退，避免把
  // 用户手动输入 / 书签里的 https 地址错误地降级到明文。
  let repro;
  try {
    repro = httpsOnlyCore.upgradeHttpUrl(httpUrl);
  } catch { repro = null; }
  if (!repro || !repro.ok || repro.url !== validatedURL) return false;
  // 私网 / 回环本来就不会被升级，理论上进不来；再守一道。
  if (isPrivateNetworkHost(httpUrl)) return false;
  if (tab.httpsFallbackPrompting) return true; // 已有一个确认框在等，不叠加。
  tab.httpsFallbackPrompting = true;
  let choice = 0;
  try {
    const res = dialog.showMessageBoxSync(mainWindow, {
      type: 'warning',
      buttons: ['返回安全页面', '继续使用 HTTP（本次并记住该站点）'],
      defaultId: 0,
      cancelId: 0,
      title: '该站点不支持 HTTPS',
      message: `无法通过加密连接访问 ${host}`,
      detail: '服务器在 443 端口没有提供可用的 TLS（连接被拒绝 / 协议不匹配）。\n\n'
        + '如果继续，将以明文 HTTP 访问该站点，同网段中的其他人可能看到或篡改你与该站点之间传输的内容。\n'
        + '仅在你确认这是可信站点、且它确实只提供 HTTP 时才继续。',
      noLink: true,
    });
    choice = Number(res) || 0;
  } finally {
    tab.httpsFallbackPrompting = false;
  }
  if (choice !== 1) return true; // 用户选择留在错误页，已接手不再叠加通用错误页。
  httpsExceptions.add(host);
  persistHttpsExceptions();
  recordSecurityEvent('https-only', 'warn',
    `用户确认在不支持 HTTPS 的站点回退到明文 HTTP：${host}`, host);
  try {
    tab.view.webContents.loadURL(httpUrl);
  } catch (e) {
    console.error('HTTPS 回退加载失败:', e);
    return false;
  }
  return true;
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
    cookieLedger.load(ledgerStore.readJSONStore(cookieLedgerStorePath, {}));
  } catch {}
}

function persistCookieLedger() {
  if (cookieLedgerSaveTimer) clearTimeout(cookieLedgerSaveTimer);
  cookieLedgerSaveTimer = setTimeout(() => {
    try {
      ledgerStore.writeJSONStore(cookieLedgerStorePath, cookieLedger.toJSON());
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
    const data = ledgerStore.readJSONStore(pnaLedgerStorePath, {});
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
      ledgerStore.writeJSONStore(pnaLedgerStorePath, { version: 1, rows });
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
    fpLedger.load(ledgerStore.readJSONStore(fpLedgerStorePath, {}));
  } catch {}
}

function persistFpLedger() {
  if (fpLedgerSaveTimer) clearTimeout(fpLedgerSaveTimer);
  fpLedgerSaveTimer = setTimeout(() => {
    try {
      ledgerStore.writeJSONStore(fpLedgerStorePath, fpLedger.toJSON());
    } catch {}
  }, 400);
}

// recordFpHit 按主机+类别登记一条被收敛的指纹/追踪信号。


// applyCookieHardening 就地加固响应头里的 Set-Cookie，返回本次动作列表。
// 任何异常都不阻断浏览：出错时保留原始响应头。


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
    dohLedger.load(ledgerStore.readJSONStore(dohStorePath, {}));
  } catch {}
}

function persistDohLedger() {
  if (dohSaveTimer) clearTimeout(dohSaveTimer);
  dohSaveTimer = setTimeout(() => {
    try {
      ledgerStore.writeJSONStore(dohStorePath, dohLedger.toJSON());
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


// LOCAL_UI_CSP：自有 UI（cosy:// / file://）页面统一的严 CSP，defaultSession 与
// 隔离 / 访客会话共用，避免两套手写策略漂移。
//  object-src 'none'      ：彻底禁掉插件 / 嵌入对象（Flash 残留、恶意 <embed>）；
//  base-uri 'self'       ：页面不允许被 <base> 改掉所有相对 URL 的基准；
//  form-action 'self'    ：表单不允许提交到外部源（防内部页被注入后外发数据）；
//  frame-ancestors 'none'：任何页面都不许 iframe 我们的内部 UI（等价 X-Frame-Options DENY）；
//  worker-src 'self'     ：worker 只能从自身加载，挡 data: blob: worker 注入。
const LOCAL_UI_CSP =
  "default-src 'self'; " +
  "script-src 'self' 'unsafe-inline'; " +
  "style-src 'self' 'unsafe-inline'; " +
  "img-src 'self' data: https:; " +
  "connect-src 'self' https:; " +
  "object-src 'none'; " +
  "base-uri 'self'; " +
  "form-action 'self'; " +
  "frame-ancestors 'none'; " +
  "worker-src 'self';";

// hardenResponseHeaders：把一份“服务器原始响应头”就地加固后返回。defaultSession 与
// 每个非默认会话（访客 / 隔离 partition）共用同一套变换，杜绝只加固主会话的纵深缺口。
// options.grade=true 时对远端顶层文档记一条安全头评级（仅 defaultSession 需要记账）。
const { hardenResponseHeaders } = require('./responseharden').create({
  LOCAL_UI_CSP, acacGuard, acceptChGuard, acceptChLifetimeGuard, acceptCharsetGuard, acceptEncodingGuard,
  acceptLanguageGuard, acceptPatchGuard, acceptRangesGuard, ageClockGuard, allowHeaderGuard, allowHeadersGuard,
  allowMethodsGuard, altSvcGuard, applyCookieHardening, attributionGuard, authChallengeGuard, authenticationInfoGuard,
  baggageGuard, cacheAuthGuard, cacheStatusGuard, cacheVaryGuard, chMobileGuard, chPlatformGuard,
  charsetGuard, clearSiteDataGuard, coepGuard, connectionGuard, contentBaseGuard, contentDigestGuard,
  contentDispositionGuard, contentEncodingGuard, contentLanguageGuard, contentLocationGuard, contentMd5Guard, contentRangeGuard,
  contentTypeGuard, cookieJarGuard, coopGuard, corpGuard, corsGuard, credentialRequestGuard,
  criticalChGuard, crossDomainPolicyGuard, crossOriginPolicyGuard, cspReportOnlyGuard, digestGuard, dnsPrefetchGuard,
  dntGuard, documentPolicyGuard, downloadNameGuard, earlyHintGuard, etagGuard, expectCtGuard,
  expiresGuard, exposeHeadersGuard, featurePolicyGuard, fileSystemAccessGuard, forwardedGuard, fpGuard,
  frameOptionsGuard, headerBudgetGuard, headerInjectionGuard, hopByHopGuard, hstsGuard, ifMatchGuard,
  ifModifiedSinceGuard, ifNoneMatchGuard, ifRangeGuard, ifUnmodifiedSinceGuard, keepAliveGuard, lastModifiedGuard,
  legacyPinGuard, linkPreloadGuard, linkResponseGuard, maxAgeGuard, mimeExecGuard, nelReportGuard,
  noSniffGuard, noteGuardDenied, noteGuardResult, originAgentClusterGuard, originTrialGuard, permissionsPolicyGuard,
  pragmaCacheGuard, priorityGuard, protocol, proxyAuthGuard, proxyAuthenticateGuard, proxyStatusGuard,
  publicKeyPinsGuard, rangeGuard, recordFpHit, recordHeaderGrade, recordSecurityEvent: (...args) => recordSecurityEvent(...args), referrerPolicyGuard,
  refreshGuard, reportingEndpointsGuard, reportingGuard, retryAfterGuard, saveDataGuard, secFetchDestGuard,
  secFetchModeGuard, secFetchSiteGuard, secFetchUserGuard, secGpcGuard, secWebSocketGuard, securityBoundaryHub,
  securityHeadersGuard, serverBannerGuard, serverTimingGuard, serviceWorkerAllowedGuard, setCookie2Guard, setCookiePrefixGuard,
  sourceMapGuard, speculationRulesGuard, surrogateControlGuard, taoOriginGuard, teGuard, timingAllowOriginGuard,
  traceStateGuard, traceparentGuard, trailerFieldGuard, transferEncodingGuard, trueClientIpGuard, upgradeGuard,
  viaGuard, wantDigestGuard, warningHeaderGuard, wwwAuthenticateGuard, xContentTypeOptionsGuard, xDownloadOptionsGuard,
  xMethodOverrideGuard, xOriginalUrlGuard, xRealIpGuard, xRequestIdGuard, xRequestedWithGuard, xRobotsGuard,
  xWebKitCspGuard, xfwdForGuard, xfwdHostGuard, xfwdPortGuard, xfwdProtoGuard, xpcdpGuard,
  xssProtectionGuard, xuaCompatibleGuard,
  readAllowPictureInPicture: () => allowPictureInPicture, readStripAcceptCh: () => stripAcceptCh,
});

// applyOutboundHeaderHardening：在任意会话上挂统一的“出向请求头”加固。
// 无论默认会话还是 fromPartition 的隔离 / 访客会话，都必须：
//   - 注入 DNT / Sec-GPC / Upgrade-Insecure-Requests；
//   - 收敛 Referer；
//   - 剥离高熵 Client Hints、Topics / 归因等广告指纹头（fpGuard）。
// 历史上隔离会话只补了前两项，漏掉 fpGuard 清洗，导致“本该更隐私的隔离分区”
// 反而继续外发高熵指纹头。options.recordFp 仅控制是否把命中聚合进指纹台账
// （分区会话不重复计数），但清洗动作在所有会话上恒为开启。


// applyWebRequestFiltering：在任意会话上挂统一的 onBeforeRequest 过滤。
// Electron 的 webRequest 处理器按会话注册、不会从 defaultSession 继承，因此
// fromPartition 的隔离 / 访客会话必须各自挂一份，否则 tracker / ping / 私网访问 /
// 混合内容 / 追踪参数 / HTTPS-only 在这些“本该更安全”的分区里全部失效。
// options.logRequests 仅控制是否把请求量计入默认会话的连接统计（分区不重复计数）；
// 阻断 / 升级 / 安全审计在所有会话上行为一致。
// buildRequestPipelineDeps 组装纯决策内核所需的守卫 / 台账 / 横幅能力。
// 三个开关是可变设置（用户可在设置页切换），用 getter 保证每次判定都读到当前值。


function applyWebRequestFiltering(targetSession, options) {
  // options.logRequests 仅控制是否把请求量计入默认会话的连接统计（分区不重复计数）；
  // 阻断 / 升级 / 安全审计在所有会话上行为一致。
  const logRequests = !!(options && options.logRequests);
  const noteAttempt = logRequests ? recordRequestAttempt : () => {};
  requestPipeline.applyPipeline(targetSession.webRequest, buildRequestPipelineDeps(), noteAttempt);
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

const permissionStore = require('./permissionstore');
const protocolRate = require('./protocolrate');
const {
  CONFIRMABLE_EXTERNAL_SCHEMES,
  getRememberedProtocolDecision,
  rememberProtocolDecision,
  listProtocolDecisions,
  forgetProtocolDecision,
} = permissionStore;

// classifyFrameNavigation 判断一次（主/子框架）导航该如何处理：
//   'in-pane'  ：浏览器内正常加载；
//   'confirm'  ：外部协议但可在确认后交给系统（mailto/tel）；
//   'block'    ：危险 / 不允许的协议，必须取消。


function originOfContents(contents) {
  if (!contents || typeof contents.getURL !== 'function') return '';
  return urlResolve.safeOrigin(contents.getURL(), '');
}

// launchExternalWithPrompt 是所有"页面想唤起外部程序"的唯一出口。
// remembered 决定直接兑现，否则弹原生确认框；remember=true 时按 origin+scheme 记忆。
const protocolRateLimiter = protocolRate.createLimiter();



// handleFrameNavigationAttempt 供 will-navigate / will-frame-navigate /
// will-redirect 统一调用，返回 true 表示"已经接管，原导航必须 preventDefault"。


const securityCenter = require('./securitycenter');
securityCenter.bindRendererNotifier(sendToRenderer);
const recordSecurityEvent = securityCenter.recordSecurityEvent;
const listSecurityEvents = securityCenter.listSecurityEvents;
const clearSecurityEvents = securityCenter.clearSecurityEvents;
const recordCspViolationFromRenderer = securityCenter.recordCspViolationFromRenderer;
const listCspReports = securityCenter.listCspReports;
const clearCspReports = securityCenter.clearCspReports;
const removeCspReport = securityCenter.removeCspReport;
const getCspReportStats = securityCenter.getCspReportStats;

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



function persistHeaderGrades() {
  if (headerGradeSaveTimer) clearTimeout(headerGradeSaveTimer);
  headerGradeSaveTimer = setTimeout(() => {
    try {
      ledgerStore.writeJSONStore(headerGradeStorePath, { version: 1, hosts: headerGrades });
    } catch {}
  }, 400);
}

// recordHeaderGrade 对一次顶层文档响应评级并按 host 聚合。纯计算，不抛错。


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
    const data = ledgerStore.readJSONStore(requestLogStorePath, {});
    if (data && Array.isArray(data.entries)) {
      requestLogStore = requestLog.hydrate(data.entries, MAX_REQUEST_LOG_HOSTS);
    }
  } catch {}
}

function persistRequestLog() {
  if (requestLogSaveTimer) clearTimeout(requestLogSaveTimer);
  requestLogSaveTimer = setTimeout(() => {
    try {
      const entries = requestLog.toList(requestLogStore);
      ledgerStore.writeJSONStore(requestLogStorePath, { version: 1, savedAt: Date.now(), entries });
    } catch {}
  }, 5000);
}

// recordRequestAttempt 由 onBeforeRequest 调用；任何异常都不影响浏览。


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



function persistBrandSpoofs() {
  if (brandSpoofSaveTimer) clearTimeout(brandSpoofSaveTimer);
  brandSpoofSaveTimer = setTimeout(() => {
    try {
      ledgerStore.writeJSONStore(brandSpoofStorePath, { version: 1, savedAt: Date.now(), hosts: brandSpoofs });
    } catch {}
  }, 5000);
}

// recordBrandSpoof 由 onBeforeRequest 顶层导航调用；入参来自纯模块，仍重新白名单化，
// 防止脏数据写盘。任何异常都不影响浏览。


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





// certExceptionAllowed 判断当前失败事件是否命中已批准的“主机+指纹”例外。












// makeCertChallenge 为一次拦截生成一次性 nonce，供渲染进程“仍要前往”回传。


// consumeCertChallenge 取出并销毁一次挑战，返回 null 表示过期/伪造。


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



function loadClientCertChoices() {
  if (clientCertStoreLoaded) return;
  clientCertStoreLoaded = true;
  try {
    // 有界文本读：clientCert 台账缺失时 readBoundedText 返回 {missing}，不解析、不加载；
    // 被塞成巨值或损坏则交由外层 try/catch / loadJSON 容错，绝不整读撑爆主进程。
    const picked = ledgerStore.readBoundedText(clientCertStorePath);
    if (!picked.missing) clientCertStore.loadJSON(picked.text);
  } catch {}
}

function persistClientCertChoices() {
  if (clientCertSaveTimer) clearTimeout(clientCertSaveTimer);
  clientCertSaveTimer = setTimeout(() => {
    try {
      ledgerStore.writeJSONStore(clientCertStorePath, clientCertStore.toJSON());
    } catch {}
  }, 300);
}

// failAuthCallback 在“不弹框 / 超时 / 窗口关闭”等路径上安全地兑现一个空凭据，
// 让请求以未认证失败，而不是卡住或回退到系统默认行为。


function rejectAuthChallenge(nonce) {
  const c = pendingAuthChallenges.get(nonce);
  if (!c) return false;
  clearTimeout(c.timer);
  pendingAuthChallenges.delete(nonce);
  failAuthCallback(c.callback);
  return true;
}



// sanitizeCertPickList 只把证书的非敏感摘要给渲染层，绝不传证书对象本体。




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


const downloadHashes = require('./downloadhashes');
const securityledger = require('./securityledger');
const downloadsbridge = require('./downloadsbridge');
const vaultmain = require('./vaultmain');
const readerbridge = require('./readerbridge');
const extensionstoremain = require('./extensionstoremain');
const externalcall = require('./externalcall');
const certledger = require('./certledger');
const tabactions = require('./tabactions');
const headerpipeline = require('./headerpipeline');
const searchmain = require('./searchmain');
const netauthmain = require('./netauthmain');
const { setupNetworkAuth } = netauthmain;
netauthmain.bindDeps({
  get app() { return app; },
  get authEventOrigin() { return authEventOrigin; },
  get authLimiter() { return authLimiter; },
  get authStats() { return authStats; },
  get clientCertStore() { return clientCertStore; },
  get failAuthCallback() { return failAuthCallback; },
  get loadClientCertChoices() { return loadClientCertChoices; },
  get netAuthGuard() { return netAuthGuard; },
  get netAuthNonce() { return netAuthNonce; },
  get pendingAuthChallenges() { return pendingAuthChallenges; },
  get recordSecurityEvent() { return recordSecurityEvent; },
  get rejectAuthChallenge() { return rejectAuthChallenge; },
  get sanitizeCertPickList() { return sanitizeCertPickList; },
  get sendToRenderer() { return sendToRenderer; },
  get session() { return session; },
  get urlResolve() { return urlResolve; },
  get webContents() { return webContents; }
,
  get netAuthGuard() { return netAuthGuard; },
  get pendingAuthChallenges() { return pendingAuthChallenges; },
  get webContents() { return webContents; }});

const { fetchSearchSuggestions, generateUserAgent } = searchmain;
searchmain.bindDeps({
  get SUGGEST_MAX_ITEMS() { return SUGGEST_MAX_ITEMS; },
  get SUGGEST_TIMEOUT_MS() { return SUGGEST_TIMEOUT_MS; },
  get net() { return net; },
  get os() { return os; },
  get searchProvider() { return searchProvider; },
  get searchProviderId() { return searchProviderId; },
  get suggestionGuard() { return suggestionGuard; }
});

const { applyOutboundHeaderHardening, applySecureDns, applyCookieHardening, buildRequestPipelineDeps, setupSecurityHeaders, trimReferrerHeader } = headerpipeline;
headerpipeline.bindDeps({
  get analyzeHostForSpoof() { return analyzeHostForSpoof; },
  get applyWebRequestFiltering() { return applyWebRequestFiltering; },
  get blockAdSignals() { return blockAdSignals; },
  get blockHyperlinkPing() { return blockHyperlinkPing; },
  get blockLocalNetworkAccess() { return blockLocalNetworkAccess; },
  get blockThirdPartyCookies() { return blockThirdPartyCookies; },
  get brandGuard() { return brandGuard; },
  get cookieGuard() { return cookieGuard; },
  get cookieLedger() { return cookieLedger; },
  get dohActive() { return dohActive; },
  set dohActive(v) { dohActive = v; },
  get dohCustomUrl() { return dohCustomUrl; },
  get dohGuard() { return dohGuard; },
  get dohLedger() { return dohLedger; },
  get dohMode() { return dohMode; },
  get dohProvider() { return dohProvider; },
  get fpGuard() { return fpGuard; },
  get hardenCookies() { return hardenCookies; },
  get hardenResponseHeaders() { return hardenResponseHeaders; },
  get httpsOnlyEnabled() { return httpsOnlyEnabled; },
  get isHttpExceptionHost() { return isHttpExceptionHost; },
  get isPrivateNetworkHost() { return isPrivateNetworkHost; },
  get isTrackerRequest() { return isTrackerRequest; },
  get loadCookieLedger() { return loadCookieLedger; },
  get loadDohLedger() { return loadDohLedger; },
  get mixedGuard() { return mixedGuard; },
  get originOf() { return originOf; },
  get persistCookieLedger() { return persistCookieLedger; },
  get persistDohLedger() { return persistDohLedger; },
  get phishUrl() { return phishUrl; },
  get pluginResourceGuard() { return pluginResourceGuard; },
  get pnaGuard() { return pnaGuard; },
  get recordBlockedTracker() { return recordBlockedTracker; },
  get recordBrandSpoof() { return recordBrandSpoof; },
  get recordFpHit() { return recordFpHit; },
  get recordPnaBlock() { return recordPnaBlock; },
  get recordSecurityEvent() { return recordSecurityEvent; },
  get reduceClientHints() { return reduceClientHints; },
  get requestMethodGuard() { return requestMethodGuard; },
  get resolveEffectiveUa() { return resolveEffectiveUa; },
  get sendToRenderer() { return sendToRenderer; },
  get session() { return session; },
  get stripAcceptCh() { return stripAcceptCh; },
  get stripTrackingFromUrl() { return stripTrackingFromUrl; },
  get uaLastOverrideAt() { return uaLastOverrideAt; },
  set uaLastOverrideAt(v) { uaLastOverrideAt = v; },
  get uaOverrideCount() { return uaOverrideCount; },
  set uaOverrideCount(v) { uaOverrideCount = v; },
  get uaPolicyCore() { return uaPolicyCore; },
  get uaPolicyState() { return uaPolicyState; },
  get webrtcMode() { return webrtcMode; }
,
  get analyzeHostForSpoof() { return analyzeHostForSpoof; },
  get blockAdSignals() { return blockAdSignals; },
  get blockHyperlinkPing() { return blockHyperlinkPing; },
  get blockLocalNetworkAccess() { return blockLocalNetworkAccess; },
  get httpsOnlyEnabled() { return httpsOnlyEnabled; },
  get isPrivateNetworkHost() { return isPrivateNetworkHost; },
  get isTrackerRequest() { return isTrackerRequest; },
  get reduceClientHints() { return reduceClientHints; },
  get sendToRenderer() { return sendToRenderer; },
  get stripAcceptCh() { return stripAcceptCh; },
  get stripTrackingFromUrl() { return stripTrackingFromUrl; },
  get webrtcMode() { return webrtcMode; }});

const { tabOverviewItem, closeTab, switchToTab, createNewTab, adjustCurrentZoom, updateBrowserViewBounds, clampZoomFactor, applySavedZoom, resetZoom, zoomIn, zoomOut, persistZoomFactors, loadZoomFactors } = tabactions;
tabactions.bindDeps({
  get COLLAPSED_TAB_BAR_WIDTH() { return COLLAPSED_TAB_BAR_WIDTH; },
  get DEFAULT_TAB_BAR_HEIGHT_HORIZONTAL() { return DEFAULT_TAB_BAR_HEIGHT_HORIZONTAL; },
  get DEFAULT_TAB_BAR_WIDTH_VERTICAL() { return DEFAULT_TAB_BAR_WIDTH_VERTICAL; },
  get MAX_REMEMBERED_ORIGINS() { return MAX_REMEMBERED_ORIGINS; },
  get MAX_ZOOM_FACTOR() { return MAX_ZOOM_FACTOR; },
  get MIN_ZOOM_FACTOR() { return MIN_ZOOM_FACTOR; },
  get addToRecentlyClosed() { return addToRecentlyClosed; },
  get applyFind() { return applyFind; },
  get currentTabIndex() { return currentTabIndex; },
  set currentTabIndex(v) { currentTabIndex = v; },
  get findState() { return findState; },
  get getCurrentTabWebContents() { return getCurrentTabWebContents; },
  get getDefaultTabUrl() { return getDefaultTabUrl; },
  get getTabLayout() { return getTabLayout; },
  get getUrlProtocol() { return getUrlProtocol; },
  get isSafeUrl() { return isSafeUrl; },
  get isTabBarCollapsed() { return isTabBarCollapsed; },
  get ledgerStore() { return ledgerStore; },
  get loadTabContent() { return loadTabContent; },
  get mainWindow() { return mainWindow; },
  get originOfUrl() { return originOfUrl; },
  get path() { return path; },
  get persistPins() { return persistPins; },
  get persistTabGroups() { return persistTabGroups; },
  get pinModel() { return pinModel; },
  get popupOpenTimes() { return popupOpenTimes; },
  get pushNavState() { return pushNavState; },
  get rebuildCrashedTab() { return rebuildCrashedTab; },
  get reloadDiscardedTab() { return reloadDiscardedTab; },
  get sendToRenderer() { return sendToRenderer; },
  get tabGroupModel() { return tabGroupModel; },
  get tabs() { return tabs; },
  get zoomFactorsByOrigin() { return zoomFactorsByOrigin; },
  get zoomSaveTimer() { return zoomSaveTimer; },
  set zoomSaveTimer(v) { zoomSaveTimer = v; },
  get zoomStorePath() { return zoomStorePath; }
});

const { loadCertExceptions, persistCertExceptions, addCertException, removeCertException, clearCertExceptions, certExceptionAllowed, getCertExceptionStats, listCertExceptionEntries, sanitizeCertPickList, makeCertChallenge, consumeCertChallenge, failAuthCallback, authEventOrigin, netAuthNonce } = certledger;
certledger.bindDeps({
  get CERT_CHALLENGE_TTL() { return CERT_CHALLENGE_TTL; },
  get MAX_CERT_EXCEPTIONS() { return MAX_CERT_EXCEPTIONS; },
  get MAX_CLIENT_CERT_PICK_CHARS() { return MAX_CLIENT_CERT_PICK_CHARS; },
  get certChallenges() { return certChallenges; },
  get certExceptionSaveTimer() { return certExceptionSaveTimer; },
  set certExceptionSaveTimer(v) { certExceptionSaveTimer = v; },
  get certExceptionStorePath() { return certExceptionStorePath; },
  get certExceptions() { return certExceptions; },
  set certExceptions(v) { certExceptions = v; },
  get certExceptionsLoaded() { return certExceptionsLoaded; },
  set certExceptionsLoaded(v) { certExceptionsLoaded = v; },
  get certGuard() { return certGuard; },
  get fsSync() { return fsSync; },
  get ledgerStore() { return ledgerStore; },
  get netAuthCrypto() { return netAuthCrypto; },
  get netAuthGuard() { return netAuthGuard; },
  get urlResolve() { return urlResolve; }
});

const { launchExternalWithPrompt, classifyFrameNavigation, handleFrameNavigationAttempt, confirmAndOpenExternal } = externalcall;
externalcall.bindDeps({
  get CONFIRMABLE_EXTERNAL_SCHEMES() { return CONFIRMABLE_EXTERNAL_SCHEMES; },
  get createNewTab() { return createNewTab; },
  get dialog() { return dialog; },
  get externalBudget() { return externalBudget; },
  get getRememberedProtocolDecision() { return getRememberedProtocolDecision; },
  get isRememberableOrigin() { return isRememberableOrigin; },
  get isSafeUrl() { return isSafeUrl; },
  get originOfContents() { return originOfContents; },
  get protocolRate() { return protocolRate; },
  get protocolRateLimiter() { return protocolRateLimiter; },
  get recordSecurityEvent() { return recordSecurityEvent; },
  get rememberProtocolDecision() { return rememberProtocolDecision; },
  get sendToRenderer() { return sendToRenderer; },
  get shell() { return shell; },
  get shellGuard() { return shellGuard; }
,
  get mainWindow() { return mainWindow; }});

const { copyExtensionToStorage, validateExtensionFolder } = extensionstoremain;
extensionstoremain.bindDeps({
  get extensionStore() { return extensionStore; },
  get extensionsPath() { return extensionsPath; },
  get fs() { return fs; },
  get fsSync() { return fsSync; },
  get path() { return path; },
  get recordSecurityEvent() { return recordSecurityEvent; }
});

const { sanitizeReaderNodes, enterReaderMode, sanitizeReaderArticle, clampReaderInt, openReaderTab } = readerbridge;
readerbridge.bindDeps({
  get READER_PAGE_URL() { return READER_PAGE_URL; },
  get currentTabIndex() { return currentTabIndex; },
  get readerArticle() { return readerArticle; },
  set readerArticle(v) { readerArticle = v; },
  get readerCore() { return readerCore; },
  get tabs() { return tabs; }
,
  get createNewTab() { return createNewTab; },
  get getUrlProtocol() { return getUrlProtocol; },
  get switchToTab() { return switchToTab; }});

const { executeCleanPlan, initVaultOnStartup, createNewVault, unlockVault, vaultStatusSnapshot, enumerateSiteStorage } = vaultmain;
vaultmain.bindDeps({
  get cleanAuditLog() { return cleanAuditLog; },
  get cleanerCore() { return cleanerCore; },
  get crypto() { return crypto; },
  get fsSync() { return fsSync; },
  get recordSecurityEvent() { return recordSecurityEvent; },
  get vaultCore() { return vaultCore; },
  get vaultHandle() { return vaultHandle; },
  set vaultHandle(v) { vaultHandle = v; },
  get vaultKeyPath() { return vaultKeyPath; },
  get vaultState() { return vaultState; },
  set vaultState(v) { vaultState = v; },
  get vaultUsePasswordMode() { return vaultUsePasswordMode; },
  set vaultUsePasswordMode(v) { vaultUsePasswordMode = v; }
,
  get loadVaultStateFromDisk() { return loadVaultStateFromDisk; },
  get persistCleanAudit() { return persistCleanAudit; },
  get persistVaultKey() { return persistVaultKey; },
  get persistVaultState() { return persistVaultState; },
  get safeStorage() { return safeStorage; },
  get session() { return session; }});

const { performDownloadOpen, confirmDownloadDecision, getDownloadJournal, loadDownloadRisks, loadDownloads, journalDownloadState, downloadNotifyDeps } = downloadsbridge;
downloadsbridge.bindDeps({
  get MAX_DOWNLOAD_RISK_RECORDS() { return MAX_DOWNLOAD_RISK_RECORDS; },
  get MAX_PERSISTED_DOWNLOADS() { return MAX_PERSISTED_DOWNLOADS; },
  get dloadGuard() { return dloadGuard; },
  get dloadOpen() { return dloadOpen; },
  get downloadJournal() { return downloadJournal; },
  set downloadJournal(v) { downloadJournal = v; },
  get downloadJournalModule() { return downloadJournalModule; },
  get downloadOriginByPath() { return downloadOriginByPath; },
  get downloadRiskLoaded() { return downloadRiskLoaded; },
  set downloadRiskLoaded(v) { downloadRiskLoaded = v; },
  get downloadRiskRecords() { return downloadRiskRecords; },
  get downloadRiskStorePath() { return downloadRiskStorePath; },
  get downloadShelf() { return downloadShelf; },
  get downloads() { return downloads; },
  get fsSync() { return fsSync; },
  get ledgerStore() { return ledgerStore; },
  get path() { return path; },
  get recordSecurityEvent() { return recordSecurityEvent; },
  get shellGuard() { return shellGuard; },
  get urlResolve() { return urlResolve; }
,
  get app() { return app; },
  get dialog() { return dialog; },
  get downloadJournalFileProbe() { return downloadJournalFileProbe; },
  get downloadsStorePath() { return downloadsStorePath; },
  get isInSafeDirs() { return isInSafeDirs; },
  get sendToRenderer() { return sendToRenderer; },
  get shell() { return shell; },
  get mainWindow() { return mainWindow; }});

const { recordBrandSpoof, recordRequestAttempt, recordHeaderGrade, recordFpHit, loadBrandSpoofs, loadHeaderGrades } = securityledger;
securityledger.bindDeps({
  get BRAND_SPOOF_REASONS() { return BRAND_SPOOF_REASONS; },
  get MAX_BRAND_SPOOF_HOSTS() { return MAX_BRAND_SPOOF_HOSTS; },
  get MAX_HEADER_GRADE_HOSTS() { return MAX_HEADER_GRADE_HOSTS; },
  get brandSpoofNotifyTimer() { return brandSpoofNotifyTimer; },
  set brandSpoofNotifyTimer(v) { brandSpoofNotifyTimer = v; },
  get brandSpoofStorePath() { return brandSpoofStorePath; },
  get brandSpoofs() { return brandSpoofs; },
  set brandSpoofs(v) { brandSpoofs = v; },
  get brandSpoofsLoaded() { return brandSpoofsLoaded; },
  set brandSpoofsLoaded(v) { brandSpoofsLoaded = v; },
  get fpLedger() { return fpLedger; },
  get headerGrade() { return headerGrade; },
  get headerGradeStorePath() { return headerGradeStorePath; },
  get headerGrades() { return headerGrades; },
  get headerGradesLoaded() { return headerGradesLoaded; },
  set headerGradesLoaded(v) { headerGradesLoaded = v; },
  get ledgerStore() { return ledgerStore; },
  get requestLog() { return requestLog; },
  get requestLogNotifyTimer() { return requestLogNotifyTimer; },
  set requestLogNotifyTimer(v) { requestLogNotifyTimer = v; },
  get requestLogStore() { return requestLogStore; }
,
  get getBrandSpoofStats() { return getBrandSpoofStats; },
  get loadFpLedger() { return loadFpLedger; },
  get loadRequestLog() { return loadRequestLog; },
  get persistBrandSpoofs() { return persistBrandSpoofs; },
  get persistFpLedger() { return persistFpLedger; },
  get persistHeaderGrades() { return persistHeaderGrades; },
  get persistRequestLog() { return persistRequestLog; },
  get sendToRenderer() { return sendToRenderer; }});

downloadHashes.bindRendererNotifier(sendToRenderer);
downloadHashes.bindWindowHost(() => mainWindow);
const {
  queueDownloadHashing,
  listDownloadHashes,
  removeDownloadHashRecord,
  clearDownloadHashes,
  verifyDownloadHashById,
  hashLocalFileViaDialog,
} = downloadHashes;


permissionStore.bindSecurityRecorder(recordSecurityEvent);
const {
  isRememberableOrigin,
  REMEMBERED_PAGE_PERMISSIONS,
  getRememberedPermission,
  rememberPermission,
  forgetPermission,
  listPermissionDecisions,
  clearPermissionDecisionsForOrigin,
  auditPermissionDecisions,
  prunePermissionDecisions,
} = permissionStore;

const { setupPermissionHandlers } = require('./permissionhandlers').create({
  ALLOWED_PERMISSIONS, clearBrandSpoofs, clearCspReports, clearDownloadRisks, clearHeaderGrades, clearRequestLog,
  clearSecurityEvents, clipboard, clipboardFrame, clipboardReadOrigin, confirmAndOpenExternal, createDenyLedger,
  dialog, displayGuard, fullscreenFrame, getBrandSpoofStats, getCspReportStats, getCurrentTabWebContents,
  getHeaderGradeStats, getRequestLogStats, ipcMain, isMainSender, listBrandSpoofEntries, listCspReports,
  listDownloadRisks, listHeaderGrades, listRequestLogEntries, listSecurityEvents, notificationFrame, pointerLockFrame,
  popupOpenerFrame, recordCspViolationFromRenderer, recordSecurityEvent, removeCspReport, sendToRenderer, session,
  urlClean, urlResolve, webContents,
  readCurrentTabIndex: () => currentTabIndex, readMainWindow: () => mainWindow, readTabs: () => tabs,
});

// setupGlobalWebContentsHooks 给所有 webContents 兜底：
// - 任何没被我们显式设置过 windowOpenHandler 的 webContents（扩展后台页、插件 popup、
//   未来新增的窗口等）默认 deny 弹窗，只放行我们白名单里的协议；
// - 拦 will-navigate，不允许跳到 javascript:/data:/vbscript: 这些危险 scheme；
// - beforeunload 弹确认，避免用户关标签时把没保存的表单/SQL 编辑器内容直接丢了。
const { setupGlobalWebContentsHooks } = require('./webcontentshooks').create({
  BrowserWindow, RAW_IPC_SEND_ALLOWED, RAW_IPC_SYNC_ALLOWED, WebContentsView, app, captureGuard,
  captureStates, childWindowGuard, childWindowStates, consoleGuard, consoleStates, crashGuard,
  crashReloadCounts, crashStates, createNewTab, cursorGuard, cursorStates, devicerGuard,
  devtoolsGuard, devtoolsSwitchGuard, devtoolsSwitchStates, dialog, dialogGuard, dialogStates,
  displayGuard, entryGuard, entryStates, frameGuard, frameStates, fullscreenGuard,
  getContentsState, getCurrentTabWebContents, goneGuard, handleFrameNavigationAttempt, hoverGuard, hoverStates,
  inpageGuard, inpageStates, ipcChannelGuard, ipcChannelStates, isSafeUrl, isolatedChildContents,
  launchExternalWithPrompt, mediaGuard, mediaStates, navGuard, originOfContents, popupGuard,
  preloadGuard, printGuard, recordSecurityEvent, redirectChainStates, redirectGuard, remoteGuard,
  remoteStates, revokeGuard, revokeStates, schemeOrigin, securityBoundaryHub, sendToRenderer,
  session, storageAccessGuard, storageAccessStates, themeGuard, themeStates, titleStates,
  unloadGuard, unloadStates, webContents, webviewHarden, zoomGuard,
  readCrashRecoveryEnabled: () => crashRecoveryEnabled, readMainWindow: () => mainWindow, readTabs: () => tabs,
});

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
const setupExtraSessionHardeningCtx = {
  get app() { return app; },
  get applyOutboundHeaderHardening() { return applyOutboundHeaderHardening; },
  get applyWebRequestFiltering() { return applyWebRequestFiltering; },
  get attachDownloadManager() { return attachDownloadManager; },
  get downloads() { return downloads; },
  get recordSecurityEvent() { return recordSecurityEvent; },
  get session() { return session; },
  get sessionGuardState() { return sessionGuardState; },
  get setupSecurityHeaders() { return setupSecurityHeaders; },
  get urlResolve() { return urlResolve; },
  get webContents() { return webContents; },
};
function setupExtraSessionHardening() {
  return require('./sessionhardening').setupExtraSessionHardening(setupExtraSessionHardeningCtx, );
}

function getTabLayout() {
  // 复用统一的有界设置读取（坏 / 超大文件回落 {}），不再各自 existsSync+parse。
  const settings = readStoredSettings();
  return settings.tabLayout || 'horizontal';
}

function getDefaultTabUrl() {
  const settings = readStoredSettings();
  if (settings.defaultTab === 'bing') return 'https://www.bing.com';
  if (settings.defaultTab === 'custom' && settings.customUrl && isSafeUrl(settings.customUrl))
    return settings.customUrl;
  return 'cosy://newtab';
}

const createWindowCtx = {
  get DEFAULT_WINDOW_HEIGHT() { return DEFAULT_WINDOW_HEIGHT; },
  get DEFAULT_WINDOW_WIDTH() { return DEFAULT_WINDOW_WIDTH; },
  get MIN_WINDOW_HEIGHT() { return MIN_WINDOW_HEIGHT; },
  get MIN_WINDOW_WIDTH() { return MIN_WINDOW_WIDTH; },
  get clearOnExit() { return clearOnExit; },
  get clearSession() { return clearSession; },
  get clearStoredPins() { return clearStoredPins; },
  get clearStoredTabGroups() { return clearStoredTabGroups; },
  get confirmCloseMultiple() { return confirmCloseMultiple; },
  get createNewTab() { return createNewTab; },
  get downloads() { return downloads; },
  get ensurePinnedTabsOpened() { return ensurePinnedTabsOpened; },
  setFileToOpen: (v) => { fileToOpen = v; },
  get fileToOpen() { return fileToOpen; },
  get getDefaultTabUrl() { return getDefaultTabUrl; },
  get getTabLayout() { return getTabLayout; },
  get isSafeUrl() { return isSafeUrl; },
  get loadSession() { return loadSession; },
  get purgeBrowsingDataOnExit() { return purgeBrowsingDataOnExit; },
  get recordSecurityEvent() { return recordSecurityEvent; },
  get registerShortcuts() { return registerShortcuts; },
  get rehydrateTabGroups() { return rehydrateTabGroups; },
  get savePinsNow() { return savePinsNow; },
  get saveSession() { return saveSession; },
  get saveTabGroupsNow() { return saveTabGroupsNow; },
  get tabs() { return tabs; },
  get updateBrowserViewBounds() { return updateBrowserViewBounds; },
};
function createWindow() {
  return require('./windowfactory').createWindow(createWindowCtx, );
}

const registerShortcutsCtx = {
  get applyFind() { return applyFind; },
  get bookmarks() { return bookmarks; },
  get closeTab() { return closeTab; },
  get createNewTab() { return createNewTab; },
  get createWindow() { return createWindow; },
  get currentTabIndex() { return currentTabIndex; },
  get discardAllBackgroundTabs() { return discardAllBackgroundTabs; },
  get enterReaderMode() { return enterReaderMode; },
  get getCurrentTabWebContents() { return getCurrentTabWebContents; },
  get getLastClosedTab() { return getLastClosedTab; },
  get goHome() { return goHome; },
  get history() { return history; },
  get isSafeUrl() { return isSafeUrl; },
  get openTabOverviewTab() { return openTabOverviewTab; },
  get openTaskManagerTab() { return openTaskManagerTab; },
  get resetZoom() { return resetZoom; },
  get saveBookmarks() { return saveBookmarks; },
  get sendToRenderer() { return sendToRenderer; },
  get showOpenFileDialog() { return showOpenFileDialog; },
  get switchToTab() { return switchToTab; },
  get tabs() { return tabs; },
  get toggleDevTools() { return toggleDevTools; },
  get toggleTabPinned() { return toggleTabPinned; },
  get zoomIn() { return zoomIn; },
  get zoomOut() { return zoomOut; },
};
function registerShortcuts() {
  return require('./shortcutrouter').registerShortcuts(registerShortcutsCtx, );
}

function getUrlProtocol(url) {
  // safeProtocol 默认解析失败回 null，与历史实现逐字一致。
  return urlResolve.safeProtocol(url);
}



const TASK_MANAGER_URL = 'cosy://taskmanager';

// openTaskManagerTab 打开（或切到已有的）任务管理器内置页。任务管理器是 cosy: 页，
// 承载在普通标签视图里；已开则复用，避免连按 Shift+Esc 开出一堆相同页。
function openTaskManagerTab() {
  const existing = tabs.findIndex(t => t && t.url === TASK_MANAGER_URL);
  if (existing >= 0) {
    if (existing !== currentTabIndex) switchToTab(existing);
    return tabs[existing];
  }
  return createNewTab(TASK_MANAGER_URL);
}

const TAB_OVERVIEW_URL = 'cosy://taboverview';

// openTabOverviewTab 打开（或切到已有的）标签页概览网格页。与任务管理器同款
// 语义：已开则复用，避免 Ctrl+Shift+E 连按开出一堆相同页。
function openTabOverviewTab() {
  const existing = tabs.findIndex(t => t && t.url === TAB_OVERVIEW_URL);
  if (existing >= 0) {
    if (existing !== currentTabIndex) switchToTab(existing);
    return tabs[existing];
  }
  return createNewTab(TAB_OVERVIEW_URL);
}

const READER_PAGE_URL = 'cosy://reader';

// readerArticle 只暂存最近一次抽取结果，供紧随其后打开的 cosy://reader 读取；
// 阅读页关闭后清空。阅读数据虽由本进程可信内核产出，但它跨了“网页主世界”边界
// （executeJavaScript 的返回值来自页面环境），落进主进程前再做一次形状与长度收口。
let readerArticle = null;









// enterReaderMode 在“当前活动的 http(s) 标签”真实 DOM 内只读抽取正文，再带着
// 净化后的数据打开阅读页。抽取脚本运行在页面主世界但只调用只读 DOM API；返回值
// 经主进程二次形状校验。cosy:/file: 等内置页不支持阅读模式。


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

// ===== 任务管理器（cosy://taskmanager，Shift+Esc 唤起）=====
// 指标来自 app.getAppMetrics()（percentCPUUsage 是相对上一次调用的均值，因此渲染端
// 固定 2s 轮询），内存单位 KB。标签进程用 webContents.getOSProcessId() 的 OS pid 关联，
// 绝不能混用 getProcessId()（Chromium 内部 pid）。
const isTaskManagerFrameSender = internalFrame.makeInternalFrameSender({ isMainSender, host: 'taskmanager' });

// 汇总各标签渲染进程 OS pid -> {id,title,index}，用于把进程指标关联到具体标签。
// 视图已销毁 / pid 取不到的标签跳过，不让单个坏标签影响整页指标。
function buildTabPidMap() {
  const map = new Map();
  for (let i = 0; i < tabs.length; i++) {
    const tab = tabs[i];
    const wc = tab && tab.view && tab.view.webContents;
    if (!wc || typeof wc.getOSProcessId !== 'function') continue;
    let pid;
    try { pid = wc.getOSProcessId(); } catch { continue; }
    if (Number.isInteger(pid) && pid > 0 && !map.has(pid)) {
      map.set(pid, { id: String(tab.id), title: String(tab.title || tab.url || ''), index: i });
    }
  }
  return map;
}

ipcMain.handle('get-task-manager-processes', (event) => {
  if (!isTaskManagerFrameSender(event)) {
    return { total: { count: 0, memoryKB: 0, cpu: 0 }, byKind: [], rows: [] };
  }
  let metrics = [];
  try { metrics = app.getAppMetrics(); } catch { metrics = []; }
  return taskManagerCore.summarizeProcesses(metrics, buildTabPidMap());
});

// 结束标签：只接受任务管理器帧，按“稳定标签 id”定位（不接受会随标签增删漂移的索引），
// 且只允许关闭当前确实关联到某标签渲染进程的项；实际关闭复用现有 closeTab，不直接 kill。
ipcMain.handle('end-task-manager-tab', (event, payload = {}) => {
  if (!isTaskManagerFrameSender(event)) return { success: false, error: 'denied' };
  const id = payload && payload.id != null ? String(payload.id) : '';
  if (!id) return { success: false, error: 'bad-id' };
  const index = tabs.findIndex(t => t && String(t.id) === id);
  if (index < 0) return { success: false, error: 'not-found' };
  const tab = tabs[index];
  const urlProtocol = getUrlProtocol(tab.url);
  if (urlProtocol !== 'cosy:' && !isSafeUrl(tab.url)) return { success: false, error: 'unsafe' };
  closeTab(index);
  return { success: true, id };
});

// ===== 标签页概览（cosy://taboverview，Ctrl+Shift+E 唤起）=====
// 概览页按“网格卡片”展示全部标签，可搜索 / 切换 / 关闭 / 看缩略图。所有写入动作
// 都只接受概览页自身帧或主窗口帧发起，且 id 必须是当前 tabs 里真实存在的标签。

const isTabOverviewFrameSender = internalFrame.makeInternalFrameSender({ isMainSender, host: 'taboverview' });

// 历史页帧守卫：只放行 cosy://history 内置帧（主窗口外壳也可直达，供面板跳转）。
const isHistoryFrameSender = internalFrame.makeInternalFrameSender({ isMainSender, host: 'history' });

// 书签管理器帧守卫：只放行 cosy://bookmarks 内置帧（主窗口外壳也可直达）。
const isBookmarksFrameSender = internalFrame.makeInternalFrameSender({ isMainSender, host: 'bookmarks' });

// 稍后读帧守卫：只放行 cosy://readinglist 内置帧（主窗口外壳也可直达）。
const isReadingListFrameSender = internalFrame.makeInternalFrameSender({ isMainSender, host: 'readinglist' });

// 关于页帧守卫：只放行 cosy://about 内置帧（主窗口外壳也可直达）。
const isAboutFrameSender = internalFrame.makeInternalFrameSender({ isMainSender, host: 'about' });

// 快捷键速查页帧守卫：只放行 cosy://shortcuts 内置帧（主窗口外壳也可直达）。
const isShortcutsFrameSender = internalFrame.makeInternalFrameSender({ isMainSender, host: 'shortcuts' });

// 内部页导航帧守卫：只放行 cosy://pages 内置帧（主窗口外壳也可直达）。
const isPagesFrameSender = internalFrame.makeInternalFrameSender({ isMainSender, host: 'pages' });

// 内部页登记表：cosy://<name> → 标题 + 说明。供 cosy://pages 导航渲染；
// 说明仅作静态文案，不携带任何会话数据。
const INTERNAL_PAGES = {
  'setting': { title: '设置', desc: '外观、隐私与安全、WebRTC 与广告信号等浏览器全局选项。' },
  'newtab': { title: '新标签页', desc: '空白新标签页，常去网站快速入口。' },
  'extensions': { title: '扩展程序', desc: '查看与卸载已安装扩展；危险权限扩展一律拒绝安装。' },
  'version': { title: '版本信息', desc: 'OpenCosy、Electron 与 Chromium 版本号。' },
  'sitedata': { title: '站点数据', desc: 'Cookie、存储与站点数据的分站点管理与清除。' },
  'permissions': { title: '站点权限', desc: '各站点摄像头 / 麦克风 / 定位等权限授予记录。' },
  'security': { title: '安全中心', desc: '请求日志、品牌仿冒命中、CSP 报告与响应头评分。' },
  'hashes': { title: '哈希校验', desc: '下载文件的 SHA-256 校验记录。' },
  'downloadlist': { title: '下载中心', desc: '下载历史、进度与已下载文件的完整性校验。' },
  'taskmanager': { title: '任务管理器', desc: '当前标签页的进程内存占用概览。' },
  'taboverview': { title: '标签页概览', desc: '网格浏览全部标签页，分组过滤与快速切换。' },
  'history': { title: '历史记录', desc: '完整浏览历史：搜索、按站点过滤、单条删除与清空。' },
  'bookmarks': { title: '书签管理器', desc: '搜索、重命名与删除全部书签。' },
  'readinglist': { title: '稍后读', desc: '收藏待读页面：右键链接即可加入，本地持久化。' },
  'about': { title: '关于', desc: '版本、运行时与安全状态总览。' },
  'shortcuts': { title: '快捷键', desc: '全部键盘快捷键速查表。' },
  'reader': { title: '阅读模式', desc: '当前页面的纯净阅读视图。' },
  'httpsonly': { title: 'HTTPS-Only', desc: '强制 HTTPS 开关与站点例外管理。' },
};

// tabOverviewItem 输出单标签的概览数据。字段做类型收口，避免脏标题 / 长 URL
// 破坏网格布局；分组信息从 tabGroupModel 实时取，标签被改组后概览自动跟随。


ipcMain.handle('tab-overview-snapshot', (event) => {
  if (!isTabOverviewFrameSender(event)) return { ok: false, error: 'denied' };
  return {
    ok: true,
    tabs: tabs.map(tabOverviewItem),
    groups: tabGroupModel.orderedGroupIds().map(gid => {
      const g = tabGroupModel.getGroup(gid);
      return {
        id: gid,
        name: g ? String(g.title || '') : '',
        color: g ? String(g.color || '') : '',
        collapsed: !!(g && g.collapsed),
      };
    }),
  };
});

// 概览页点击卡片：切到该标签。id 不存在时静默失败（标签可能已被关闭）。
ipcMain.handle('tab-overview-activate', (event, payload = {}) => {
  if (!isTabOverviewFrameSender(event)) return { ok: false, error: 'denied' };
  const id = payload && payload.id != null ? String(payload.id) : '';
  const index = tabs.findIndex(t => t && String(t.id) === id);
  if (index < 0) return { ok: false, error: 'not-found' };
  switchToTab(index);
  return { ok: true, id };
});

// 概览页关闭卡片：复用现有 closeTab（含分组联动 / 最近关闭 / 持久化）。
ipcMain.handle('tab-overview-close', (event, payload = {}) => {
  if (!isTabOverviewFrameSender(event)) return { ok: false, error: 'denied' };
  const id = payload && payload.id != null ? String(payload.id) : '';
  const index = tabs.findIndex(t => t && String(t.id) === id);
  if (index < 0) return { ok: false, error: 'not-found' };
  closeTab(index);
  return { ok: true, id };
});

// 概览页缩略图：capturePage 截当前标签画面，按最长边 ≤360px 缩放成 dataURL。
// 只接受概览页帧；视图已销毁 / 崩溃 / 后台被丢弃的标签返回空，不让单页拖垮整页。
ipcMain.handle('tab-overview-capture', async (event, payload = {}) => {
  if (!isTabOverviewFrameSender(event)) return { ok: false, error: 'denied' };
  const id = payload && payload.id != null ? String(payload.id) : '';
  const index = tabs.findIndex(t => t && String(t.id) === id);
  if (index < 0) return { ok: false, error: 'not-found' };
  const tab = tabs[index];
  const wc = tab && tab.view && tab.view.webContents;
  if (!wc || wc.isDestroyed() || tab.crashed || tab.discarded) {
    return { ok: false, error: 'unavailable' };
  }
  try {
    const image = await wc.capturePage();
    if (image.isEmpty()) return { ok: false, error: 'empty' };
    const size = image.getSize();
    const longest = Math.max(size.width, size.height) || 1;
    let scaled = image;
    if (longest > 360) {
      const factor = 360 / longest;
      scaled = image.resize({
        width: Math.max(1, Math.round(size.width * factor)),
        height: Math.max(1, Math.round(size.height * factor)),
      });
    }
    const dataUrl = scaled.toDataURL();
    if (typeof dataUrl !== 'string' || dataUrl.length > 600000) {
      return { ok: false, error: 'too-large' };
    }
    return { ok: true, dataUrl };
  } catch {
    return { ok: false, error: 'capture-failed' };
  }
});

const loadTabContentCtx = {
  get addToHistory() { return addToHistory; },
  get addToReadingList() { return addToReadingList; },
  get allowPopupForTab() { return allowPopupForTab; },
  get applySavedZoom() { return applySavedZoom; },
  get bookmarks() { return bookmarks; },
  get classifyFrameNavigation() { return classifyFrameNavigation; },
  get createNewTab() { return createNewTab; },
  get getContentsState() { return getContentsState; },
  get getHttpStatusCode() { return getHttpStatusCode; },
  get getUrlProtocol() { return getUrlProtocol; },
  get handleRenderProcessGone() { return handleRenderProcessGone; },
  get history() { return history; },
  get inpageStates() { return inpageStates; },
  get isDev() { return isDev; },
  get isSafeUrl() { return isSafeUrl; },
  get launchExternalWithPrompt() { return launchExternalWithPrompt; },
  get maybeFallbackAfterUpgradeFailure() { return maybeFallbackAfterUpgradeFailure; },
  get originOfContents() { return originOfContents; },
  get pushNavState() { return pushNavState; },
  get recordSecurityEvent() { return recordSecurityEvent; },
  get searchProviderId() { return searchProviderId; },
  get sendToRenderer() { return sendToRenderer; },
  get showCosyError() { return showCosyError; },
  get showErrorPage() { return showErrorPage; },
  get spellcheckEnabled() { return spellcheckEnabled; },
  get switchToTab() { return switchToTab; },
  get tabs() { return tabs; },
  get titleStates() { return titleStates; },
  get toggleDevTools() { return toggleDevTools; },
  get updateBrowserViewBounds() { return updateBrowserViewBounds; },
};
function loadTabContent(tab) {
  return require('./tabcontent').loadTabContent(loadTabContentCtx, tab);
}

function showCosyError(tab, code, message, reason) {
  const errorParams = new URLSearchParams({ code, message, reason, url: tab.url, browserCode: -3, browserMessage: 'ERR_UNKNOWN_COSY_URL' });
  const errorUrl = `file://${__dirname}/src/error.html?${errorParams.toString()}`;
  tab.view.webContents.loadURL(errorUrl);
  tab.title = `错误 - ${code}`;
  tab.favicon = 'src/error.png';
  sendToRenderer('tab-updated', { id: tab.id, url: tab.url, title: tab.title });
}







// ===== 固定标签页（Pinned Tabs）=====
// 权威固定集合由 pintabs 纯内核维护；这里负责把固定状态落到 Tab 对象、把固定
// 标签物理重排到标签栏最前、跨重启按 URL 重水合、以及把状态变化广播给渲染层。
// 固定清单单独存 pintabs.json（session.json 只存 http/https 页，固定的 cosy 内置
// 页会被它过滤掉，无法复用）。
const pinModel = new pinTabs.PinModel();
const pinStorePath = path.join(app.getPath('userData'), 'pintabs.json');
let pinSaveTimer = null;

function savePinsNow() {
  try {
    // 跨重启运行时 id 会重新生成，因此按 URL 记录固定标签，重水合时再匹配新 id。
    const entries = [];
    for (const id of pinModel.ids()) {
      const t = tabs.find(tab => tab && tab.id === id);
      if (t && t.url) entries.push({ id, url: t.url });
    }
    ledgerStore.writeJSONStore(pinStorePath, { version: 1, entries });
  } catch (e) {
    console.error('保存固定标签失败:', e);
  }
}

function persistPins() {
  if (pinSaveTimer) clearTimeout(pinSaveTimer);
  pinSaveTimer = setTimeout(savePinsNow, 400);
}

function loadStoredPins() {
  try {
    const data = ledgerStore.readJSONStore(pinStorePath, null);
    if (!data || typeof data !== 'object') return [];
    return pinTabs.sanitizeStoredPinEntries(data.entries);
  } catch (e) {
    console.error('读取固定标签失败:', e);
    return [];
  }
}

function clearStoredPins() {
  try {
    if (fsSync.existsSync(pinStorePath)) fsSync.unlinkSync(pinStorePath);
  } catch (e) {
    console.error('清除固定标签失败:', e);
  }
}

function findTabIndexById(tabId) {
  return tabs.findIndex(t => t && String(t.id) === String(tabId));
}

// broadcastPinnedState 把单个标签的固定 / 取消固定结果推给渲染层。
function broadcastPinnedState(tab) {
  sendToRenderer('tab-pinned-changed', { id: tab.id, pinned: !!tab.pinned });
}

// applyPinnedState 设置标签固定态并同步内核；不负责重排，重排统一走
// movePinnedTabsToFront，便于批量重水合时只重排一次。
function applyPinnedState(tabId, pinned) {
  const idx = findTabIndexById(tabId);
  if (idx < 0) return { success: false };
  const tab = tabs[idx];
  const want = !!pinned;
  if (want) {
    const r = pinModel.pin(tab.id);
    if (!r.ok) return { success: false, reason: r.reason };
  } else {
    const r = pinModel.unpin(tab.id);
    if (!r.ok) return { success: false, reason: r.reason };
  }
  tab.pinned = want;
  broadcastPinnedState(tab);
  return { success: true, pinned: want, changed: true };
}

// movePinnedTabsToFront 依据内核的稳定分区结果，物理重排 tabs 数组（视图对象挂在
// Tab 上，随元素一起移动，不需要重建），并修正当前标签索引，最后让渲染层同步顺序。
function movePinnedTabsToFront() {
  const ordered = pinModel.arrange(tabs.map(t => t.id));
  if (ordered.length !== tabs.length) return false;
  const byId = new Map(tabs.map(t => [t.id, t]));
  const next = ordered.map(id => byId.get(id));
  const currentTab = tabs[currentTabIndex];
  for (let i = 0; i < tabs.length; i++) tabs[i] = next[i];
  if (currentTab) {
    const ni = tabs.indexOf(currentTab);
    if (ni >= 0) currentTabIndex = ni;
  }
  sendToRenderer('pins-order-changed', { ids: pinModel.ids() });
  return true;
}

function pinTab(tabId) {
  const r = applyPinnedState(tabId, true);
  if (!r.success) return r;
  movePinnedTabsToFront();
  persistPins();
  return r;
}

function unpinTab(tabId) {
  const r = applyPinnedState(tabId, false);
  if (!r.success) return r;
  movePinnedTabsToFront();
  persistPins();
  return r;
}

function toggleTabPinned(tabId) {
  const idx = findTabIndexById(tabId);
  if (idx < 0) return { success: false };
  return tabs[idx].pinned ? unpinTab(tabs[idx].id) : pinTab(tabs[idx].id);
}

// rehydratePinnedTabs 在启动恢复出标签后，用磁盘上的固定 URL 清单匹配本次新标签，
// 一次性恢复固定态并把它们排到最前。匹配不到（对应页本次没恢复）的固定项忽略。
function rehydratePinnedTabs() {
  const stored = loadStoredPins();
  if (!stored.length) return 0;
  const current = tabs.map(t => ({ id: t.id, url: t.url }));
  const pinnedIds = pinTabs.rehydratePinsByUrl(stored, current);
  for (const id of pinnedIds) {
    const r = applyPinnedState(id, true);
    if (!r.success) continue;
  }
  if (pinModel.count() > 0) movePinnedTabsToFront();
  return pinModel.count();
}

// ensurePinnedTabsOpened 在启动会话恢复之后调用：固定标签独立于 session.json
// 持久化，即使会话文件被清，也应把固定的 http/https 页补开后再重水合。固定的
// cosy 内置页不主动补开（避免与默认新标签页重复），只在它本次本就存在时固定。
function ensurePinnedTabsOpened() {
  const stored = loadStoredPins();
  if (!stored.length) return 0;
  const haveUrls = new Set(tabs.map(t => t.url));
  for (const rec of stored) {
    if (haveUrls.has(rec.url)) continue;
    if (getUrlProtocol(rec.url) === 'cosy:') continue;
    if (!isSafeUrl(rec.url)) continue;
    haveUrls.add(rec.url);
    createNewTab(rec.url);
  }
  return rehydratePinnedTabs();
}

// closeTabsByIds 按一组标签 id 批量关闭。为避免 splice 导致的索引漂移，统一从
// 最大索引向最小索引关闭。返回实际关闭数量。
function closeTabsByIds(ids) {
  const indexes = [];
  for (const id of ids) {
    const i = findTabIndexById(id);
    if (i >= 0) indexes.push(i);
  }
  indexes.sort((a, b) => b - a);
  for (const i of indexes) closeTab(i);
  return indexes.length;
}

// planAndCloseTabs 是批量关闭的唯一权威入口：先由 pintabs 内核裁决哪些标签允许
// 关闭（固定标签在任何模式下都保留），再真正关闭。渲染层不再自己循环关标签。
function planAndCloseTabs(mode, anchorId) {
  const plan = pinTabs.planBatchClose(
    tabs.map(t => ({ id: t.id, pinned: !!t.pinned })),
    { mode, anchorId }
  );
  if (!plan) return { success: false, closed: 0 };
  const closed = closeTabsByIds(plan.closeIds);
  return { success: true, closed, kept: plan.keepIds };
}

// ===== 标签分组（Tab Groups）=====
// 权威分组集合由 tabgroups 纯内核维护；这里负责把分组状态落到 IPC / 磁盘、按分组
// 重排标签栏、跨重启按当前标签重水合，以及把状态变化广播给渲染层。
// 分组清单单独存 tabgroups.json：记录的是运行时标签 id，跨重启时用 rehydrate 按
// “分组 id + 组内标签 id 集合”与当前打开的标签匹配（id 不跨重启，但组结构按顺序
// 恢复，组内标签 id 会在启动后由渲染层按当前 id 重新归属）。
const tabGroupModel = new tabGroups.TabGroupModel();
const tabGroupStorePath = path.join(app.getPath('userData'), 'tabgroups.json');
let tabGroupSaveTimer = null;

// tabGroupIsPinned 判定标签是否固定：固定标签与分组互斥（内核同规则），
// 固定优先，分组只作用于非固定区。
function tabGroupIsPinned(tabId) {
  const idx = findTabIndexById(tabId);
  return idx >= 0 && !!tabs[idx].pinned;
}

function saveTabGroupsNow() {
  try {
    ledgerStore.writeJSONStore(tabGroupStorePath, {
      version: 1,
      groups: tabGroupModel.serialize(),
    });
  } catch (e) {
    console.error('保存标签分组失败:', e);
  }
}

function persistTabGroups() {
  if (tabGroupSaveTimer) clearTimeout(tabGroupSaveTimer);
  tabGroupSaveTimer = setTimeout(saveTabGroupsNow, 400);
}

function loadStoredTabGroups() {
  try {
    const data = ledgerStore.readJSONStore(tabGroupStorePath, null);
    if (!data || typeof data !== 'object') return [];
    return tabGroups.sanitizeStoredGroups(data.groups);
  } catch (e) {
    console.error('读取标签分组失败:', e);
    return [];
  }
}

function clearStoredTabGroups() {
  try {
    if (fsSync.existsSync(tabGroupStorePath)) fsSync.unlinkSync(tabGroupStorePath);
  } catch (e) {
    console.error('清除标签分组失败:', e);
  }
}

// tabGroupOrder 依据内核 arrangeTabs 计算“目标标签 id 顺序”：固定区最前、
// 已分组标签按组聚类、未分组标签保持原相对顺序垫后。渲染层按此顺序渲染。
function tabGroupOrder() {
  return tabGroups.arrangeTabs(
    tabs.map(t => ({ id: t.id, pinned: !!t.pinned })),
    tabGroupModel,
    { isPinnedFn: tabGroupIsPinned }
  );
}

// broadcastTabGroups 把分组快照（分组列表 + 编排后的标签顺序）推给渲染层。
// 快照只含纯数据，绝不暴露 Tab 对象 / WebContents。
function broadcastTabGroups() {
  sendToRenderer('tab-groups-changed', {
    groups: tabGroupModel.serialize(),
    order: tabGroupOrder(),
  });
}

// reorderTabsByGroupPlan 依据目标顺序对 tabs 数组做物理重排（Tab 对象挂在
// Tab.view 上，随元素移动，无需重建视图），并修正当前标签索引。最后让渲染层
// 按新顺序渲染。返回是否发生了顺序变化。
function reorderTabsByGroupPlan(targetOrder) {
  if (!Array.isArray(targetOrder) || targetOrder.length !== tabs.length) return false;
  const byId = new Map(tabs.map(t => [t.id, t]));
  const next = targetOrder.map(id => byId.get(id));
  if (next.some(t => !t)) return false; // 目标顺序与当前标签不一致时不擅动
  const currentTab = tabs[currentTabIndex];
  for (let i = 0; i < tabs.length; i++) tabs[i] = next[i];
  if (currentTab) {
    const ni = tabs.indexOf(currentTab);
    if (ni >= 0) currentTabIndex = ni;
  }
  return true;
}

// applyTabGroupArrangement 是“按分组重排标签栏”的唯一权威入口：用内核计算目标
// 顺序，再用 taborderdiff 求出最小移动指令（只移动需要挪位的标签，已有序的原地
// 不动），物理重排后广播。任何分组结构变化（建组 / 加标签 / 移出 / 解散 / 组间
// 移动）都调用它，避免渲染层各自猜测顺序。
function applyTabGroupArrangement() {
  const target = tabGroupOrder();
  const before = tabs.map(t => t.id);
  const diff = tabOrderDiff.diffOrder(before, target);
  if (!diff.ok) return;
  if (diff.unchanged) return;
  // 目标顺序与当前标签集合必须一致（diff 已确认 created/removed 为空才可重排）。
  if (diff.created.length > 0 || diff.removed.length > 0) return;
  if (reorderTabsByGroupPlan(target)) {
    broadcastTabGroups();
    sendToRenderer('pins-order-changed', { ids: pinModel.ids() });
  }
}

// rehydrateTabGroups 在启动会话恢复出标签之后调用：读取磁盘分组清单，按“组内
// 标签 id 与本次打开的非固定标签匹配”重水合模型（不匹配的组内标签剔除，变空的
// 组丢弃），然后按分组重排一次标签栏。
function rehydrateTabGroups() {
  const stored = loadStoredTabGroups();
  if (!stored.length) return 0;
  const current = tabs.map(t => ({ id: t.id, pinned: !!t.pinned }));
  const clean = tabGroups.rehydrateGroupsByTabs(stored, current);
  tabGroupModel.loadStored(clean);
  if (tabGroupModel.groupCount() > 0) {
    applyTabGroupArrangement();
    broadcastTabGroups();
  }
  return tabGroupModel.groupCount();
}

// tabGroupError 把内核拒绝原因转成渲染层可读的 { ok:false, reason }。
function tabGroupError(r) {
  return { ok: false, reason: r && r.reason ? tabGroups.describeReject(r.reason) : '分组操作失败' };
}

ipcMain.handle('get-tab-groups', (event) => {
  if (!isMainSender(event)) return { groups: [], order: [] };
  return { groups: tabGroupModel.serialize(), order: tabGroupOrder() };
});

ipcMain.handle('create-tab-group', (event, payload) => {
  if (!isMainSender(event)) return { ok: false, reason: 'Unauthorized' };
  const opts = payload || {};
  // 入参全部由内核净化：标题 / 颜色 / 标签 id 列表 / 折叠态都走白名单校验，
  // 固定标签会被剔除；脏输入不会进入模型或台账。
  const r = tabGroupModel.createGroup({
    title: opts.title,
    color: opts.color,
    tabIds: Array.isArray(opts.tabIds) ? opts.tabIds : [],
    collapsed: opts.collapsed === true,
  }, tabGroupIsPinned);
  if (!r.ok) return tabGroupError(r);
  persistTabGroups();
  applyTabGroupArrangement();
  return { ok: true, group: r.group };
});

ipcMain.handle('add-tabs-to-group', (event, payload) => {
  if (!isMainSender(event)) return { ok: false, reason: 'Unauthorized' };
  const r = tabGroupModel.addTabs(
    payload && payload.groupId,
    Array.isArray(payload && payload.tabIds) ? payload.tabIds : [],
    tabGroupIsPinned
  );
  if (!r.ok) return tabGroupError(r);
  persistTabGroups();
  applyTabGroupArrangement();
  return { ok: true, added: r.added, skippedPinned: r.skippedPinned };
});

ipcMain.handle('remove-tabs-from-group', (event, payload) => {
  if (!isMainSender(event)) return { ok: false, reason: 'Unauthorized' };
  const r = tabGroupModel.removeTabs(
    Array.isArray(payload && payload.tabIds) ? payload.tabIds : []
  );
  if (!r.ok) return tabGroupError(r);
  persistTabGroups();
  applyTabGroupArrangement();
  return { ok: true, removed: r.removed };
});

ipcMain.handle('move-tab-to-group', (event, payload) => {
  if (!isMainSender(event)) return { ok: false, reason: 'Unauthorized' };
  const r = tabGroupModel.moveTab(
    payload && payload.tabId,
    payload && payload.groupId,
    tabGroupIsPinned
  );
  if (!r.ok) return tabGroupError(r);
  persistTabGroups();
  applyTabGroupArrangement();
  return { ok: true, movedTo: r.movedTo || null };
});

ipcMain.handle('rename-tab-group', (event, payload) => {
  if (!isMainSender(event)) return { ok: false, reason: 'Unauthorized' };
  const r = tabGroupModel.renameGroup(payload && payload.groupId, payload && payload.title);
  if (!r.ok) return tabGroupError(r);
  persistTabGroups();
  broadcastTabGroups();
  return { ok: true, group: r.group };
});

ipcMain.handle('set-tab-group-color', (event, payload) => {
  if (!isMainSender(event)) return { ok: false, reason: 'Unauthorized' };
  const r = tabGroupModel.setGroupColor(payload && payload.groupId, payload && payload.color);
  if (!r.ok) return tabGroupError(r);
  persistTabGroups();
  broadcastTabGroups();
  return { ok: true, group: r.group };
});

ipcMain.handle('set-tab-group-collapsed', (event, payload) => {
  if (!isMainSender(event)) return { ok: false, reason: 'Unauthorized' };
  const r = tabGroupModel.setGroupCollapsed(payload && payload.groupId, !!(payload && payload.collapsed));
  if (!r.ok) return tabGroupError(r);
  persistTabGroups();
  broadcastTabGroups();
  return { ok: true, group: r.group };
});

ipcMain.handle('move-tab-group', (event, payload) => {
  if (!isMainSender(event)) return { ok: false, reason: 'Unauthorized' };
  const r = tabGroupModel.moveGroup(payload && payload.groupId, payload && payload.toGroupId);
  if (!r.ok) return tabGroupError(r);
  persistTabGroups();
  applyTabGroupArrangement();
  return { ok: true, order: r.order };
});

ipcMain.handle('dissolve-tab-group', (event, payload) => {
  if (!isMainSender(event)) return { ok: false, reason: 'Unauthorized' };
  const r = tabGroupModel.dissolveGroup(payload && payload.groupId);
  if (!r.ok) return tabGroupError(r);
  persistTabGroups();
  applyTabGroupArrangement();
  return { ok: true, freedTabs: r.freedTabs };
});

// sanitizeDownloadFilename 防 Content-Disposition 路径穿越与视觉伪装：
// 服务端可能在 filename 里塞 "../../evil.exe"、RTL 反转符、结尾点空格或
// Windows 保留设备名。这里委托 dloadguard.sanitizeName：剥离目录组件与不可见
// 字符、剥掉结尾点空格、给保留名加前缀，返回可安全落盘的纯文件名。
function sanitizeDownloadFilename(name) {
  if (!name || typeof name !== 'string') return 'download';
  const res = dloadGuard.sanitizeName(name);
  if (res.rejected || !res.name) return 'download';
  // 双保险：dloadguard 已剥目录，这里再清一遍 Windows/Unix 保留字符。
  const final = downloadName.sanitizeDownloadName(res.name, 'download');
  if (final.changed) {
    recordSecurityEvent('download-name', 'info',
      `下载文件名已净化（${final.reasons.join(',')}）`, '');
  }
  return final.name || 'download';
}

// resolveUniqueDownloadPath 如果目标已存在，自动追加 (1)/(2)/... 避免覆盖
function resolveUniqueDownloadPath(dir, filename) {
  let existingNames = [];
  try {
    existingNames = fsSync.readdirSync(dir);
  } catch (scanError) {
    existingNames = [];
  }
  const allocation = downloadPathCollision.claimUniquePath({ dir, filename, taken: existingNames });
  if (!allocation.ok) {
    recordSecurityEvent('download-savepath', 'critical',
      `无法分配唯一下载文件名: ${downloadPathCollision.describeAllocation(allocation)}`, 'download-manager');
    return '';
  }
  return allocation.path;
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



function persistDownloadRisks() {
  if (downloadRiskSaveTimer) clearTimeout(downloadRiskSaveTimer);
  downloadRiskSaveTimer = setTimeout(() => {
    try {
      ledgerStore.writeJSONStore(downloadRiskStorePath, { version: 1, records: downloadRiskRecords });
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



// handleDownloadEvent 是所有 session 共用的 will-download 处理器。历史上它只挂在
// defaultSession 上，而隔离 / 访客分区（fromPartition）的下载只在各自 session 上触发，
// 于是分区下载绕过了文件名净化、危险类型确认、保存路径策略与 MOTW。准入判定抽到
// downloadadmission 纯内核后，这里只负责执行决策（取消 / 弹窗 / 台账 / 落盘）。
const handleDownloadEventCtx = {
  get analyzeDownloadSafety() { return analyzeDownloadSafety; },
  get applyRateLimitToItem() { return applyRateLimitToItem; },
  get confirmDownloadDecision() { return confirmDownloadDecision; },
  setCurrentDownloadInfo: (v) => { currentDownloadInfo = v; },
  get currentDownloadInfo() { return currentDownloadInfo; },
  get downloadByteQuota() { return downloadByteQuota; },
  get downloadDiskMonitor() { return downloadDiskMonitor; },
  get downloadFreqLimiter() { return downloadFreqLimiter; },
  get downloadMaxBytes() { return downloadMaxBytes; },
  get downloadSlotGuard() { return downloadSlotGuard; },
  get downloads() { return downloads; },
  get formatSpeed() { return formatSpeed; },
  get getDownloadJournal() { return getDownloadJournal; },
  get isSafeUrl() { return isSafeUrl; },
  get journalDownloadState() { return journalDownloadState; },
  get notifyDownloadResult() { return notifyDownloadResult; },
  get originOfContents() { return originOfContents; },
  get recordDownloadRisk() { return recordDownloadRisk; },
  get recordSecurityEvent() { return recordSecurityEvent; },
  get rememberDownloadOrigin() { return rememberDownloadOrigin; },
  get resolveUniqueDownloadPath() { return resolveUniqueDownloadPath; },
  get sanitizeDownloadFilename() { return sanitizeDownloadFilename; },
  get sendShelf() { return sendShelf; },
  get sendToRenderer() { return sendToRenderer; },
};
function handleDownloadEvent(event, item, webContents) {
  return require('./downloadsevents').handleDownloadEvent(handleDownloadEventCtx, event, item, webContents);
}

// managedDownloadSessions 记录已挂过下载保护的 session。will-download 若对同一
// session 注册两次，一次下载会触发两轮回调：弹两次确认框、写两条台账、落盘后补两次
// MOTW。defaultSession 走 setupDownloadManager、分区走 session-created，理论上互斥，
// 但仍用 WeakSet 做幂等兜底（session 回收后条目自动消失，不泄漏）。
function downloadJournalFileProbe() {
  return {
    exists: (target) => {
      try { return fsSync.lstatSync(target).isFile(); } catch { return false; }
    },
    sizeOf: (target) => {
      try {
        const stat = fsSync.lstatSync(target);
        return stat.isFile() ? stat.size : null;
      } catch { return null; }
    },
  };
}





const managedDownloadSessions = new WeakSet();

// attachDownloadManager 把同一套下载保护挂到任意 session；defaultSession 与分区会话
// 都必须经过它，避免隔离 / 访客分区下载绕过文件名净化、危险类型确认与 MOTW。
function attachDownloadManager(sess) {
  if (!sess || managedDownloadSessions.has(sess)) return;
  try {
    sess.on('will-download', handleDownloadEvent);
    managedDownloadSessions.add(sess);
  } catch {}
}

function setupDownloadManager() {
  attachDownloadManager(session.defaultSession);
}

function formatSpeed(bytesPerSecond) {
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  let speed = bytesPerSecond;
  let unitIndex = 0;
  while (speed >= 1024 && unitIndex < units.length - 1) { speed /= 1024; unitIndex++; }
  return speed.toFixed(2) + ' ' + units[unitIndex];
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
  loadReadingList();
  loadZoomFactors();
  loadCustomRulesFromDisk(path.join(app.getPath('userData'), 'blockrules.json'));
  initVaultOnStartup();
  loadDownloads();

  // 启动时还原 darkMode / httpsOnly / memorySaver 等运行时状态
  const stored = readStoredSettings();
  applyDarkMode(!!stored.darkMode);
  httpsOnlyEnabled = stored.httpsOnly !== false;
  bookmarkBarVisible = stored.bookmarkBarVisible !== false;
  loadHttpsExceptions();
  blockTrackers = stored.blockTrackers !== false;
  blockThirdPartyCookies = stored.blockThirdPartyCookies !== false;
  hardenCookies = stored.hardenCookies !== false;
  blockLocalNetworkAccess = stored.blockLocalNetworkAccess !== false;
  reduceClientHints = stored.reduceClientHints !== false;
  blockAdSignals = stored.blockAdSignals !== false;
  blockHyperlinkPing = stored.blockHyperlinkPing !== false;
  stripAcceptCh = stored.stripAcceptCh !== false;
  if ('allowPictureInPicture' in stored) allowPictureInPicture = !!stored.allowPictureInPicture;
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
  downloadMaxBytes = downloadSizeGuard.normalizeLimit(persisted.downloadMaxBytes);
  applySpellcheckSettings();
  searchProviderId = searchProvider.sanitizeProviderChoice(persisted.searchEngine);
  loadUaPolicyStateFromDisk();
  applyUaPolicyToSession(session.defaultSession);
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

// get-recently-closed 供新标签页的“最近关闭”区块拉取（只读、不弹栈）：
// 快照字段经 downloadshelf 内核净化（剥控制字符/ANSI、限长），url 再走
// isSafeUrl 白名单，cosy:// 与危险协议绝不外泄。
ipcMain.handle('get-recently-closed', (event) => {
  if (!isMainSender(event)) return { success: false };
  const items = [];
  for (let i = recentlyClosedTabs.length - 1; i >= 0 && items.length < 8; i--) {
    const t = recentlyClosedTabs[i];
    if (!t || !t.url || !isSafeUrl(t.url) || String(t.url).startsWith('cosy://')) continue;
    items.push({
      url: downloadShelf.truncateRunes(downloadShelf.stripControlChars(String(t.url)), 800),
      title: downloadShelf.truncateRunes(downloadShelf.stripControlChars(String(t.title || '')), 120),
      closedAt: Number.isFinite(Number(t.closedAt)) ? Number(t.closedAt) : null,
    });
  }
  return { success: true, items };
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

// set-tab-pinned 固定 / 取消固定指定标签（默认当前标签）。重排与持久化都在
// 主进程完成，渲染层只据广播更新视图。
ipcMain.handle('set-tab-pinned', (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false };
  const { tabId, pinned } = payload || {};
  const targetId = (tabId === undefined || tabId === null)
    ? (tabs[currentTabIndex] && tabs[currentTabIndex].id)
    : tabId;
  if (targetId === undefined || targetId === null) return { success: false };
  const r = applyPinnedState(targetId, !!pinned);
  if (!r.success) return { success: false, reason: r.reason };
  movePinnedTabsToFront();
  persistPins();
  return { success: true, pinned: !!pinned };
});

// toggle-tab-pinned 在固定 / 取消固定之间切换（供右键菜单与快捷键使用）。
ipcMain.handle('toggle-tab-pinned', (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false };
  const tabId = (payload && payload.tabId !== undefined && payload.tabId !== null)
    ? payload.tabId
    : (tabs[currentTabIndex] && tabs[currentTabIndex].id);
  if (tabId === undefined || tabId === null) return { success: false };
  const r = toggleTabPinned(tabId);
  if (!r.success) return { success: false, reason: r.reason };
  return { success: true, pinned: !!r.pinned };
});

// close-tabs-batch 批量关闭（all/others/left/right）。固定标签由主进程内核统一
// 豁免，渲染层不再自行循环关闭，避免固定标签被“关闭其他 / 左侧 / 右侧”误关。
ipcMain.handle('close-tabs-batch', (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false, closed: 0 };
  const mode = payload && payload.mode;
  const anchorId = payload && payload.anchorId;
  const r = planAndCloseTabs(mode, anchorId);
  if (!r.success) return { success: false, closed: 0 };
  return { success: true, closed: r.closed };
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



function originOfUrl(u) {
  return urlResolve.safeOrigin(u, '');
}

// loadZoomFactors 启动时从 userData 读取按站点记忆的缩放（对齐 Chrome 跨重启保留缩放）。
// 文件损坏 / 被外部塞非法内容时静默丢弃，绝不因此影响浏览器启动。


// persistZoomFactors 防抖落盘，避免连续放大缩小频繁写文件。




// adjustCurrentZoom 是菜单快捷键与 IPC 共用的唯一缩放入口：
// 统一用 setZoomFactor（不要混用 setZoomLevel，二者写同一底层值会互相覆盖），
// 计算结果按 origin 记忆、导航恢复、并持久化到磁盘。


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
  const payload = data && typeof data === 'object' ? data : {};
  if (currentDownloadInfo) {
    try {
      const fallbackName = sanitizeDownloadFilename(currentDownloadInfo.filename);
      let savePath = path.join(app.getPath('downloads'), fallbackName);
      if (payload.savePath) {
        const requestedPath = path.resolve(String(payload.savePath));
        const safeRoot = getSafeDirs().find((dir) => isPathInDir(requestedPath, dir));
        const targetCheck = safeRoot
          ? downloadSaveTarget.auditSaveTargetReal(safeRoot, requestedPath, path.basename(requestedPath))
          : null;
        if (targetCheck && targetCheck.ok) savePath = targetCheck.path;
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
  const payload = data && typeof data === 'object' ? data : {};
  dialog.showSaveDialog(mainWindow, {
    defaultPath: path.join(app.getPath('downloads'), sanitizeDownloadFilename(payload.defaultName || 'download')),
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
        const chosenVerdict = downloadSaveTarget.auditSaveName(path.basename(result.filePath));
        if (chosenVerdict !== downloadSaveTarget.REASON.OK) {
          sendToRenderer('show-toast',
            `另存为文件名非法，已取消：${downloadSaveTarget.describeSaveTargetReject(chosenVerdict)}`);
          return;
        }
        currentDownloadInfo.savePath = result.filePath;
        currentDownloadInfo.status = 'pending';
        currentDownloadInfo.item = null;
        currentDownloadInfo.isItemValid = false;
      }
      if (payload.url && isSafeUrl(payload.url)) session.defaultSession.downloadURL(payload.url);
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

// copy-text：受控剪贴板写入（下载项右键“复制链接/复制文件名”用）。
// 只接受字符串、长度上限 4096，避免恶意渲染层借 IPC 写入超长文本 / 二进制垃圾；
// 文本本身由调用方（renderer 右键菜单）提供，这里仅做类型与长度收口。
ipcMain.on('copy-text', (event, text) => {
  if (!isMainSender(event)) return;
  if (typeof text !== 'string' || text.length === 0 || text.length > 4096) return;
  clipboard.writeText(text);
});

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
  const url = data && typeof data === 'object' ? data.url : null;
  if (typeof url === 'string' && url.length > 0 && isSafeUrl(url)) session.defaultSession.downloadURL(url);
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

// performDownloadOpen 是“打开已下载文件”的唯一执行出口：下载列表 IPC 与系统
// 通知点击都走这里。判定交给 dloadopen 内核（文件名伪装、来源、容器类型），
// UI（确认框）与系统调用留在这里，避免通知点击绕过来源确认与路径消毒。


ipcMain.on('open-file', (event, filePath) => {
  if (!isMainSender(event)) return;
  performDownloadOpen(path.resolve(filePath));
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
  const origin = urlResolve.safeOrigin(event.sender.getURL());
  return await confirmAndOpenExternal(String(url || ''), origin);
});

// 供设置页读取 / 撤销"站点 -> 外部协议"的记忆决定。
ipcMain.handle('get-protocol-decisions', (event) => {
  if (!isMainSender(event)) return { ok: false, reason: 'unauthorized' };
  return { ok: true, items: listProtocolDecisions() };
});

ipcMain.handle('clear-protocol-decision', (event, data) => {
  if (!isMainSender(event)) return { ok: false, reason: 'unauthorized' };
  const origin = data && typeof data.origin === 'string' ? data.origin : '';
  const scheme = data && typeof data.scheme === 'string' ? data.scheme : '';
  return forgetProtocolDecision(origin, scheme);
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
    discarded: !!tab.discarded, pinned: !!tab.pinned
  }));
});

// search-tabs：在“当前权威 tabs 列表”上跑纯逻辑标签搜索。匹配/排序全部在
// tabsearch 内核完成，这里只喂 id/title/url/pinned，结果里的 index 即当前 tabs
// 下标，渲染层回车时直接复用 switch-tab(index) 切换，不需要新增激活通道。
ipcMain.handle('search-tabs', (event, query) => {
  if (!isMainSender(event)) return [];
  const q = typeof query === 'string' ? query : '';
  const snapshot = tabs.map(tab => ({
    id: tab.id,
    title: typeof tab.title === 'string' ? tab.title : '',
    url: typeof tab.url === 'string' ? tab.url : '',
    pinned: !!tab.pinned,
  }));
  return tabSearch.searchTabs(snapshot, q);
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
  const pos = position && Number.isFinite(position.x) && Number.isFinite(position.y)
    ? { x: Math.round(position.x), y: Math.round(position.y) }
    : null;
  menu.popup(pos ? { window: mainWindow, x: pos.x, y: pos.y } : { window: mainWindow });
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



// 条目名安全判定统一走 extensionstore 内核（含穿越、ADS 冒号、控制字符、超长名）。
const isSafeEntryName = extensionStore.isSafeEntryName;

// copyExtensionToStorage 递归复制扩展文件到 extensionsPath/<id>。
// 安全关键：
//  1. 用 lstat 的 isSymbolicLink()（注意小写 i；旧代码误写 IsSymbolicLink，Node 无此
//     方法，调用必抛 TypeError，导致复制永远失败、符号链接保护也从未生效）。符号链接
//     一律跳过，否则一个指到 ~/.ssh/id_rsa 的链接会把私钥复制进扩展目录被扩展读到。
//  2. 每个目标路径用 resolveWithinRoot 收口，防止条目名或目录深度拼接触底扩展根。
//  3. 复制受深度 / 条目数 / 总字节预算约束，防止恶意目录耗尽磁盘。
// 返回 { ok:true } 或 { ok:false, reason }，越界预算类问题整单中止（不装半截扩展）。


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
    // 配置文件可能被外部篡改，id 必须仍解析到扩展根之内，拒绝加载任意目录。
    const extensionPath = extensionStore.resolveExtensionDir(extensionsPath, extension && extension.id);
    if (!extensionPath) {
      recordSecurityEvent('extension-blocked', 'warn',
        `拒绝加载越界插件目录（id=${extension && extension.id}）`, '');
      return;
    }
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
    const extensionId = extensionStore.buildExtensionId(manifest.name, manifest.version);
    if (!extensionId) return { success: false, error: '插件名称或版本不合法，无法生成安全ID' };
    const config = await readExtensionsConfig();
    if (config.extensions.find(ext => ext.id === extensionId)) return { success: false, error: '该插件已存在' };
    const copyResult = await copyExtensionToStorage(folderPath, extensionId);
    if (!copyResult.ok) return { success: false, error: '复制插件文件失败（' + copyResult.reason + '）' };
    let iconPath = '';
    if (manifest.icons) {
      const iconSizes = Object.keys(manifest.icons).sort((a, b) => parseInt(b) - parseInt(a));
      if (iconSizes.length > 0) {
        const iconName = manifest.icons[iconSizes[0]];
        if (isSafeEntryName(iconName)) {
          iconPath = extensionStore.resolveWithinRoot(extensionsPath, extensionId, iconName) || '';
        }
      }
    }
    const extensionDir = extensionStore.resolveExtensionDir(extensionsPath, extensionId);
    const newExtension = {
      id: extensionId, name: manifest.name, version: manifest.version,
      description: manifest.description || '', icon: iconPath,
      path: extensionDir || '', enabled: true, addedDate: new Date().toISOString()
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
    // 递归 rm 前必须把目录收口到扩展根之内：配置若被塞成 id="../AppData"，旧实现
    // path.join 后会递归删除扩展目录之外的内容。越界直接拒绝删除。
    const extensionPath = extensionStore.resolveExtensionDir(extensionsPath, id);
    if (!extensionPath) {
      recordSecurityEvent('extension-blocked', 'warn',
        `拒绝删除越界插件目录（id=${id}）`, '');
      return { success: false, error: '插件目录不合法' };
    }
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
  const payload = data && typeof data === 'object' ? data : {};
  const menuType = payload.menuType === 'selection' ? 'selection' : 'default';
  const selectedText = typeof payload.selectedText === 'string' ? payload.selectedText.slice(0, 256) : '';
  const menu = createContextMenu(menuType, selectedText);
  if (!mainWindow || mainWindow.isDestroyed()) return;
  menu.popup({ window: mainWindow });
});

// ===== 标签页右键菜单（原生 Tab 菜单）=====
// 渲染层在标签元素上右键时只上报内部 tabId；这里基于主进程维护的 tab 状态构建
// 原生菜单。菜单项的 URL / 标题全部来自本机 tabs 数据（非网页注入），复制走
// clipboard 仅写入受控文本，杜绝自绘菜单的样式/事件注入面。
ipcMain.on('show-tab-context-menu', (event, payload) => {
  if (!isMainSender(event)) return;
  const tabId = payload && payload.tabId;
  const idx = findTabIndexById(tabId);
  if (idx < 0) return;
  const tab = tabs[idx];
  const safeUrl = (typeof tab.url === 'string' && tab.url.length <= 2048) ? tab.url : '';
  const safeTitle = (typeof tab.title === 'string' && tab.title.length <= 300) ? tab.title : '';
  const menu = new Menu();
  menu.append(new MenuItem({
    label: '在新标签页中打开',
    enabled: Boolean(safeUrl),
    click: () => { if (safeUrl) createNewTab(safeUrl); }
  }));
  menu.append(new MenuItem({
    label: '复制链接地址',
    enabled: Boolean(safeUrl),
    click: () => { if (safeUrl) clipboard.writeText(safeUrl); }
  }));
  menu.append(new MenuItem({
    label: '复制标题',
    enabled: Boolean(safeTitle),
    click: () => { if (safeTitle) clipboard.writeText(safeTitle); }
  }));
  menu.append(new MenuItem({ type: 'separator' }));
  menu.append(new MenuItem({
    label: '重新加载',
    click: () => { if (tab.view && tab.view.webContents) tab.view.webContents.reload(); }
  }));
  menu.append(new MenuItem({ type: 'separator' }));
  menu.append(new MenuItem({
    label: tab.pinned ? '取消固定标签页' : '固定标签页',
    click: () => toggleTabPinned(tab.id)
  }));
  menu.append(new MenuItem({
    label: tab.muted ? '取消静音标签页' : '静音标签页',
    click: () => {
      if (!tab.view || !tab.view.webContents) return;
      tab.muted = !tab.muted;
      tab.view.webContents.setAudioMuted(tab.muted);
      try { tab.audible = !!tab.view.webContents.isCurrentlyAudible(); } catch {}
      sendToRenderer('tab-audio-changed', { id: tab.id, audible: tab.audible, muted: tab.muted });
    }
  }));
  menu.append(new MenuItem({ type: 'separator' }));
  menu.append(new MenuItem({
    label: '关闭标签页',
    click: () => { closeTabsByIds([tab.id]); }
  }));
  menu.append(new MenuItem({
    label: '关闭其他标签页',
    click: () => { planAndCloseTabs('others', tab.id); }
  }));
  menu.popup({ window: mainWindow });
});

// ===== 书签栏显隐的查询与持久化 =====
// 顶栏书签栏的显隐是用户偏好：切换后写回 cosySettings.json（复用 sanitizeSettings
// 白名单校验），启动时恢复。查询走 invoke（渲染层只读），切换走 send（受信帧）。
ipcMain.handle('get-bookmark-bar-visible', (event) => {
  if (!isMainSender(event)) return { success: false };
  return { success: true, visible: bookmarkBarVisible };
});

ipcMain.on('set-bookmark-bar-visible', (event, payload) => {
  if (!isMainSender(event)) return;
  const next = !!(payload && payload.visible);
  if (next === bookmarkBarVisible) return;
  bookmarkBarVisible = next;
  try {
    const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
    const cur = readStoredSettings();
    cur.bookmarkBarVisible = next;
    ledgerStore.writeJSONStore(settingsPath, sanitizeSettings(cur), { pretty: true });
  } catch (e) {
    console.error('保存书签栏显隐失败:', e);
  }
});

const ALLOWED_SETTING_KEYS = {
  darkMode: v => typeof v === 'boolean',
  httpsOnly: v => typeof v === 'boolean',
  bookmarkBarVisible: v => typeof v === 'boolean',
  blockTrackers: v => typeof v === 'boolean',
  blockThirdPartyCookies: v => typeof v === 'boolean',
  hardenCookies: v => typeof v === 'boolean',
  blockLocalNetworkAccess: v => typeof v === 'boolean',
  reduceClientHints: v => typeof v === 'boolean',
  blockAdSignals: v => typeof v === 'boolean',
  blockHyperlinkPing: v => typeof v === 'boolean',
  downloadMaxBytes: v => Number.isFinite(v) && v >= 0,
  stripAcceptCh: v => typeof v === 'boolean',
  allowPictureInPicture: v => typeof v === 'boolean',
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
  searchEngine: v => typeof v === 'string' && searchProvider.providerById(v) !== null,
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
    // 崩溃安全原子写：避免写一半断电导致设置文件截断、下次启动全部偏好丢失。
    ledgerStore.writeJSONStore(settingsPath, clean, { pretty: true });
    // 立即把 darkMode / httpsOnly / memorySaver 应用到运行时
    applyDarkMode(clean.darkMode);
    httpsOnlyEnabled = clean.httpsOnly !== false;
    bookmarkBarVisible = clean.bookmarkBarVisible !== false;
    blockTrackers = clean.blockTrackers !== false;
    blockThirdPartyCookies = clean.blockThirdPartyCookies !== false;
    hardenCookies = clean.hardenCookies !== false;
    blockLocalNetworkAccess = clean.blockLocalNetworkAccess !== false;
    reduceClientHints = clean.reduceClientHints !== false;
    blockAdSignals = clean.blockAdSignals !== false;
    blockHyperlinkPing = clean.blockHyperlinkPing !== false;
    stripAcceptCh = clean.stripAcceptCh !== false;
    if ('allowPictureInPicture' in clean) allowPictureInPicture = !!clean.allowPictureInPicture;
    if ('searchEngine' in clean) searchProviderId = searchProvider.sanitizeProviderChoice(clean.searchEngine);
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
    if ('downloadMaxBytes' in clean) downloadMaxBytes = downloadSizeGuard.normalizeLimit(clean.downloadMaxBytes);
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
    // 复用统一的有界设置读取，坏 / 超大文件回落 {}，不再 existsSync+整读。
    event.reply('settings-loaded', readStoredSettings());
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

// sanitizeBookmarkLike 把书签 / 稍后读条目收敛成可进内部页 DOM 的标量快照：
// url、title 限长，addedDate 只接受字符串。两个管理器历史上各自内联了同一段映射，
// 集中到这里，避免标题长度上限或类型收口在某一处被改漏。
function sanitizeBookmarkLike(b) {
  return {
    url: typeof b.url === 'string' ? b.url.slice(0, 8192) : '',
    title: typeof b.title === 'string' ? b.title.slice(0, 300) : '',
    addedDate: typeof b.addedDate === 'string' ? b.addedDate : '',
  };
}

// openUrlFromInternalFrame 是历史 / 书签 / 稍后读三个内部页“点击条目新开标签”的
// 公共内核：frameOk 是该页自己的帧来源判定；URL 必须过 isSafeUrl（http/https），
// cosy:// 内置页则交由 createNewTab 的 pageMap 白名单兜底，其余协议一律拒绝。
// 三个 handler 过去逐字复制了同一段校验，集中后任何收紧只需改这一处。
function openUrlFromInternalFrame(frameOk, url) {
  if (!frameOk) return { ok: false, error: 'denied' };
  const isInternal = typeof url === 'string' && url.startsWith('cosy://');
  if (!isSafeUrl(url) && !isInternal) return { ok: false, error: 'bad-url' };
  const tab = createNewTab(url);
  return { ok: true, id: tab.id, index: tabs.length - 1 };
}

// 历史页快照：全量返回历史数组（上限 1000 条，磁盘加载已按 MAX_HISTORY_ENTRIES
// 截断）。只放行历史页帧 / 主窗口外壳；返回前对每条做类型收口，绝不让脏标题
// 或畸形 URL 进入内部页 DOM。
ipcMain.handle('history-snapshot', (event) => {
  if (!isHistoryFrameSender(event)) return { ok: false, error: 'denied', items: [] };
  const items = history.slice(0, MAX_HISTORY_ENTRIES).map(item => ({
    url: typeof item.url === 'string' ? item.url.slice(0, 8192) : '',
    title: typeof item.title === 'string' ? item.title.slice(0, 300) : '',
    timestamp: typeof item.timestamp === 'number' && Number.isFinite(item.timestamp) ? item.timestamp : 0,
  }));
  return { ok: true, items };
});

// 历史页删除单条：按 url + timestamp 精确匹配删除（同一 URL 可能有多条时间戳）。
// 匹配不到静默成功；删除后落盘。
ipcMain.handle('history-delete-entry', (event, payload = {}) => {
  if (!isHistoryFrameSender(event)) return { ok: false, error: 'denied' };
  const url = typeof payload.url === 'string' ? payload.url : '';
  const timestamp = typeof payload.timestamp === 'number' ? payload.timestamp : NaN;
  const before = history.length;
  history = history.filter(item =>
    !(String(item.url || '') === url && item.timestamp === timestamp));
  if (history.length !== before) saveHistory();
  return { ok: true, removed: before - history.length };
});

// 历史页点击条目：经 isSafeUrl 校验后在当前窗口新开标签。cosy:// 内置地址
// 同样放行（历史页“在新标签打开”允许内部页跳转），其余非法协议一律拒绝。
ipcMain.handle('history-open-url', (event, url) =>
  openUrlFromInternalFrame(isHistoryFrameSender(event), url));

// 历史页清空：仅受信帧可触发，与面板“清除历史”共用 saveHistory 落盘。
ipcMain.handle('history-clear-all', (event) => {
  if (!isHistoryFrameSender(event)) return { ok: false, error: 'denied' };
  history = [];
  saveHistory();
  return { ok: true };
});

// 历史页批量删除：urls 数组（每项 {url,timestamp}）逐条精确匹配。
// 条数上限防滥用；删除后落盘。
ipcMain.handle('history-delete-entries', (event, payload = {}) => {
  if (!isHistoryFrameSender(event)) return { ok: false, error: 'denied' };
  const urls = Array.isArray(payload.urls) ? payload.urls : [];
  if (urls.length > 5000) return { ok: false, error: 'too-many' };
  const targets = [];
  for (const it of urls) {
    if (!it || typeof it !== 'object') continue;
    const url = typeof it.url === 'string' ? it.url.slice(0, 8192) : '';
    const timestamp = typeof it.timestamp === 'number' ? it.timestamp : NaN;
    if (!url || !Number.isFinite(timestamp)) continue;
    targets.push({ url, timestamp });
  }
  if (targets.length === 0) return { ok: true, removed: 0 };
  const before = history.length;
  history = history.filter(item => {
    for (const t of targets) {
      if (String(item.url || '') === t.url && item.timestamp === t.timestamp) return false;
    }
    return true;
  });
  if (history.length !== before) saveHistory();
  return { ok: true, removed: before - history.length };
});

// 历史页导出 JSON：弹保存框，写 UTF-8 文件。内容由渲染层传入的纯文本
// （已本地生成），本端仅做类型与长度收口，防止大 payload 撑爆内存。
ipcMain.handle('history-export-json', async (event, payload = {}) => {
  if (!isHistoryFrameSender(event)) return { ok: false, error: 'denied' };
  try {
    const name = typeof payload.name === 'string' ? payload.name.slice(0, 128).replace(/[^\w.-]/g, '') : 'opencosy-history.json';
    const text = typeof payload.text === 'string' ? payload.text : '';
    if (text.length > 64 * 1024 * 1024) return { ok: false, error: 'too-large' };
    const result = await dialog.showSaveDialog(mainWindow, {
      title: '导出历史记录',
      defaultPath: name,
      filters: [{ name: 'JSON 文件', extensions: ['json'] }, { name: '所有文件', extensions: ['*'] }],
    });
    if (result.canceled || !result.filePath) return { ok: true, canceled: true };
    fsSync.writeFileSync(result.filePath, text, 'utf-8');
    return { ok: true, path: result.filePath, bytes: Buffer.byteLength(text, 'utf-8') };
  } catch (e) {
    console.error('导出历史失败:', e);
    return { ok: false, error: e.message };
  }
});

// 书签管理器快照：返回全量书签（拷贝防外部篡改，标题/URL 长度收口）。
ipcMain.handle('bookmarks-snapshot', (event) => {
  if (!isBookmarksFrameSender(event)) return { ok: false, error: 'denied', items: [] };
  const items = bookmarks.map(sanitizeBookmarkLike);
  return { ok: true, items };
});

// 书签管理器打开：经 isSafeUrl 校验（含 cosy:// 内部页），新标签打开。
ipcMain.handle('bookmarks-open-url', (event, url) =>
  openUrlFromInternalFrame(isBookmarksFrameSender(event), url));

// 书签管理器删除：按 url 精确匹配，删除后落盘并广播（书签栏同步）。
ipcMain.handle('bookmarks-remove', (event, payload = {}) => {
  if (!isBookmarksFrameSender(event)) return { ok: false, error: 'denied' };
  const url = typeof payload.url === 'string' ? payload.url : '';
  const before = bookmarks.length;
  bookmarks = bookmarks.filter(b => !(String(b.url || '') === url));
  if (bookmarks.length !== before) {
    saveBookmarks();
    sendToRenderer('bookmarks-updated', bookmarks);
  }
  return { ok: true, removed: before - bookmarks.length };
});

// 书签管理器重命名：标题经 300 字收口 + 控制字符清洗，防注入脏文本。
ipcMain.handle('bookmarks-rename', (event, payload = {}) => {
  if (!isBookmarksFrameSender(event)) return { ok: false, error: 'denied' };
  const url = typeof payload.url === 'string' ? payload.url : '';
  let title = typeof payload.title === 'string' ? payload.title : '';
  title = title.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 300).trim();
  if (!title) return { ok: false, error: 'bad-title' };
  const b = bookmarks.find(x => String(x.url || '') === url);
  if (!b) return { ok: false, error: 'not-found' };
  b.title = title;
  saveBookmarks();
  sendToRenderer('bookmarks-updated', bookmarks);
  return { ok: true, title };
});

// 稍后读快照：返回全量条目（拷贝防外部篡改，标题/URL 长度收口，与书签同款净化）。
ipcMain.handle('readinglist-snapshot', (event) => {
  if (!isReadingListFrameSender(event)) return { ok: false, error: 'denied', items: [] };
  const items = readingList.map(sanitizeBookmarkLike);
  return { ok: true, items };
});

// 稍后读新增（右键菜单“加入稍后读”/页面内部调用）：URL 必须经 isSafeUrl 校验
// （http/https），标题去控制字符并限长。已存在的同 URL 条目忽略（幂等）。
function addToReadingList(url, title) {
  if (!isSafeUrl(url)) return { ok: false, error: 'bad-url' };
  let t = typeof title === 'string' ? title : '';
  t = t.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 300).trim();
  if (readingList.some(b => String(b.url || '') === url)) return { ok: true, added: false };
  readingList.push({ url, title: t || url, addedDate: new Date().toISOString() });
  saveReadingList();
  return { ok: true, added: true };
}

ipcMain.handle('readinglist-add', (event, payload = {}) => {
  if (!isReadingListFrameSender(event) && !isMainSender(event)) return { ok: false, error: 'denied' };
  const url = typeof payload.url === 'string' ? payload.url : '';
  return addToReadingList(url, payload.title);
});

// 稍后读打开：经 isSafeUrl 校验（含 cosy:// 内部页），新标签打开。
ipcMain.handle('readinglist-open-url', (event, url) =>
  openUrlFromInternalFrame(isReadingListFrameSender(event), url));

// 稍后读删除：按 url 精确匹配，删除后落盘。
ipcMain.handle('readinglist-remove', (event, payload = {}) => {
  if (!isReadingListFrameSender(event)) return { ok: false, error: 'denied' };
  const url = typeof payload.url === 'string' ? payload.url : '';
  const before = readingList.length;
  readingList = readingList.filter(b => !(String(b.url || '') === url));
  if (readingList.length !== before) saveReadingList();
  return { ok: true, removed: before - readingList.length };
});

// 稍后读清空：整表清空并落盘。
ipcMain.handle('readinglist-clear', (event) => {
  if (!isReadingListFrameSender(event)) return { ok: false, error: 'denied' };
  const before = readingList.length;
  readingList = [];
  if (before > 0) saveReadingList();
  return { ok: true, removed: before };
});

// 关于页快照：版本 / 运行时 / 安全开关 / 跨主机连接台账汇总。
// 只放行 cosy://about 帧与主窗口外壳；不做任何网络请求，纯本地信息。
ipcMain.handle('about-snapshot', (event) => {
  if (!isAboutFrameSender(event)) return { ok: false, error: 'denied' };
  const stats = getRequestLogStats();
  const secEvents = listSecurityEvents('', 500);
  const secStats = { total: 0, critical: 0, warn: 0, info: 0, latest: [] };
  for (const e of secEvents) {
    secStats.total++;
    if (e.severity === 'critical') secStats.critical++;
    else if (e.severity === 'warn') secStats.warn++;
    else secStats.info++;
  }
  secStats.latest = secEvents.slice(0, 5).map(e => ({
    time: e.time, type: String(e.type || ''), severity: String(e.severity || 'info'),
    detail: String(e.detail || '').slice(0, 160),
  }));
  return {
    ok: true,
    info: {
      appName: 'OpenCosy',
      appVersion: typeof app.getVersion === 'function' ? app.getVersion() : '',
      userDataPath: app.getPath('userData'),
      internalPages: Object.keys(pageMap).length,
      electronVersion: process.versions.electron || '',
      chromiumVersion: process.versions.chrome || '',
      nodeVersion: process.versions.node || '',
      v8Version: process.versions.v8 || '',
      platform: process.platform || '',
      arch: process.arch || '',
      httpsOnly: httpsOnlyEnabled,
      httpsOnlyBlockInsecure: !!httpsOnlyEnabled,
      dnt: true,
      disableWebRTC: webrtcMode !== 'legacy',
      webrtcMode,
      httpsExceptions: typeof httpsExceptions.size === 'function' ? httpsExceptions.size() : 0,
      tabCount: Array.isArray(tabs) ? tabs.length : 0,
      bookmarkCount: Array.isArray(bookmarks) ? bookmarks.length : 0,
      stats: {
        hosts: Number(stats.hosts) || 0,
        requests: Number(stats.requests) || 0,
        blocked: Number(stats.blocked) || 0,
        backgroundHosts: Number(stats.backgroundHosts) || 0,
        insecureHosts: Number(stats.insecureHosts) || 0,
      },
      security: secStats,
    },
  };
});

// 关于页导出诊断 JSON：渲染层已本地生成纯文本，本端仅收口类型与长度，
// 弹保存框写盘。仅受信帧可触发。
ipcMain.handle('about-export-diagnostics', async (event, payload = {}) => {
  if (!isAboutFrameSender(event)) return { ok: false, error: 'denied' };
  try {
    const text = typeof payload.text === 'string' ? payload.text : '';
    if (text.length > 16 * 1024 * 1024) return { ok: false, error: 'too-large' };
    const stamp = new Date().toISOString().slice(0, 10);
    const result = await dialog.showSaveDialog(mainWindow, {
      title: '导出诊断信息',
      defaultPath: `opencosy-diagnostics-${stamp}.json`,
      filters: [{ name: 'JSON 文件', extensions: ['json'] }, { name: '所有文件', extensions: ['*'] }],
    });
    if (result.canceled || !result.filePath) return { ok: true, canceled: true };
    fsSync.writeFileSync(result.filePath, text, 'utf-8');
    return { ok: true, path: result.filePath };
  } catch (e) {
    console.error('导出诊断失败:', e);
    return { ok: false, error: e.message };
  }
});

// 快捷键速查页快照：导出规则表（动作 id + 键位 + 修饰键），供 cosy://shortcuts// 渲染。只放行内置帧；规则键值全部标量化，避免把内部对象引用暴露给页面。
ipcMain.handle('shortcuts-snapshot', (event) => {
  if (!isShortcutsFrameSender(event)) return { ok: false, error: 'denied', rules: [] };
  const rules = shortcutKeys.SHORTCUT_RULES.map(r => ({
    action: String(r.action || ''),
    key: String(r.key || ''),
    ctrl: r.ctrl === true ? 1 : r.ctrl === false ? 0 : null,
    shift: r.shift === true ? 1 : r.shift === false ? 0 : null,
    alt: r.alt === true ? 1 : r.alt === false ? 0 : null,
  }));
  return { ok: true, rules };
});

// 内部页导航快照：返回全部已登记内部页（名称 / 标题 / 说明），供 cosy://pages
// 渲染。只放行内置帧；标题说明为静态文案，名称经白名单校验后才可用于打开。
ipcMain.handle('pages-snapshot', (event) => {
  if (!isPagesFrameSender(event)) return { ok: false, error: 'denied', pages: [] };
  const pages = Object.keys(INTERNAL_PAGES).map(name => ({
    name,
    title: INTERNAL_PAGES[name].title,
    desc: INTERNAL_PAGES[name].desc,
  }));
  return { ok: true, pages };
});

// 内部页导航打开：只接受登记表内存在的页面名，白名单外一律拒绝（防止把任意
// 字符串拼进 cosy:// 后跳转到未注册地址）。新标签打开。
ipcMain.handle('pages-open', (event, payload = {}) => {
  if (!isPagesFrameSender(event)) return { ok: false, error: 'denied' };
  const name = typeof payload.name === 'string' ? payload.name : '';
  if (!INTERNAL_PAGES[name]) return { ok: false, error: 'unknown-page' };
  const tab = createNewTab('cosy://' + name);
  return { ok: true, id: tab.id, name };
});

ipcMain.handle('get-https-only', (event) => {
  if (!isMainSender(event)) return { success: false };
  return { success: true, enabled: httpsOnlyEnabled };
});

// HTTPS-Only 站点例外的查询与管理。来源校验交给 ipcGuard（仅受信 file/cosy 帧，
// 远程网页在主进程边界即被拒）；主机名一律经内核净化，非法输入返回 ok:false，
// 不接受路径 / 端口 / 控制字符。写操作落盘并向所有受信界面广播变更。
ipcMain.handle('list-https-exceptions', () => ({
  enabled: httpsOnlyEnabled,
  hosts: httpsExceptions.hosts(),
  size: typeof httpsExceptions.size === 'function' ? httpsExceptions.size() : 0,
  capacity: httpsExceptions.capacity || 0,
}));

ipcMain.handle('add-https-exception', (event, payload = {}) => {
  const host = httpsOnlyCore.normalizeExceptionHost(payload && payload.host);
  if (!host) return { ok: false, error: '主机名无效' };
  httpsExceptions.add(host);
  persistHttpsExceptions();
  sendToRenderer('https-exceptions-updated', { hosts: httpsExceptions.hosts() });
  return { ok: true, host };
});

ipcMain.handle('remove-https-exception', (event, payload = {}) => {
  const host = httpsOnlyCore.normalizeExceptionHost(payload && payload.host);
  if (!host) return { ok: false, error: '主机名无效' };
  const removed = httpsExceptions.remove(host);
  if (removed) {
    persistHttpsExceptions();
    sendToRenderer('https-exceptions-updated', { hosts: httpsExceptions.hosts() });
  }
  return { ok: true, removed };
});

ipcMain.handle('clear-https-exceptions', () => {
  httpsExceptions.clear();
  persistHttpsExceptions();
  sendToRenderer('https-exceptions-updated', { hosts: httpsExceptions.hosts() });
  return { ok: true };
});

ipcMain.handle('get-network-status', (event) => {
  if (!isMainSender(event)) return { success: false };
  return { success: true, online: net.isOnline() };
});

// 阅读页读取本次抽取结果（分级 COSY_ONLY，仅 cosy://reader 帧可调）。文章保留到
// 阅读标签关闭或下一次抽取，便于页面内切换字号 / 暗色后重建时重复取用。
ipcMain.handle('get-reader-article', () => {
  const article = readerArticle;
  return article || { ok: false, contentNodes: [] };
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

// ===== 自定义拦截规则 IPC =====
// 规则以字符串行表达：裸域名 / host:x / glob:https://*.x/* / path:https://x/ads/
// 所有写操作后立即持久化并重编译，webRequest 管道下一次判定即生效。
function customRulesSnapshot() {
  return {
    host: customRules.host.slice(),
    glob: customRules.glob.slice(),
    path: customRules.path.slice(),
    count: blockRules.ruleCount(customRules),
  };
}

ipcMain.handle('get-block-rules', (event) => {
  if (!isMainSender(event)) return { success: false };
  return { success: true, enabled: blockTrackers, rules: customRulesSnapshot() };
});

ipcMain.handle('add-block-rule', (event, raw) => {
  if (!isMainSender(event)) return { success: false };
  const res = blockRules.addRule(customRules, String(raw || ''));
  if (res.ok) {
    const saved = persistCustomRules();
    if (!saved.ok) return { success: false, ok: false, reason: saved.reason };
  }
  return { success: true, ...res, count: blockRules.ruleCount(customRules) };
});

ipcMain.handle('remove-block-rule', (event, raw) => {
  if (!isMainSender(event)) return { success: false };
  const removed = blockRules.removeRule(customRules, String(raw || ''));
  if (removed) persistCustomRules();
  return { success: true, removed, count: blockRules.ruleCount(customRules) };
});

ipcMain.handle('import-block-rules', (event, text) => {
  if (!isMainSender(event)) return { success: false };
  const res = blockRules.importRulesText(customRules, String(text || ''));
  const saved = persistCustomRules();
  if (!saved.ok) return { success: false, ...res, reason: saved.reason };
  return { success: true, ...res, count: blockRules.ruleCount(customRules) };
});

ipcMain.handle('export-block-rules', (event) => {
  if (!isMainSender(event)) return { success: false };
  return { success: true, text: blockRules.exportRulesText(customRules) };
});

ipcMain.handle('clear-block-rules', (event) => {
  if (!isMainSender(event)) return { success: false };
  customRules.host = [];
  customRules.glob = [];
  customRules.path = [];
  persistCustomRules();
  return { success: true, count: 0 };
});

// ===== 保险库 IPC =====
// 写操作（创建/解锁/写入/删除）均走 COSY_ONLY 分级（见 channelpolicy）；读快照走
// GENERAL。任何 handler 都不回传密文与主密钥。
// vaultPasswordOK：主进程侧主密码收口校验（渲染层另有 UI 限制，此处纵深防御）。
// 规则：必须是字符串；1~256 个可见字符；不含控制字符/NUL；非纯空白；
// UTF-8 编码后不超过 1024 字节，防止超长输入拖垮 PBKDF2 慢化造成 DoS。
function vaultPasswordOK(pw) {
  if (typeof pw !== 'string') return false;
  if (pw.length < 1 || pw.length > 256) return false;
  if (/[\x00-\x1f\x7f]/.test(pw)) return false;
  if (/^\s*$/.test(pw)) return false;
  try {
    return Buffer.byteLength(pw, 'utf8') <= 1024;
  } catch {
    return false;
  }
}

ipcMain.handle('vault-status', (event) => {
  if (!isMainSender(event)) return { success: false };
  return { success: true, ...vaultStatusSnapshot() };
});

ipcMain.handle('vault-create', (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false };
  const pw = typeof payload === 'string' ? payload : (payload && payload.masterPassword);
  if (!vaultPasswordOK(pw)) return { success: false, reason: 'bad-password' };
  return { success: true, ...createNewVault(pw) };
});

ipcMain.handle('vault-unlock', (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false };
  const pw = typeof payload === 'string' ? payload : (payload && payload.masterPassword);
  if (!vaultPasswordOK(pw)) return { success: false, reason: 'bad-password' };
  return { success: true, ...unlockVault(pw) };
});

ipcMain.handle('vault-lock', (event) => {
  if (!isMainSender(event)) return { success: false };
  if (vaultHandle) vaultHandle.lock();
  vaultHandle = null;
  return { success: true, ...vaultStatusSnapshot() };
});

ipcMain.handle('vault-list', (event) => {
  if (!isMainSender(event)) return { success: false };
  if (!vaultHandle || vaultHandle.locked()) return { success: false, reason: 'locked' };
  return { success: true, ...vaultHandle.list() };
});

ipcMain.handle('vault-get', (event, id) => {
  if (!isMainSender(event)) return { success: false };
  if (!vaultHandle || vaultHandle.locked()) return { success: false, reason: 'locked' };
  const g = vaultHandle.get(String(id || ''));
  if (!g.ok) return { success: false, reason: g.reason };
  return { success: true, payload: g.payload, ...(vaultHandle.list().ok ? { label: vaultHandle.list().entries.find((e) => e.id === id)?.label } : {}) };
});

ipcMain.handle('vault-set', (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false };
  if (!vaultHandle || vaultHandle.locked()) return { success: false, reason: 'locked' };
  const r = vaultHandle.set(String(payload.kind || ''), String(payload.label || ''), payload.payload);
  if (r.ok) persistVaultState();
  return { success: true, ...r };
});

ipcMain.handle('vault-update', (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false };
  if (!vaultHandle || vaultHandle.locked()) return { success: false, reason: 'locked' };
  const r = vaultHandle.update(String(payload.id || ''), String(payload.kind || ''),
    String(payload.label || ''), payload.payload);
  if (r.ok) persistVaultState();
  return { success: true, ...r };
});

ipcMain.handle('vault-delete', (event, id) => {
  if (!isMainSender(event)) return { success: false };
  if (!vaultHandle || vaultHandle.locked()) return { success: false, reason: 'locked' };
  const r = vaultHandle.delete(String(id || ''));
  if (r.ok) persistVaultState();
  return { success: true, ...r };
});

// vault-rekey：修改主密码。传主密码 → PBKDF2 慢化重包裹；留空 → 生成新随机密钥
// 并重新写回系统安全存储。任一条目解密失败会整体中止，保持原状态。
ipcMain.handle('vault-rekey', (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false };
  if (!vaultHandle || vaultHandle.locked()) return { success: false, reason: 'locked' };
  const pw = typeof payload === 'string' ? payload : (payload && payload.masterPassword);
  let key;
  let kdf;
  if (typeof pw === 'string' && pw.length > 0) {
    if (!vaultPasswordOK(pw)) return { success: false, reason: 'bad-password' };
    key = Buffer.from(pw, 'utf8');
    kdf = vaultCore.KDF_PBKDF2;
    vaultUsePasswordMode = true;
  } else {
    if (!safeStorage.isEncryptionAvailable()) {
      return { success: false, reason: 'password-required' };
    }
    key = crypto.randomBytes(32);
    kdf = vaultCore.KDF_HKDF;
    vaultUsePasswordMode = false;
  }
  const rr = vaultHandle.rekey(key, { kdf });
  if (!rr.ok) return { success: false, reason: rr.reason };
  persistVaultState();
  const keyPersisted = vaultUsePasswordMode ? true : persistVaultKey(key);
  return { success: true, keyPersisted, ...rr, ...vaultStatusSnapshot() };
});

// vault-export-backup：返回密文 JSON 文本（不含密钥/明文），供用户自行保存。
ipcMain.handle('vault-export-backup', (event) => {
  if (!isMainSender(event)) return { success: false };
  if (!vaultHandle || vaultHandle.locked()) return { success: false, reason: 'locked' };
  const ex = vaultHandle.exportState();
  if (!ex.ok) return { success: false, reason: ex.reason };
  return { success: true, backup: JSON.stringify(ex.state) };
});

// vault-import-backup：合并同一主密钥包裹的备份密文；格式/密钥不匹配整体拒绝。
ipcMain.handle('vault-import-backup', (event, text) => {
  if (!isMainSender(event)) return { success: false };
  if (!vaultHandle || vaultHandle.locked()) return { success: false, reason: 'locked' };
  let state;
  try {
    state = JSON.parse(String(text || ''));
  } catch {
    return { success: false, reason: 'bad-state' };
  }
  const rr = vaultHandle.mergeFromState(state);
  if (rr.ok) persistVaultState();
  return { success: true, ...rr };
});

// ===== 站点数据清理 IPC =====
// 流程固定为：枚举 → 规划（纯函数）→ 用户确认 plan → 执行 → 审计。
// 执行只接受 filterSiteEntries 产出的 plan 对象（含 targets 白名单）。
ipcMain.handle('cleaner-enumerate', async (event) => {
  if (!isMainSender(event)) return { success: false };
  return { success: true, ...enumerateSiteStorage() };
});

ipcMain.handle('cleaner-plan', (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false };
  const src = enumerateSiteStorage();
  const filtered = cleanerCore.filterSiteEntries(src.entries, {
    matchMode: payload.matchMode,
    host: payload.host,
    since: payload.since,
    storageTypes: payload.storageTypes,
  });
  if (!filtered.ok) return { success: false, ...filtered };
  return {
    success: true,
    ...filtered,
    storageTypes: payload.storageTypes || [],
    ...cleanerCore.summarizePlan(filtered, payload.actions || []),
  };
});

ipcMain.handle('cleaner-execute', async (event, plan) => {
  if (!isMainSender(event)) return { success: false };
  const res = await executeCleanPlan(plan);
  return { success: true, ...res };
});

ipcMain.handle('cleaner-audit', (event) => {
  if (!isMainSender(event)) return { success: false };
  return { success: true, entries: cleanAuditLog.slice() };
});

ipcMain.handle('cleaner-prune-audit', (event, keep) => {
  if (!isMainSender(event)) return { success: false };
  const r = cleanerCore.pruneAuditLog(cleanAuditLog, Number(keep) || 0);
  if (r.ok) persistCleanAudit();
  return { success: true, ...r };
});

// ===== UA 覆盖策略 IPC =====
// get-ua-policy：返回当前策略、改写统计与生效 UA（含 default 时的自算值），
// 供 cosy://privacy 页展示。set/reset 都会持久化并立刻应用到 defaultSession
// （隔离会话下一次请求时也会吃到新策略，因为 resolveEffectiveUa 每次现算）。
ipcMain.handle('get-ua-policy', (event) => {
  if (!isMainSender(event)) return { success: false };
  return {
    success: true,
    ...uaPolicyCore.policyToPlain(uaPolicyState),
    effectiveUa: resolveEffectiveUa(),
    overrideCount: uaOverrideCount,
    lastOverrideAt: uaLastOverrideAt,
  };
});

ipcMain.handle('set-ua-policy', (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false };
  const next = uaPolicyCore.sanitizePolicy(payload);
  uaPolicyState = next;
  persistUaPolicyState();
  applyUaPolicyToSession(session.defaultSession);
  return {
    success: true,
    ...uaPolicyCore.policyToPlain(uaPolicyState),
    effectiveUa: resolveEffectiveUa(),
  };
});

ipcMain.handle('reset-ua-policy', (event) => {
  if (!isMainSender(event)) return { success: false };
  uaPolicyState = { ...uaPolicyCore.DEFAULT_POLICY };
  uaOverrideCount = 0;
  uaLastOverrideAt = 0;
  persistUaPolicyState();
  applyUaPolicyToSession(session.defaultSession);
  return { success: true, ...uaPolicyCore.policyToPlain(uaPolicyState), effectiveUa: resolveEffectiveUa() };
});

// 随机预览一条 Chrome UA（只展示不改状态）：从内置池随机取。
// 仅主窗口可调用。
ipcMain.handle('preview-random-ua', (event) => {
  if (!isMainSender(event)) return { success: false };
  const pool = uaPolicyCore && Array.isArray(uaPolicyCore.COMMON_CHROME_UAS) ? uaPolicyCore.COMMON_CHROME_UAS : [];
  if (pool.length === 0) return { success: false, reason: 'empty-pool' };
  const ua = uaPolicyCore.pickRandomChromeUa();
  return { success: true, ua: String(ua || '') };
});

// ===== 下载限速 IPC =====
ipcMain.handle('get-security-posture', (event) => {
  if (!isMainSender(event)) return { ok: false };
  const decisions = listPermissionDecisions();
  const riskyOrigins = new Set();
  for (const decision of decisions) {
    if (decision.state !== permissionGrants.STATE.ALLOW) continue;
    if ((permissionGrants.HIGH_RISK_WEIGHT[decision.permission] || 0) >= 2) riskyOrigins.add(decision.origin);
  }
  let criticalEvents = 0;
  for (const item of listSecurityEvents('', 200)) {
    if (item.severity === 'critical') criticalEvents += 1;
  }
  const cspStats = getCspReportStats();
  const headerStats = getHeaderGradeStats();
  loadCertExceptions();
  const report = securityPosture.scorePosture({
    httpsOnly: httpsOnlyEnabled,
    blockRules: (compiledCustomRules.host ? compiledCustomRules.host.size : 0)
      + (compiledCustomRules.glob ? compiledCustomRules.glob.length : 0)
      + (compiledCustomRules.path ? compiledCustomRules.path.length : 0),
    cspReports: Number(cspStats.totalHits) || 0,
    certExceptions: certExceptions.length,
    riskyOrigins: riskyOrigins.size,
    criticalEvents,
    headerGrades: headerStats.byGrade,
    expiredGrants: decisions.filter((decision) => decision.state === permissionGrants.STATE.EXPIRED).length,
  });
  return {
    ok: true,
    report,
    description: securityPosture.describePosture(report),
    worst: securityPosture.worstSeverity(report),
  };
});

ipcMain.handle('get-download-journal-export', (event, payload = {}) => {
  if (!isMainSender(event)) return { ok: false };
  const requested = Number.isInteger(payload.limit) && payload.limit > 0 ? payload.limit : downloadJournalModule.DEFAULT_MAX_ENTRIES;
  const entries = getDownloadJournal().snapshot().slice(0, requested);
  const exported = downloadJournalExport.buildJournalExport(entries);
  return {
    ok: true,
    export: exported,
    description: downloadJournalExport.describeExport(exported),
    leaked: downloadJournalExport.exportContainsLocalPaths(exported),
  };
});

ipcMain.handle('get-permission-risk-report', (event, payload = {}) => {
  if (!isMainSender(event)) return { ok: false };
  const requested = Number.isInteger(payload.limit) && payload.limit > 0 ? payload.limit : 50;
  const report = permissionRiskReport.buildPermissionReport(listPermissionDecisions(), { limit: requested });
  return {
    ok: true,
    report,
    description: permissionRiskReport.describePermissionReport(report),
    attention: permissionRiskReport.needsAttention(report),
  };
});

ipcMain.handle('get-download-rate-limit', (event) => {
  if (!isMainSender(event)) return { success: false };
  return { success: true, bytesPerSecond: downloadRateLimit, kbps: Math.round(downloadRateLimit / 1024) };
});

ipcMain.handle('set-download-rate-limit', (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false };
  const raw = Number(payload && payload.bytesPerSecond);
  if (!Number.isFinite(raw) || raw < 0) return { success: false, reason: 'invalid-rate' };
  downloadRateLimit = Math.floor(Math.min(raw, 1024 * 1024 * 1024)); // 封顶 1 GiB/s
  persistRateLimitState();
  // 已在进行中的下载项逐个应用新限速（未开始的在 will-download 时套用）。
  for (const d of downloads) {
    if (d.item && d.isItemValid) applyRateLimitToItem(d.item);
  }
  return { success: true, bytesPerSecond: downloadRateLimit };
});

ipcMain.handle('get-download-max-bytes', (event) => {
  if (!isMainSender(event)) return { success: false };
  return { success: true, bytes: downloadMaxBytes };
});

ipcMain.handle('set-download-max-bytes', (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false };
  const raw = Number(payload && payload.bytes);
  if (!Number.isFinite(raw) || raw < 0) return { success: false, reason: 'invalid-limit' };
  downloadMaxBytes = downloadSizeGuard.normalizeLimit(raw);
  try {
    const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
    const cur = ledgerStore.readJSONStore(settingsPath, {});
    ledgerStore.writeJSONStore(settingsPath, sanitizeSettings(Object.assign({}, cur, { downloadMaxBytes })), { pretty: true });
  } catch (e) { console.error('保存下载体积上限失败:', e); }
  return { success: true, bytes: downloadMaxBytes };
});

ipcMain.handle('get-download-journal', (event, payload = {}) => {
  const requested = Number.isInteger(payload.limit) && payload.limit > 0 ? payload.limit : 50;
  const limit = Math.min(requested, downloadJournalModule.DEFAULT_MAX_ENTRIES);
  return getDownloadJournal().snapshot().slice(0, limit).map((entry) => ({
    id: entry.id,
    filename: entry.filename,
    host: entry.host,
    totalBytes: entry.totalBytes,
    receivedBytes: entry.receivedBytes,
    state: entry.state,
    startedAt: entry.startedAt,
    updatedAt: entry.updatedAt,
    resumable: entry.resumable === true,
    resumeReason: entry.resumeReason,
    resumeOffset: entry.resumeOffset,
    fileCheck: entry.fileCheck || downloadReconcileModule.VERDICT.SKIPPED,
    fileCheckReason: downloadReconcileModule.describeVerdict(entry.fileCheck || downloadReconcileModule.VERDICT.SKIPPED),
    fileBytes: Number.isFinite(entry.fileBytes) ? entry.fileBytes : null,
  }));
});

ipcMain.handle('reconcile-download-journal', (event) => {
  if (!isMainSender(event)) return { success: false };
  const result = getDownloadJournal().reconcile(downloadJournalFileProbe());
  return {
    success: result.ok,
    summary: result.summary,
    description: downloadReconcileModule.summarizeReconcile(result.summary),
    changes: result.changes.length,
  };
});

ipcMain.handle('clear-download-journal', () => getDownloadJournal().clear());

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
      return hostMatch.hostEqualsOrSubdomain(d, domain);
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
      return hostMatch.hostEqualsOrSubdomain(d, domain);
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

// 地址栏搜索建议：端点来自 searchprovider 内置白名单（随默认搜索引擎切换），
// 不接受 renderer 传入的任意 URL，避免被当成 SSRF 跳板。返回严格限定为
// 字符串数组并限量。
const SUGGEST_MAX_CHARS = 200;
const SUGGEST_MAX_ITEMS = 8;
const SUGGEST_TIMEOUT_MS = 2500;

// 当前生效的默认搜索引擎 id；随 cosySettings.searchEngine 加载/保存，未知值
// 一律回落内核默认（bing）。
let searchProviderId = searchProvider.DEFAULT_PROVIDER_ID;



ipcMain.handle('get-search-suggestions', async (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false, suggestions: [] };
  const q = typeof payload.q === 'string' ? payload.q.trim() : '';
  if (!q || q.length > SUGGEST_MAX_CHARS) return { success: false, suggestions: [] };
  // 已经是完整 URL / 内置协议时不给搜索建议，交给历史/书签补全。
  if (/^[a-z][a-z0-9+.-]*:/i.test(q) || q.startsWith('//')) return { success: true, suggestions: [] };
  const suggestions = await fetchSearchSuggestions(q);
  return { success: true, suggestions };
});

// —— 默认搜索引擎（searchprovider 内核）——
ipcMain.handle('get-search-provider', (event) => {
  if (!isMainSender(event)) return { success: false };
  return {
    success: true,
    providerId: searchProviderId,
    providers: searchProvider.providerSummary(),
    defaultId: searchProvider.DEFAULT_PROVIDER_ID,
  };
});

ipcMain.handle('set-search-provider', (event, payload = {}) => {
  if (!isMainSender(event)) return { success: false };
  const id = typeof payload === 'string' ? payload : (payload && payload.providerId);
  const chosen = searchProvider.sanitizeProviderChoice(id);
  // 未知 id 被收敛回默认：此时不落盘（脏数据不污染设置），仅返回当前值。
  if (chosen === id || id === searchProvider.DEFAULT_PROVIDER_ID) {
    searchProviderId = chosen;
    try {
      const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
      const cur = ledgerStore.readJSONStore(settingsPath, {});
      const clean = sanitizeSettings(Object.assign({}, cur, { searchEngine: chosen }));
      ledgerStore.writeJSONStore(settingsPath, clean, { pretty: true });
      recordSecurityEvent('settings-search-provider', 'info',
        `默认搜索引擎切换为 ${chosen}`, 'main');
    } catch (e) {
      recordSecurityEvent('settings-search-provider', 'warn',
        `搜索引擎设置落盘失败: ${e.message}`, 'main');
    }
  }
  return { success: true, providerId: searchProviderId };
});
