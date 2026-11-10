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
const {
	noteGuardResult,
	noteGuardDenied,
	allowPopupForTab,
	getContentsState,
	reloadCustomRules,
	loadCustomRulesFromDisk,
	persistCustomRules,
	hostMatchesTracker,
	isTrackerRequest,
	recordBlockedTracker,
	topBlockedHosts,
	isTrackingQueryKey,
	stripTrackingFromUrl,
	hostnameHasSuspiciousChars,
	analyzeHostForSpoof,
	originOf,
	sanitizeSpellcheckLanguages,
	applySpellcheckSettings,
	readPersistedSettings,
	isMainSender,
	isInternalFileFrame,
	sendToRenderer,
	shelfSnapshot,
	sendShelf,
	downloadsStorePath,
	persistDownloads,
	notifyDownloadResult,
	getSafeDirs,
	isInSafeDirs,
	getHttpStatusCode,
	getErrorMessage,
	getBrowserErrorText,
	isSafeUrl,
	sanitizePath,
	isPathInDir,
	realpathForContainment,
	isValidColor,
	getCurrentTabWebContents,
	toggleDevTools,
	goHome,
	addToHistory,
	saveHistory,
	loadHistory,
	saveBookmarks,
	loadBookmarks,
	saveReadingList,
	loadReadingList,
	saveSession,
	loadSession,
	clearSession,
	addToRecentlyClosed,
	getLastClosedTab,
	isPrivateNetworkHost,
	readStoredSettings,
	loadHttpsExceptions,
	persistHttpsExceptions,
	isHttpExceptionHost,
	loadUaPolicyStateFromDisk,
	persistUaPolicyState,
	persistRateLimitState,
	applyUaPolicyToSession,
	resolveEffectiveUa,
	applyRateLimitToItem,
	atomicWriteJSON,
	loadVaultStateFromDisk,
	persistVaultState,
	persistCleanAudit,
	persistVaultKey,
	maybeFallbackAfterUpgradeFailure,
	applyDarkMode,
	loadPnaLedger,
	persistPnaLedger,
	pnaLedgerStats,
	recordPnaBlock,
	loadFpLedger,
	persistFpLedger,
	applyWebRtcPolicy,
	loadDohLedger,
	persistDohLedger,
	dohStatus,
	applyWebRequestFiltering,
	originOfContents,
	persistHeaderGrades,
	listHeaderGrades,
	clearHeaderGrades,
	getHeaderGradeStats,
	loadRequestLog,
	persistRequestLog,
	listRequestLogEntries,
	getRequestLogStats,
	clearRequestLog,
	persistBrandSpoofs,
	listBrandSpoofEntries,
	getBrandSpoofStats,
	clearBrandSpoofs,
	loadClientCertChoices,
	persistClientCertChoices,
	rejectAuthChallenge,
	getClientCertChoiceStats,
	setupNetworkStatus,
	setupSystemEventGuards,
	setupExtraSessionHardening,
	getTabLayout,
	getDefaultTabUrl,
	createWindow,
	registerShortcuts,
	getUrlProtocol,
	openTaskManagerTab,
	openTabOverviewTab,
	showErrorPage,
	pushNavState,
	recordCrash,
	canAutoRecover,
	destroyTabView,
	rebuildCrashedTab,
	handleRenderProcessGone,
	discardTab,
	reloadDiscardedTab,
	sweepDiscardableTabs,
	startMemorySaver,
	discardAllBackgroundTabs,
	buildTabPidMap,
	loadTabContent,
	showCosyError,
	savePinsNow,
	persistPins,
	loadStoredPins,
	clearStoredPins,
	findTabIndexById,
	broadcastPinnedState,
	applyPinnedState,
	movePinnedTabsToFront,
	pinTab,
	unpinTab,
	toggleTabPinned,
	rehydratePinnedTabs,
	ensurePinnedTabsOpened,
	closeTabsByIds,
	planAndCloseTabs,
	rehydrateTabGroups,
	sanitizeDownloadFilename,
	resolveUniqueDownloadPath,
	rememberDownloadOrigin,
	persistDownloadRisks,
	recordDownloadRisk,
	listDownloadRisks,
	clearDownloadRisks,
	analyzeDownloadSafety,
	handleDownloadEvent,
	downloadJournalFileProbe,
	attachDownloadManager,
	setupDownloadManager,
	formatSpeed,
	reviewToOpenUrl,
	resolveStartupDeepLink,
	resolveStartupArgv,
	originOfUrl,
	applyFind,
	createContextMenu,
	sanitizeSettings,
	sanitizeBookmarkLike,
	openUrlFromInternalFrame,
	addToReadingList,
	customRulesSnapshot,
	vaultPasswordOK,
} = require('./cosymaindelegates');

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

// hostMatchesTracker 判断主机是否为已知追踪域（精确或其子域）。
// 归一化（小写/去尾点）与精确-子域边界判断统一由 hostmatch 内核负责，
// 避免与 Cookie 归属、私网判定各写一套口径。

// isTrackerRequest 只拦子资源，顶层框架 / iframe 框架文档一律放行，避免误伤导航。
// 自定义规则优先（decideBlocked 先查 host/glob/path），内置列表兜底。

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

// 返回剥离追踪参数后的 URL；没有可删参数时返回 null（调用方据此避免无谓重定向）。

// ===== 同形异义（homograph / IDN）反钓鱼提示 =====
// 只“提示”不拦截：对包含非 ASCII（含西里尔/希腊等与拉丁形近的字符）或易混拉丁字符、
// 且非用户常用站点的主机，发横幅让用户留意，地址栏仍照常显示，避免误伤合法国际化域名。
const SKEW_LATIN_HOSTS = new Set([
  'google', 'youtube', 'facebook', 'amazon', 'apple', 'microsoft', 'github',
  'twitter', 'x', 'instagram', 'netflix', 'paypal', 'alibaba', 'taobao',
  'baidu', 'bing', 'office', 'live', 'steam', 'epicgames',
]);

// 主机里只要出现这些码位就视为“可能在冒充拉丁字母”。

// ===== Referrer 收敛（默认 strict-origin-when-cross-origin 语义）=====
// 网页自己的 <meta name=referrer> / 页面策略由 Chromium 处理；这里兜底修正 Electron
// 可能仍带“完整来路 URL（含查询/路径）”的情况，避免把上个页面的敏感路径、搜索词、
// token 经 Referer 头泄露给第三方：
//   - 同源：保留完整 Referer；
//   - 跨源且安全等级不降低：收敛为源（origin/）；
//   - https → http 降级：直接去除 Referer。

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

// applySpellcheckSettings 把当前拼写检查开关 / 语言应用到默认会话。
// 每次保存设置都会重新调用；语言列表只保留当前平台真正可用的词典。

// readPersistedSettings 在 app 启动早期同步读取已保存的设置，
// 让拼写检查这类需要在第一个页面加载前生效的偏好不必等渲染层来取。

const isDev = !app.isPackaged;

// 判断一个 file: 帧是否为“应用自带的内置静态页”（如 tab 视图加载的 src/error.html、
// src/download/index.html）。这些页物理上位于安装目录 __dirname 内；用户在标签里
// 打开的任意本地 html（D:\xxx.html）在目录外，必须按不可信帧处理。

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

// ===== 底部下载栏（download shelf）=====
// 现代浏览器在窗口底部用一条 shelf 展示下载进度，不必每次下载都新开标签页打断浏览。
// 主进程只推送可序列化的快照给主界面；DownloadItem 等 Electron 对象绝不跨进程暴露。
// 快照构建与字段净化收口到 downloadshelf 内核：剥控制字符/ANSI、按字节截断、
// 状态白名单、进度 clamp、savePath 只留存在性标记、附带整张台账的统计角标。
const MAX_SHELF_ITEMS = 3;

// ===== 下载记录持久化（downloads.json）=====
// 下载台账此前只活在内存里，重启即丢。这里落盘到 userData/downloads.json：
// 写入前每条记录过 downloadshelf 内核净化（剥控制字符/ANSI、字段白名单、
// savePath 显式校验），读取时同源净化并约束条数，防止被外部程序写坏的
// 文件把危险字段灌回运行时。落盘走 ledgerStore 原子写，失败只记审计事件，
// 不阻断下载流程。
const MAX_PERSISTED_DOWNLOADS = 500;

// ===== 下载系统通知（downloadnotify 内核的 Electron 接线）=====
// 窗口最小化 / 失焦时用户看不到底部下载栏，完成与失败都要弹系统通知（Chrome、
// Edge 同款行为）。通知内容已由 downloadnotify 内核净化：剥控制字符与 CSI 序列、
// 按字节截断、不落完整本地路径、失败不给原始异常，这里只把内核产出接到 Electron
// Notification 与点击动作上（完成点开文件，失败只聚焦窗口并留给用户显式重试）。

// notifyDownloadResult 把一次下载结果接成系统通知；通知失败只审计，不打断下载流程。

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

// saveReadingList 写稍后读列表：复用 bookmarkGuard 的净化口径（仅 http/https、
// title 去控制字符并限长、按 url 去重），与书签同款有界落盘。

// readStoredSettings 只读不校验，启动时用来还原 darkMode / httpsOnly 等运行时状态。
// 校验交给 save-settings 里的 sanitizeSettings。

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

// isHttpExceptionHost 供请求管道与回退逻辑共用，输入可以是 URL 或主机名。

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

// applyUaPolicyToSession：把当前策略应用到目标 session（导航级 UA）。
// webRequest 层的按请求改写由 applyOutboundHeaderHardening 负责；这里只在
// 启动与策略变更时调用，让导航请求也吃到最新 UA。

// resolveEffectiveUa 是 webRequest 层每次请求都读取的 UA 取值器。

// applyRateLimitToItem：对新下载项套限速（0 表示不限，setRate 无效时不抛）。

let atomicWriteSeq = 0;

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

// applyDarkMode 切 Chromium 原生暗色主题，影响滚动条、文件对话框、DevTools 外壳。
// renderer 的 CSS 暗色由 settings-loaded 自己管，这里只管原生 UI。

// ===== Set-Cookie 加固台账（cookie-hardening.json / cosy://security 面板）=====
// 纯判定在 cookieguard.js；这里负责在 onHeadersReceived 里应用改写、聚合落盘，
// 并把“被剥离的 Cookie”登记到安全事件。SameSite 补全这类静默改写只进台账、
// 不刷安全事件列表，避免正常网站产生大量噪音。
const cookieLedgerStorePath = path.join(app.getPath('userData'), 'cookie-hardening.json');
const MAX_COOKIE_LEDGER = 500;
const cookieLedger = cookieGuard.createCookieLedger(MAX_COOKIE_LEDGER);
let cookieLedgerLoaded = false;
let cookieLedgerSaveTimer = null;

// ===== PNA 私有网络访问拦截台账（pna-access.json / cosy://security 面板）=====
const pnaLedgerStorePath = path.join(app.getPath('userData'), 'pna-access.json');
const MAX_PNA_LEDGER = 300;
const pnaLedger = new Map(); // host -> { host, space, hits, lastTime, types:Set-as-map }
let pnaLedgerLoaded = false;
let pnaLedgerSaveTimer = null;

// ===== 指纹 / 跨站追踪收敛台账（fp-leaks.json / cosy://security 面板）=====
const fpLedgerStorePath = path.join(app.getPath('userData'), 'fp-leaks.json');
const MAX_FP_LEDGER = 500;
const fpLedger = fpGuard.createFingerprintLedger(MAX_FP_LEDGER);
let fpLedgerLoaded = false;
let fpLedgerSaveTimer = null;

// recordFpHit 按主机+类别登记一条被收敛的指纹/追踪信号。

// applyCookieHardening 就地加固响应头里的 Set-Cookie，返回本次动作列表。
// 任何异常都不阻断浏览：出错时保留原始响应头。

// ===== 安全 DNS（DoH）状态与落盘 =====
const dohStorePath = path.join(app.getPath('userData'), 'doh-status.json');
const dohLedger = dohGuard.createDohLedger(200);
let dohLedgerLoaded = false;
let dohSaveTimer = null;

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

// recordHeaderGrade 对一次顶层文档响应评级并按 host 聚合。纯计算，不抛错。

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

// recordRequestAttempt 由 onBeforeRequest 调用；任何异常都不影响浏览。

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

// recordBrandSpoof 由 onBeforeRequest 顶层导航调用；入参来自纯模块，仍重新白名单化，
// 防止脏数据写盘。任何异常都不影响浏览。

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
const cosyipcwire4Mod = require('./cosyipcwire4');
cosyipcwire4Mod.bindDeps({
    get addCertException() { return addCertException; },
    get app() { return app; },
    get certExceptionAllowed() { return certExceptionAllowed; },
    get certGuard() { return certGuard; },
    get clearCertExceptions() { return clearCertExceptions; },
    get consumeCertChallenge() { return consumeCertChallenge; },
    get getCertExceptionStats() { return getCertExceptionStats; },
    get ipcMain() { return ipcMain; },
    get listCertExceptionEntries() { return listCertExceptionEntries; },
    get makeCertChallenge() { return makeCertChallenge; },
    get removeCertException() { return removeCertException; },
    get sendToRenderer() { return sendToRenderer; },
    get webContents() { return webContents; },
});
cosyipcwire4Mod.installCertificateErrorHandler();

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

// failAuthCallback 在“不弹框 / 超时 / 窗口关闭”等路径上安全地兑现一个空凭据，
// 让请求以未认证失败，而不是卡住或回退到系统默认行为。

// sanitizeCertPickList 只把证书的非敏感摘要给渲染层，绝不传证书对象本体。

// 渲染层提交账号口令。只接受主界面，且 nonce 必须仍在待处理表里。
const cosyipcregisterMod = require('./cosyipcregister');
cosyipcregisterMod.bindDeps({ get ALLOWED_SPELLCHECK_LANGUAGES() { return ALLOWED_SPELLCHECK_LANGUAGES; }, set ALLOWED_SPELLCHECK_LANGUAGES(v) { ALLOWED_SPELLCHECK_LANGUAGES = v; }, get INTERNAL_PAGES() { return INTERNAL_PAGES; }, set INTERNAL_PAGES(v) { INTERNAL_PAGES = v; }, get addToReadingList() { return addToReadingList; }, set addToReadingList(v) { addToReadingList = v; }, get allowPictureInPicture() { return allowPictureInPicture; }, set allowPictureInPicture(v) { allowPictureInPicture = v; }, get app() { return app; }, set app(v) { app = v; }, get applyDarkMode() { return applyDarkMode; }, set applyDarkMode(v) { applyDarkMode = v; }, get applyRateLimitToItem() { return applyRateLimitToItem; }, set applyRateLimitToItem(v) { applyRateLimitToItem = v; }, get applySecureDns() { return applySecureDns; }, set applySecureDns(v) { applySecureDns = v; }, get applySpellcheckSettings() { return applySpellcheckSettings; }, set applySpellcheckSettings(v) { applySpellcheckSettings = v; }, get applyUaPolicyToSession() { return applyUaPolicyToSession; }, set applyUaPolicyToSession(v) { applyUaPolicyToSession = v; }, get applyWebRtcPolicy() { return applyWebRtcPolicy; }, set applyWebRtcPolicy(v) { applyWebRtcPolicy = v; }, get authLimiter() { return authLimiter; }, set authLimiter(v) { authLimiter = v; }, get authStats() { return authStats; }, set authStats(v) { authStats = v; }, get blockAdSignals() { return blockAdSignals; }, set blockAdSignals(v) { blockAdSignals = v; }, get blockHyperlinkPing() { return blockHyperlinkPing; }, set blockHyperlinkPing(v) { blockHyperlinkPing = v; }, get blockLocalNetworkAccess() { return blockLocalNetworkAccess; }, set blockLocalNetworkAccess(v) { blockLocalNetworkAccess = v; }, get blockThirdPartyCookies() { return blockThirdPartyCookies; }, set blockThirdPartyCookies(v) { blockThirdPartyCookies = v; }, get blockTrackers() { return blockTrackers; }, set blockTrackers(v) { blockTrackers = v; }, get blockedTrackerByHost() { return blockedTrackerByHost; }, set blockedTrackerByHost(v) { blockedTrackerByHost = v; }, get blockedTrackerCount() { return blockedTrackerCount; }, set blockedTrackerCount(v) { blockedTrackerCount = v; }, get bookmarkBarVisible() { return bookmarkBarVisible; }, set bookmarkBarVisible(v) { bookmarkBarVisible = v; }, get bookmarkIO() { return bookmarkIO; }, set bookmarkIO(v) { bookmarkIO = v; }, get bookmarks() { return bookmarks; }, set bookmarks(v) { bookmarks = v; }, get certExceptions() { return certExceptions; }, set certExceptions(v) { certExceptions = v; }, get cleanAuditLog() { return cleanAuditLog; }, set cleanAuditLog(v) { cleanAuditLog = v; }, get cleanerCore() { return cleanerCore; }, set cleanerCore(v) { cleanerCore = v; }, get clearOnExit() { return clearOnExit; }, set clearOnExit(v) { clearOnExit = v; }, get clientCertStore() { return clientCertStore; }, set clientCertStore(v) { clientCertStore = v; }, get compiledCustomRules() { return compiledCustomRules; }, set compiledCustomRules(v) { compiledCustomRules = v; }, get confirmCloseMultiple() { return confirmCloseMultiple; }, set confirmCloseMultiple(v) { confirmCloseMultiple = v; }, get cookieLedger() { return cookieLedger; }, set cookieLedger(v) { cookieLedger = v; }, get crashRecoveryEnabled() { return crashRecoveryEnabled; }, set crashRecoveryEnabled(v) { crashRecoveryEnabled = v; }, get crashReloadCounts() { return crashReloadCounts; }, set crashReloadCounts(v) { crashReloadCounts = v; }, get createNewTab() { return createNewTab; }, set createNewTab(v) { createNewTab = v; }, get createNewVault() { return createNewVault; }, set createNewVault(v) { createNewVault = v; }, get crypto() { return crypto; }, set crypto(v) { crypto = v; }, get dialog() { return dialog; }, set dialog(v) { dialog = v; }, get dohCustomUrl() { return dohCustomUrl; }, set dohCustomUrl(v) { dohCustomUrl = v; }, get dohGuard() { return dohGuard; }, set dohGuard(v) { dohGuard = v; }, get dohLedger() { return dohLedger; }, set dohLedger(v) { dohLedger = v; }, get dohMode() { return dohMode; }, set dohMode(v) { dohMode = v; }, get dohProvider() { return dohProvider; }, set dohProvider(v) { dohProvider = v; }, get dohStatus() { return dohStatus; }, set dohStatus(v) { dohStatus = v; }, get downloadJournalExport() { return downloadJournalExport; }, set downloadJournalExport(v) { downloadJournalExport = v; }, get downloadJournalFileProbe() { return downloadJournalFileProbe; }, set downloadJournalFileProbe(v) { downloadJournalFileProbe = v; }, get downloadJournalModule() { return downloadJournalModule; }, set downloadJournalModule(v) { downloadJournalModule = v; }, get downloadMaxBytes() { return downloadMaxBytes; }, set downloadMaxBytes(v) { downloadMaxBytes = v; }, get downloadRateLimit() { return downloadRateLimit; }, set downloadRateLimit(v) { downloadRateLimit = v; }, get downloadReconcileModule() { return downloadReconcileModule; }, set downloadReconcileModule(v) { downloadReconcileModule = v; }, get downloadSizeGuard() { return downloadSizeGuard; }, set downloadSizeGuard(v) { downloadSizeGuard = v; }, get downloads() { return downloads; }, set downloads(v) { downloads = v; }, get enumerateSiteStorage() { return enumerateSiteStorage; }, set enumerateSiteStorage(v) { enumerateSiteStorage = v; }, get executeCleanPlan() { return executeCleanPlan; }, set executeCleanPlan(v) { executeCleanPlan = v; }, get fpGuard() { return fpGuard; }, set fpGuard(v) { fpGuard = v; }, get fpLedger() { return fpLedger; }, set fpLedger(v) { fpLedger = v; }, get fsSync() { return fsSync; }, set fsSync(v) { fsSync = v; }, get getClientCertChoiceStats() { return getClientCertChoiceStats; }, set getClientCertChoiceStats(v) { getClientCertChoiceStats = v; }, get getCspReportStats() { return getCspReportStats; }, set getCspReportStats(v) { getCspReportStats = v; }, get getDownloadJournal() { return getDownloadJournal; }, set getDownloadJournal(v) { getDownloadJournal = v; }, get getHeaderGradeStats() { return getHeaderGradeStats; }, set getHeaderGradeStats(v) { getHeaderGradeStats = v; }, get getRequestLogStats() { return getRequestLogStats; }, set getRequestLogStats(v) { getRequestLogStats = v; }, get hardenCookies() { return hardenCookies; }, set hardenCookies(v) { hardenCookies = v; }, get history() { return history; }, set history(v) { history = v; }, get httpsExceptions() { return httpsExceptions; }, set httpsExceptions(v) { httpsExceptions = v; }, get httpsOnlyCore() { return httpsOnlyCore; }, set httpsOnlyCore(v) { httpsOnlyCore = v; }, get httpsOnlyEnabled() { return httpsOnlyEnabled; }, set httpsOnlyEnabled(v) { httpsOnlyEnabled = v; }, get inputGuard() { return inputGuard; }, set inputGuard(v) { inputGuard = v; }, get ipcMain() { return ipcMain; }, set ipcMain(v) { ipcMain = v; }, get isAboutFrameSender() { return isAboutFrameSender; }, set isAboutFrameSender(v) { isAboutFrameSender = v; }, get isMainSender() { return isMainSender; }, set isMainSender(v) { isMainSender = v; }, get isPagesFrameSender() { return isPagesFrameSender; }, set isPagesFrameSender(v) { isPagesFrameSender = v; }, get isReadingListFrameSender() { return isReadingListFrameSender; }, set isReadingListFrameSender(v) { isReadingListFrameSender = v; }, get isSafeUrl() { return isSafeUrl; }, set isSafeUrl(v) { isSafeUrl = v; }, get isShortcutsFrameSender() { return isShortcutsFrameSender; }, set isShortcutsFrameSender(v) { isShortcutsFrameSender = v; }, get isValidColor() { return isValidColor; }, set isValidColor(v) { isValidColor = v; }, get ledgerStore() { return ledgerStore; }, set ledgerStore(v) { ledgerStore = v; }, get listPermissionDecisions() { return listPermissionDecisions; }, set listPermissionDecisions(v) { listPermissionDecisions = v; }, get listSecurityEvents() { return listSecurityEvents; }, set listSecurityEvents(v) { listSecurityEvents = v; }, get loadCertExceptions() { return loadCertExceptions; }, set loadCertExceptions(v) { loadCertExceptions = v; }, get loadClientCertChoices() { return loadClientCertChoices; }, set loadClientCertChoices(v) { loadClientCertChoices = v; }, get loadCookieLedger() { return loadCookieLedger; }, set loadCookieLedger(v) { loadCookieLedger = v; }, get loadDohLedger() { return loadDohLedger; }, set loadDohLedger(v) { loadDohLedger = v; }, get loadFpLedger() { return loadFpLedger; }, set loadFpLedger(v) { loadFpLedger = v; }, get loadPnaLedger() { return loadPnaLedger; }, set loadPnaLedger(v) { loadPnaLedger = v; }, get mainWindow() { return mainWindow; }, set mainWindow(v) { mainWindow = v; }, get memorySaverEnabled() { return memorySaverEnabled; }, set memorySaverEnabled(v) { memorySaverEnabled = v; }, get net() { return net; }, set net(v) { net = v; }, get netAuthGuard() { return netAuthGuard; }, set netAuthGuard(v) { netAuthGuard = v; }, get openUrlFromInternalFrame() { return openUrlFromInternalFrame; }, set openUrlFromInternalFrame(v) { openUrlFromInternalFrame = v; }, get originOfContents() { return originOfContents; }, set originOfContents(v) { originOfContents = v; }, get path() { return path; }, set path(v) { path = v; }, get pendingAuthChallenges() { return pendingAuthChallenges; }, set pendingAuthChallenges(v) { pendingAuthChallenges = v; }, get permPolicy() { return permPolicy; }, set permPolicy(v) { permPolicy = v; }, get permissionGrants() { return permissionGrants; }, set permissionGrants(v) { permissionGrants = v; }, get permissionRiskReport() { return permissionRiskReport; }, set permissionRiskReport(v) { permissionRiskReport = v; }, get persistCleanAudit() { return persistCleanAudit; }, set persistCleanAudit(v) { persistCleanAudit = v; }, get persistClientCertChoices() { return persistClientCertChoices; }, set persistClientCertChoices(v) { persistClientCertChoices = v; }, get persistCookieLedger() { return persistCookieLedger; }, set persistCookieLedger(v) { persistCookieLedger = v; }, get persistDohLedger() { return persistDohLedger; }, set persistDohLedger(v) { persistDohLedger = v; }, get persistFpLedger() { return persistFpLedger; }, set persistFpLedger(v) { persistFpLedger = v; }, get persistHttpsExceptions() { return persistHttpsExceptions; }, set persistHttpsExceptions(v) { persistHttpsExceptions = v; }, get persistPnaLedger() { return persistPnaLedger; }, set persistPnaLedger(v) { persistPnaLedger = v; }, get persistRateLimitState() { return persistRateLimitState; }, set persistRateLimitState(v) { persistRateLimitState = v; }, get persistUaPolicyState() { return persistUaPolicyState; }, set persistUaPolicyState(v) { persistUaPolicyState = v; }, get persistVaultKey() { return persistVaultKey; }, set persistVaultKey(v) { persistVaultKey = v; }, get persistVaultState() { return persistVaultState; }, set persistVaultState(v) { persistVaultState = v; }, get pnaLedger() { return pnaLedger; }, set pnaLedger(v) { pnaLedger = v; }, get pnaLedgerStats() { return pnaLedgerStats; }, set pnaLedgerStats(v) { pnaLedgerStats = v; }, get readStoredSettings() { return readStoredSettings; }, set readStoredSettings(v) { readStoredSettings = v; }, get readerArticle() { return readerArticle; }, set readerArticle(v) { readerArticle = v; }, get readingList() { return readingList; }, set readingList(v) { readingList = v; }, get recordSecurityEvent() { return recordSecurityEvent; }, set recordSecurityEvent(v) { recordSecurityEvent = v; }, get reduceClientHints() { return reduceClientHints; }, set reduceClientHints(v) { reduceClientHints = v; }, get rejectAuthChallenge() { return rejectAuthChallenge; }, set rejectAuthChallenge(v) { rejectAuthChallenge = v; }, get resolveEffectiveUa() { return resolveEffectiveUa; }, set resolveEffectiveUa(v) { resolveEffectiveUa = v; }, get safeStorage() { return safeStorage; }, set safeStorage(v) { safeStorage = v; }, get sanitizeSettings() { return sanitizeSettings; }, set sanitizeSettings(v) { sanitizeSettings = v; }, get sanitizeSpellcheckLanguages() { return sanitizeSpellcheckLanguages; }, set sanitizeSpellcheckLanguages(v) { sanitizeSpellcheckLanguages = v; }, get saveBookmarks() { return saveBookmarks; }, set saveBookmarks(v) { saveBookmarks = v; }, get saveHistory() { return saveHistory; }, set saveHistory(v) { saveHistory = v; }, get saveReadingList() { return saveReadingList; }, set saveReadingList(v) { saveReadingList = v; }, get searchProvider() { return searchProvider; }, set searchProvider(v) { searchProvider = v; }, get searchProviderId() { return searchProviderId; }, set searchProviderId(v) { searchProviderId = v; }, get securityPosture() { return securityPosture; }, set securityPosture(v) { securityPosture = v; }, get sendToRenderer() { return sendToRenderer; }, set sendToRenderer(v) { sendToRenderer = v; }, get session() { return session; }, set session(v) { session = v; }, get shortcutKeys() { return shortcutKeys; }, set shortcutKeys(v) { shortcutKeys = v; }, get spellcheckEnabled() { return spellcheckEnabled; }, set spellcheckEnabled(v) { spellcheckEnabled = v; }, get spellcheckLanguages() { return spellcheckLanguages; }, set spellcheckLanguages(v) { spellcheckLanguages = v; }, get stripAcceptCh() { return stripAcceptCh; }, set stripAcceptCh(v) { stripAcceptCh = v; }, get stripTrackingParams() { return stripTrackingParams; }, set stripTrackingParams(v) { stripTrackingParams = v; }, get tabs() { return tabs; }, set tabs(v) { tabs = v; }, get topBlockedHosts() { return topBlockedHosts; }, set topBlockedHosts(v) { topBlockedHosts = v; }, get uaLastOverrideAt() { return uaLastOverrideAt; }, set uaLastOverrideAt(v) { uaLastOverrideAt = v; }, get uaOverrideCount() { return uaOverrideCount; }, set uaOverrideCount(v) { uaOverrideCount = v; }, get uaPolicyCore() { return uaPolicyCore; }, set uaPolicyCore(v) { uaPolicyCore = v; }, get uaPolicyState() { return uaPolicyState; }, set uaPolicyState(v) { uaPolicyState = v; }, get unlockVault() { return unlockVault; }, set unlockVault(v) { unlockVault = v; }, get vaultCore() { return vaultCore; }, set vaultCore(v) { vaultCore = v; }, get vaultHandle() { return vaultHandle; }, set vaultHandle(v) { vaultHandle = v; }, get vaultPasswordOK() { return vaultPasswordOK; }, set vaultPasswordOK(v) { vaultPasswordOK = v; }, get vaultStatusSnapshot() { return vaultStatusSnapshot; }, set vaultStatusSnapshot(v) { vaultStatusSnapshot = v; }, get vaultUsePasswordMode() { return vaultUsePasswordMode; }, set vaultUsePasswordMode(v) { vaultUsePasswordMode = v; }, get webrtcMode() { return webrtcMode; }, set webrtcMode(v) { webrtcMode = v; } });
cosyipcregisterMod.registerNetworkGuards();

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
const cookieledger = require('./cookieledger');
const tabgroupmain = require('./tabgroupmain');
const { applyTabGroupArrangement, broadcastTabGroups, clearStoredTabGroups, loadStoredTabGroups, persistTabGroups, saveTabGroupsNow, reorderTabsByGroupPlan, tabGroupError, tabGroupIsPinned, tabGroupOrder, tabKeepsAlive } = tabgroupmain;
tabgroupmain.bindDeps({
  get currentTabIndex() { return currentTabIndex; },
  set currentTabIndex(v) { currentTabIndex = v; },
  get findTabIndexById() { return findTabIndexById; },
  get fsSync() { return fsSync; },
  get ledgerStore() { return ledgerStore; },
  get pinModel() { return pinModel; },
  get sendToRenderer() { return sendToRenderer; },
  get tabGroupModel() { return tabGroupModel; },
  get tabGroupSaveTimer() { return tabGroupSaveTimer; },
  set tabGroupSaveTimer(v) { tabGroupSaveTimer = v; },
  get tabGroupStorePath() { return tabGroupStorePath; },
  get tabGroups() { return tabGroups; },
  get tabOrderDiff() { return tabOrderDiff; },
  get tabs() { return tabs; }
});

const { loadCookieLedger, persistCookieLedger, normalizeCookieDomain, pickCookieFields, removeCookieEntry, cookieOriginSchemes } = cookieledger;
cookieledger.bindDeps({
  get cookieLedger() { return cookieLedger; },
  get cookieLedgerLoaded() { return cookieLedgerLoaded; },
  set cookieLedgerLoaded(v) { cookieLedgerLoaded = v; },
  get cookieLedgerSaveTimer() { return cookieLedgerSaveTimer; },
  set cookieLedgerSaveTimer(v) { cookieLedgerSaveTimer = v; },
  get cookieLedgerStorePath() { return cookieLedgerStorePath; },
  get ledgerStore() { return ledgerStore; },
  get path() { return path; },
  get session() { return session; }
,
  get path() { return path; },
  get session() { return session; }});

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

// r34：GPU 进程崩溃 / GPU 信息更新 / 无障碍支持变化是 app 级系统事件，与具体标签弱
// 关联，用进程级单份状态去重。崩溃风暴折叠为一条审计并提示重载；GPU 重枚举只保留
// 白名单字段，软件渲染回退时留痕；系统读屏被打开（渲染路径变化）留痕。

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

const TASK_MANAGER_URL = 'cosy://taskmanager';

// openTaskManagerTab 打开（或切到已有的）任务管理器内置页。任务管理器是 cosy: 页，
// 承载在普通标签视图里；已开则复用，避免连按 Shift+Esc 开出一堆相同页。

const TAB_OVERVIEW_URL = 'cosy://taboverview';

// openTabOverviewTab 打开（或切到已有的）标签页概览网格页。与任务管理器同款
// 语义：已开则复用，避免 Ctrl+Shift+E 连按开出一堆相同页。

const READER_PAGE_URL = 'cosy://reader';

// readerArticle 只暂存最近一次抽取结果，供紧随其后打开的 cosy://reader 读取；
// 阅读页关闭后清空。阅读数据虽由本进程可信内核产出，但它跨了“网页主世界”边界
// （executeJavaScript 的返回值来自页面环境），落进主进程前再做一次形状与长度收口。
let readerArticle = null;

// enterReaderMode 在“当前活动的 http(s) 标签”真实 DOM 内只读抽取正文，再带着
// 净化后的数据打开阅读页。抽取脚本运行在页面主世界但只调用只读 DOM API；返回值
// 经主进程二次形状校验。cosy:/file: 等内置页不支持阅读模式。

// pushNavState 每次导航完成后同步 canGoBack/canGoForward，让 renderer 知道按钮该灰掉还是点亮

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

// 销毁已经死亡的视图；webContents 在崩溃后可能已被回收，全部容错。

// 重建崩溃标签的视图；超过自动恢复上限时改显错误页，不再自动加载原 URL。

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

// discardTab 回收一个后台标签的渲染进程并保留标签壳。

// reloadDiscardedTab 唤醒休眠标签：按记录的 URL 重建视图并重新加载。

// sweepDiscardableTabs 把超过空闲阈值且无需常驻的后台标签休眠掉。

// discardAllBackgroundTabs 立即休眠除活动标签外所有可休眠的后台标签，
// 返回成功休眠的数量，供快捷键 / 右键菜单给用户一个明确反馈。

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

cosyipcwire2Mod.registerTabOverviewIpc();

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

// ===== 固定标签页（Pinned Tabs）=====
// 权威固定集合由 pintabs 纯内核维护；这里负责把固定状态落到 Tab 对象、把固定
// 标签物理重排到标签栏最前、跨重启按 URL 重水合、以及把状态变化广播给渲染层。
// 固定清单单独存 pintabs.json（session.json 只存 http/https 页，固定的 cosy 内置
// 页会被它过滤掉，无法复用）。
const pinModel = new pinTabs.PinModel();
const pinStorePath = path.join(app.getPath('userData'), 'pintabs.json');
let pinSaveTimer = null;

// broadcastPinnedState 把单个标签的固定 / 取消固定结果推给渲染层。

// applyPinnedState 设置标签固定态并同步内核；不负责重排，重排统一走
// movePinnedTabsToFront，便于批量重水合时只重排一次。

// movePinnedTabsToFront 依据内核的稳定分区结果，物理重排 tabs 数组（视图对象挂在
// Tab 上，随元素一起移动，不需要重建），并修正当前标签索引，最后让渲染层同步顺序。

// rehydratePinnedTabs 在启动恢复出标签后，用磁盘上的固定 URL 清单匹配本次新标签，
// 一次性恢复固定态并把它们排到最前。匹配不到（对应页本次没恢复）的固定项忽略。

// ensurePinnedTabsOpened 在启动会话恢复之后调用：固定标签独立于 session.json
// 持久化，即使会话文件被清，也应把固定的 http/https 页补开后再重水合。固定的
// cosy 内置页不主动补开（避免与默认新标签页重复），只在它本次本就存在时固定。

// closeTabsByIds 按一组标签 id 批量关闭。为避免 splice 导致的索引漂移，统一从
// 最大索引向最小索引关闭。返回实际关闭数量。

// planAndCloseTabs 是批量关闭的唯一权威入口：先由 pintabs 内核裁决哪些标签允许
// 关闭（固定标签在任何模式下都保留），再真正关闭。渲染层不再自己循环关标签。

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

// tabGroupOrder 依据内核 arrangeTabs 计算“目标标签 id 顺序”：固定区最前、
// 已分组标签按组聚类、未分组标签保持原相对顺序垫后。渲染层按此顺序渲染。

// broadcastTabGroups 把分组快照（分组列表 + 编排后的标签顺序）推给渲染层。
// 快照只含纯数据，绝不暴露 Tab 对象 / WebContents。

// reorderTabsByGroupPlan 依据目标顺序对 tabs 数组做物理重排（Tab 对象挂在
// Tab.view 上，随元素移动，无需重建视图），并修正当前标签索引。最后让渲染层
// 按新顺序渲染。返回是否发生了顺序变化。

// applyTabGroupArrangement 是“按分组重排标签栏”的唯一权威入口：用内核计算目标
// 顺序，再用 taborderdiff 求出最小移动指令（只移动需要挪位的标签，已有序的原地
// 不动），物理重排后广播。任何分组结构变化（建组 / 加标签 / 移出 / 解散 / 组间
// 移动）都调用它，避免渲染层各自猜测顺序。

// rehydrateTabGroups 在启动会话恢复出标签之后调用：读取磁盘分组清单，按“组内
// 标签 id 与本次打开的非固定标签匹配”重水合模型（不匹配的组内标签剔除，变空的
// 组丢弃），然后按分组重排一次标签栏。

// tabGroupError 把内核拒绝原因转成渲染层可读的 { ok:false, reason }。

const cosyipcwireMod = require('./cosyipcwire');
cosyipcwireMod.bindDeps({
    get ALLOWED_SETTING_KEYS() { return ALLOWED_SETTING_KEYS; },
    get BrowserWindow() { return BrowserWindow; },
    get MAX_DOWNLOAD_ORIGIN_ENTRIES() { return MAX_DOWNLOAD_ORIGIN_ENTRIES; },
    get MAX_DOWNLOAD_RISK_RECORDS() { return MAX_DOWNLOAD_RISK_RECORDS; },
    get Menu() { return Menu; },
    get MenuItem() { return MenuItem; },
    get adjustCurrentZoom() { return adjustCurrentZoom; },
    get allowPictureInPicture() { return allowPictureInPicture; },
    set allowPictureInPicture(v) { allowPictureInPicture = v; },
    get app() { return app; },
    get applyDarkMode() { return applyDarkMode; },
    get applyPinnedState() { return applyPinnedState; },
    get applySecureDns() { return applySecureDns; },
    get applySpellcheckSettings() { return applySpellcheckSettings; },
    get applyTabGroupArrangement() { return applyTabGroupArrangement; },
    get applyUaPolicyToSession() { return applyUaPolicyToSession; },
    get applyWebRtcPolicy() { return applyWebRtcPolicy; },
    get blockAdSignals() { return blockAdSignals; },
    set blockAdSignals(v) { blockAdSignals = v; },
    get blockHyperlinkPing() { return blockHyperlinkPing; },
    set blockHyperlinkPing(v) { blockHyperlinkPing = v; },
    get blockLocalNetworkAccess() { return blockLocalNetworkAccess; },
    set blockLocalNetworkAccess(v) { blockLocalNetworkAccess = v; },
    get blockRules() { return blockRules; },
    get blockThirdPartyCookies() { return blockThirdPartyCookies; },
    set blockThirdPartyCookies(v) { blockThirdPartyCookies = v; },
    get blockTrackers() { return blockTrackers; },
    set blockTrackers(v) { blockTrackers = v; },
    get bookmarkBarVisible() { return bookmarkBarVisible; },
    set bookmarkBarVisible(v) { bookmarkBarVisible = v; },
    get broadcastTabGroups() { return broadcastTabGroups; },
    get clearOnExit() { return clearOnExit; },
    set clearOnExit(v) { clearOnExit = v; },
    get clipboard() { return clipboard; },
    get closeTab() { return closeTab; },
    get confirmAndOpenExternal() { return confirmAndOpenExternal; },
    get confirmCloseMultiple() { return confirmCloseMultiple; },
    set confirmCloseMultiple(v) { confirmCloseMultiple = v; },
    get cosyScheme() { return cosyScheme; },
    get cosytabsmainMod() { return cosytabsmainMod; },
    get crashRecoveryEnabled() { return crashRecoveryEnabled; },
    set crashRecoveryEnabled(v) { crashRecoveryEnabled = v; },
    get createNewTab() { return createNewTab; },
    get createWindow() { return createWindow; },
    get currentDownloadInfo() { return currentDownloadInfo; },
    set currentDownloadInfo(v) { currentDownloadInfo = v; },
    get currentTabIndex() { return currentTabIndex; },
    set currentTabIndex(v) { currentTabIndex = v; },
    get customRules() { return customRules; },
    get deeplinkGuard() { return deeplinkGuard; },
    get dialog() { return dialog; },
    get dloadGuard() { return dloadGuard; },
    get dohCustomUrl() { return dohCustomUrl; },
    set dohCustomUrl(v) { dohCustomUrl = v; },
    get dohGuard() { return dohGuard; },
    get dohMode() { return dohMode; },
    set dohMode(v) { dohMode = v; },
    get dohProvider() { return dohProvider; },
    set dohProvider(v) { dohProvider = v; },
    get downloadMaxBytes() { return downloadMaxBytes; },
    set downloadMaxBytes(v) { downloadMaxBytes = v; },
    get downloadName() { return downloadName; },
    get downloadOriginByPath() { return downloadOriginByPath; },
    get downloadPathCollision() { return downloadPathCollision; },
    get downloadRiskRecords() { return downloadRiskRecords; },
    get downloadRiskSaveTimer() { return downloadRiskSaveTimer; },
    set downloadRiskSaveTimer(v) { downloadRiskSaveTimer = v; },
    get downloadRiskStorePath() { return downloadRiskStorePath; },
    get downloadSaveTarget() { return downloadSaveTarget; },
    get downloadShelf() { return downloadShelf; },
    get downloadSizeGuard() { return downloadSizeGuard; },
    get downloads() { return downloads; },
    set downloads(v) { downloads = v; },
    get findState() { return findState; },
    set findState(v) { findState = v; },
    get forgetProtocolDecision() { return forgetProtocolDecision; },
    get fpGuard() { return fpGuard; },
    get fsSync() { return fsSync; },
    get getCurrentTabWebContents() { return getCurrentTabWebContents; },
    get getLastClosedTab() { return getLastClosedTab; },
    get getSafeDirs() { return getSafeDirs; },
    get getUrlProtocol() { return getUrlProtocol; },
    get goHome() { return goHome; },
    get handleDownloadEventCtx() { return handleDownloadEventCtx; },
    get hardenCookies() { return hardenCookies; },
    set hardenCookies(v) { hardenCookies = v; },
    get httpsOnlyEnabled() { return httpsOnlyEnabled; },
    set httpsOnlyEnabled(v) { httpsOnlyEnabled = v; },
    get initVaultOnStartup() { return initVaultOnStartup; },
    get ipcMain() { return ipcMain; },
    get isDev() { return isDev; },
    get isInSafeDirs() { return isInSafeDirs; },
    get isMainSender() { return isMainSender; },
    get isPathInDir() { return isPathInDir; },
    get isSafeUrl() { return isSafeUrl; },
    get isTabBarCollapsed() { return isTabBarCollapsed; },
    set isTabBarCollapsed(v) { isTabBarCollapsed = v; },
    get launchSwitchAudit() { return launchSwitchAudit; },
    get ledgerStore() { return ledgerStore; },
    get listProtocolDecisions() { return listProtocolDecisions; },
    get loadBookmarks() { return loadBookmarks; },
    get loadCustomRulesFromDisk() { return loadCustomRulesFromDisk; },
    get loadDownloadRisks() { return loadDownloadRisks; },
    get loadDownloads() { return loadDownloads; },
    get loadEnabledExtensions() { return loadEnabledExtensions; },
    get loadHistory() { return loadHistory; },
    get loadHttpsExceptions() { return loadHttpsExceptions; },
    get loadReadingList() { return loadReadingList; },
    get loadStoredTabGroups() { return loadStoredTabGroups; },
    get loadTabContent() { return loadTabContent; },
    get loadUaPolicyStateFromDisk() { return loadUaPolicyStateFromDisk; },
    get loadZoomFactors() { return loadZoomFactors; },
    get mainWindow() { return mainWindow; },
    set mainWindow(v) { mainWindow = v; },
    get managedDownloadSessions() { return managedDownloadSessions; },
    get memorySaverEnabled() { return memorySaverEnabled; },
    set memorySaverEnabled(v) { memorySaverEnabled = v; },
    get movePinnedTabsToFront() { return movePinnedTabsToFront; },
    get path() { return path; },
    get pathToFileURL() { return pathToFileURL; },
    get performDownloadOpen() { return performDownloadOpen; },
    get persistPins() { return persistPins; },
    get persistTabGroups() { return persistTabGroups; },
    get pinModel() { return pinModel; },
    get pinSaveTimer() { return pinSaveTimer; },
    set pinSaveTimer(v) { pinSaveTimer = v; },
    get pinStorePath() { return pinStorePath; },
    get pinTabs() { return pinTabs; },
    get planAndCloseTabs() { return planAndCloseTabs; },
    get protocol() { return protocol; },
    get readPersistedSettings() { return readPersistedSettings; },
    get readStoredSettings() { return readStoredSettings; },
    get readingList() { return readingList; },
    set readingList(v) { readingList = v; },
    get recentlyClosedTabs() { return recentlyClosedTabs; },
    set recentlyClosedTabs(v) { recentlyClosedTabs = v; },
    get recordSecurityEvent() { return recordSecurityEvent; },
    get reduceClientHints() { return reduceClientHints; },
    set reduceClientHints(v) { reduceClientHints = v; },
    get resolveStartupDeepLink() { return resolveStartupDeepLink; },
    get sanitizeDownloadFilename() { return sanitizeDownloadFilename; },
    get sanitizeSpellcheckLanguages() { return sanitizeSpellcheckLanguages; },
    get saveReadingList() { return saveReadingList; },
    get searchProvider() { return searchProvider; },
    get searchProviderId() { return searchProviderId; },
    set searchProviderId(v) { searchProviderId = v; },
    get sendShelf() { return sendShelf; },
    get sendToRenderer() { return sendToRenderer; },
    get session() { return session; },
    get setupDownloadManager() { return setupDownloadManager; },
    get setupExtraSessionHardening() { return setupExtraSessionHardening; },
    get setupGlobalWebContentsHooks() { return setupGlobalWebContentsHooks; },
    get setupNetworkAuth() { return setupNetworkAuth; },
    get setupNetworkStatus() { return setupNetworkStatus; },
    get setupPermissionHandlers() { return setupPermissionHandlers; },
    get setupSecurityHeaders() { return setupSecurityHeaders; },
    get setupSystemEventGuards() { return setupSystemEventGuards; },
    get shelfSnapshot() { return shelfSnapshot; },
    get shell() { return shell; },
    get shellGuard() { return shellGuard; },
    get spellcheckEnabled() { return spellcheckEnabled; },
    set spellcheckEnabled(v) { spellcheckEnabled = v; },
    get spellcheckLanguages() { return spellcheckLanguages; },
    set spellcheckLanguages(v) { spellcheckLanguages = v; },
    get startMemorySaver() { return startMemorySaver; },
    get stripAcceptCh() { return stripAcceptCh; },
    set stripAcceptCh(v) { stripAcceptCh = v; },
    get stripTrackingParams() { return stripTrackingParams; },
    set stripTrackingParams(v) { stripTrackingParams = v; },
    get switchToTab() { return switchToTab; },
    get tabGroupError() { return tabGroupError; },
    get tabGroupIsPinned() { return tabGroupIsPinned; },
    get tabGroupModel() { return tabGroupModel; },
    get tabGroupOrder() { return tabGroupOrder; },
    get tabGroups() { return tabGroups; },
    get tabSearch() { return tabSearch; },
    get tabs() { return tabs; },
    set tabs(v) { tabs = v; },
    get toggleDevTools() { return toggleDevTools; },
    get toggleTabPinned() { return toggleTabPinned; },
    get updateBrowserViewBounds() { return updateBrowserViewBounds; },
    get urlResolve() { return urlResolve; },
    get webContents() { return webContents; },
    get webrtcMode() { return webrtcMode; },
    set webrtcMode(v) { webrtcMode = v; },
});
cosyipcwireMod.registerProtocolIpc();

// sanitizeDownloadFilename 防 Content-Disposition 路径穿越与视觉伪装：
// 服务端可能在 filename 里塞 "../../evil.exe"、RTL 反转符、结尾点空格或
// Windows 保留设备名。这里委托 dloadguard.sanitizeName：剥离目录组件与不可见
// 字符、剥掉结尾点空格、给保留名加前缀，返回可安全落盘的纯文件名。

// resolveUniqueDownloadPath 如果目标已存在，自动追加 (1)/(2)/... 避免覆盖

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

const downloadRiskRecords = [];
let downloadRiskLoaded = false;
let downloadRiskSaveTimer = null;

// listDownloadRisks 返回最近的风险记录（倒序，新的在前），供安全中心只读展示。

// 兼容旧调用名：现在基于 dloadguard 判断“是否需要用户确认/拒绝”。
// 返回 dloadguard 的完整分析结果（含原因链），供确认对话框展示。

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

// managedDownloadSessions 记录已挂过下载保护的 session。will-download 若对同一
// session 注册两次，一次下载会触发两轮回调：弹两次确认框、写两条台账、落盘后补两次
// MOTW。defaultSession 走 setupDownloadManager、分区走 session-created，理论上互斥，
// 但仍用 WeakSet 做幂等兜底（session 回收后条目自动消失，不泄漏）。

const managedDownloadSessions = new WeakSet();

// attachDownloadManager 把同一套下载保护挂到任意 session；defaultSession 与分区会话
// 都必须经过它，避免隔离 / 访客分区下载绕过文件名净化、危险类型确认与 MOTW。

// reviewToOpenUrl 把 deeplinkguard 的放行结论转成可打开 URL；本地文件需存在。

// resolveStartupDeepLink 把一条不可信入口参数（argv / open-file / open-url）
// 经 deeplinkguard 消毒后，统一转成可打开的目标 URL；不合法返回 null 并记审计。

// resolveStartupArgv 从整条命令行里找第一个合法深链（Windows 协议唤起位置不固定）。

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

const cosyguardmainMod = require('./cosyguardmain');
cosyguardmainMod.bindDeps({ get recordSecurityEvent() { return recordSecurityEvent; }, set recordSecurityEvent(v) { recordSecurityEvent = v; }, get fpGuard() { return fpGuard; }, set fpGuard(v) { fpGuard = v; }, get popupOpenTimes() { return popupOpenTimes; }, set popupOpenTimes(v) { popupOpenTimes = v; }, get POPUP_WINDOW_MS() { return POPUP_WINDOW_MS; }, set POPUP_WINDOW_MS(v) { POPUP_WINDOW_MS = v; }, get POPUP_WINDOW_MAX() { return POPUP_WINDOW_MAX; }, set POPUP_WINDOW_MAX(v) { POPUP_WINDOW_MAX = v; }, get compiledCustomRules() { return compiledCustomRules; }, set compiledCustomRules(v) { compiledCustomRules = v; }, get blockRules() { return blockRules; }, set blockRules(v) { blockRules = v; }, get customRules() { return customRules; }, set customRules(v) { customRules = v; }, get customRulesFile() { return customRulesFile; }, set customRulesFile(v) { customRulesFile = v; }, get customRulesLoaded() { return customRulesLoaded; }, set customRulesLoaded(v) { customRulesLoaded = v; }, get hostMatch() { return hostMatch; }, set hostMatch(v) { hostMatch = v; }, get TRACKER_HOSTS() { return TRACKER_HOSTS; }, set TRACKER_HOSTS(v) { TRACKER_HOSTS = v; }, get blockTrackers() { return blockTrackers; }, set blockTrackers(v) { blockTrackers = v; }, get blockedTrackerCount() { return blockedTrackerCount; }, set blockedTrackerCount(v) { blockedTrackerCount = v; }, get urlResolve() { return urlResolve; }, set urlResolve(v) { urlResolve = v; }, get blockedTrackerByHost() { return blockedTrackerByHost; }, set blockedTrackerByHost(v) { blockedTrackerByHost = v; }, get sendToRenderer() { return sendToRenderer; }, set sendToRenderer(v) { sendToRenderer = v; }, get TRACKING_QUERY_KEYS() { return TRACKING_QUERY_KEYS; }, set TRACKING_QUERY_KEYS(v) { TRACKING_QUERY_KEYS = v; }, get TRACKING_QUERY_PREFIXES() { return TRACKING_QUERY_PREFIXES; }, set TRACKING_QUERY_PREFIXES(v) { TRACKING_QUERY_PREFIXES = v; }, get stripTrackingParams() { return stripTrackingParams; }, set stripTrackingParams(v) { stripTrackingParams = v; }, get SKEW_LATIN_HOSTS() { return SKEW_LATIN_HOSTS; }, set SKEW_LATIN_HOSTS(v) { SKEW_LATIN_HOSTS = v; } });
const cosysettingsmainMod = require('./cosysettingsmain');
cosysettingsmainMod.bindDeps({ get DEFAULT_SPELLCHECK_LANGUAGES() { return DEFAULT_SPELLCHECK_LANGUAGES; }, set DEFAULT_SPELLCHECK_LANGUAGES(v) { DEFAULT_SPELLCHECK_LANGUAGES = v; }, get ALLOWED_SPELLCHECK_LANGUAGES() { return ALLOWED_SPELLCHECK_LANGUAGES; }, set ALLOWED_SPELLCHECK_LANGUAGES(v) { ALLOWED_SPELLCHECK_LANGUAGES = v; }, get MAX_SPELLCHECK_LANGUAGES() { return MAX_SPELLCHECK_LANGUAGES; }, set MAX_SPELLCHECK_LANGUAGES(v) { MAX_SPELLCHECK_LANGUAGES = v; }, get session() { return session; }, set session(v) { session = v; }, get spellcheckEnabled() { return spellcheckEnabled; }, set spellcheckEnabled(v) { spellcheckEnabled = v; }, get spellcheckLanguages() { return spellcheckLanguages; }, set spellcheckLanguages(v) { spellcheckLanguages = v; }, get path() { return path; }, set path(v) { path = v; }, get app() { return app; }, set app(v) { app = v; }, get ledgerStore() { return ledgerStore; }, set ledgerStore(v) { ledgerStore = v; }, get mainWindow() { return mainWindow; }, set mainWindow(v) { mainWindow = v; }, get winPolicy() { return winPolicy; }, set winPolicy(v) { winPolicy = v; }, get downloadShelf() { return downloadShelf; }, set downloadShelf(v) { downloadShelf = v; }, get downloads() { return downloads; }, set downloads(v) { downloads = v; }, get MAX_PERSISTED_DOWNLOADS() { return MAX_PERSISTED_DOWNLOADS; }, set MAX_PERSISTED_DOWNLOADS(v) { MAX_PERSISTED_DOWNLOADS = v; }, get recordSecurityEvent() { return recordSecurityEvent; }, set recordSecurityEvent(v) { recordSecurityEvent = v; }, get downloadNotify() { return downloadNotify; }, set downloadNotify(v) { downloadNotify = v; }, get downloadNotifyDeps() { return downloadNotifyDeps; }, set downloadNotifyDeps(v) { downloadNotifyDeps = v; }, get originOfContents() { return originOfContents; }, set originOfContents(v) { originOfContents = v; }, get webContents() { return webContents; }, set webContents(v) { webContents = v; }, get ALLOWED_PROTOCOLS() { return ALLOWED_PROTOCOLS; }, set ALLOWED_PROTOCOLS(v) { ALLOWED_PROTOCOLS = v; }, get pathContain() { return pathContain; }, set pathContain(v) { pathContain = v; }, get fsSync() { return fsSync; }, set fsSync(v) { fsSync = v; }, get tabs() { return tabs; }, set tabs(v) { tabs = v; }, get currentTabIndex() { return currentTabIndex; }, set currentTabIndex(v) { currentTabIndex = v; }, get loadTabContent() { return loadTabContent; }, set loadTabContent(v) { loadTabContent = v; }, get historyGuard() { return historyGuard; }, set historyGuard(v) { historyGuard = v; }, get history() { return history; }, set history(v) { history = v; }, get MAX_HISTORY_ENTRIES() { return MAX_HISTORY_ENTRIES; }, set MAX_HISTORY_ENTRIES(v) { MAX_HISTORY_ENTRIES = v; }, get bookmarkGuard() { return bookmarkGuard; }, set bookmarkGuard(v) { bookmarkGuard = v; }, get bookmarks() { return bookmarks; }, set bookmarks(v) { bookmarks = v; }, get readingList() { return readingList; }, set readingList(v) { readingList = v; }, get restoreGuard() { return restoreGuard; }, set restoreGuard(v) { restoreGuard = v; }, get recentlyClosedTabs() { return recentlyClosedTabs; }, set recentlyClosedTabs(v) { recentlyClosedTabs = v; }, get hostMatch() { return hostMatch; }, set hostMatch(v) { hostMatch = v; } });
const cosyledgerchainmainMod = require('./cosyledgerchainmain');
cosyledgerchainmainMod.bindDeps({ get httpsExceptionsLoaded() { return httpsExceptionsLoaded; }, set httpsExceptionsLoaded(v) { httpsExceptionsLoaded = v; }, get httpsExceptions() { return httpsExceptions; }, set httpsExceptions(v) { httpsExceptions = v; }, get ledgerStore() { return ledgerStore; }, set ledgerStore(v) { ledgerStore = v; }, get httpsExceptionStorePath() { return httpsExceptionStorePath; }, set httpsExceptionStorePath(v) { httpsExceptionStorePath = v; }, get httpsExceptionSaveTimer() { return httpsExceptionSaveTimer; }, set httpsExceptionSaveTimer(v) { httpsExceptionSaveTimer = v; }, get httpsOnlyCore() { return httpsOnlyCore; }, set httpsOnlyCore(v) { httpsOnlyCore = v; }, get fsSync() { return fsSync; }, set fsSync(v) { fsSync = v; }, get uaPolicyPath() { return uaPolicyPath; }, set uaPolicyPath(v) { uaPolicyPath = v; }, get uaPolicyState() { return uaPolicyState; }, set uaPolicyState(v) { uaPolicyState = v; }, get uaPolicyCore() { return uaPolicyCore; }, set uaPolicyCore(v) { uaPolicyCore = v; }, get rateLimitPath() { return rateLimitPath; }, set rateLimitPath(v) { rateLimitPath = v; }, get downloadRateLimit() { return downloadRateLimit; }, set downloadRateLimit(v) { downloadRateLimit = v; }, get generateUserAgent() { return generateUserAgent; }, set generateUserAgent(v) { generateUserAgent = v; }, get path() { return path; }, set path(v) { path = v; }, get atomicWriteSeq() { return atomicWriteSeq; }, set atomicWriteSeq(v) { atomicWriteSeq = v; }, get vaultStorePath() { return vaultStorePath; }, set vaultStorePath(v) { vaultStorePath = v; }, get vaultState() { return vaultState; }, set vaultState(v) { vaultState = v; }, get cleanAuditPath() { return cleanAuditPath; }, set cleanAuditPath(v) { cleanAuditPath = v; }, get cleanAuditLog() { return cleanAuditLog; }, set cleanAuditLog(v) { cleanAuditLog = v; }, get safeStorage() { return safeStorage; }, set safeStorage(v) { safeStorage = v; }, get recordSecurityEvent() { return recordSecurityEvent; }, set recordSecurityEvent(v) { recordSecurityEvent = v; }, get vaultKeyPath() { return vaultKeyPath; }, set vaultKeyPath(v) { vaultKeyPath = v; }, get httpsOnlyEnabled() { return httpsOnlyEnabled; }, set httpsOnlyEnabled(v) { httpsOnlyEnabled = v; }, get isPrivateNetworkHost() { return isPrivateNetworkHost; }, set isPrivateNetworkHost(v) { isPrivateNetworkHost = v; }, get dialog() { return dialog; }, set dialog(v) { dialog = v; }, get mainWindow() { return mainWindow; }, set mainWindow(v) { mainWindow = v; }, get nativeTheme() { return nativeTheme; }, set nativeTheme(v) { nativeTheme = v; }, get sendToRenderer() { return sendToRenderer; }, set sendToRenderer(v) { sendToRenderer = v; }, get pnaLedgerLoaded() { return pnaLedgerLoaded; }, set pnaLedgerLoaded(v) { pnaLedgerLoaded = v; }, get pnaLedgerStorePath() { return pnaLedgerStorePath; }, set pnaLedgerStorePath(v) { pnaLedgerStorePath = v; }, get pnaLedger() { return pnaLedger; }, set pnaLedger(v) { pnaLedger = v; }, get pnaLedgerSaveTimer() { return pnaLedgerSaveTimer; }, set pnaLedgerSaveTimer(v) { pnaLedgerSaveTimer = v; }, get MAX_PNA_LEDGER() { return MAX_PNA_LEDGER; }, set MAX_PNA_LEDGER(v) { MAX_PNA_LEDGER = v; }, get fpLedgerLoaded() { return fpLedgerLoaded; }, set fpLedgerLoaded(v) { fpLedgerLoaded = v; }, get fpLedger() { return fpLedger; }, set fpLedger(v) { fpLedger = v; }, get fpLedgerStorePath() { return fpLedgerStorePath; }, set fpLedgerStorePath(v) { fpLedgerStorePath = v; }, get fpLedgerSaveTimer() { return fpLedgerSaveTimer; }, set fpLedgerSaveTimer(v) { fpLedgerSaveTimer = v; }, get session() { return session; }, set session(v) { session = v; }, get fpGuard() { return fpGuard; }, set fpGuard(v) { fpGuard = v; }, get webrtcMode() { return webrtcMode; }, set webrtcMode(v) { webrtcMode = v; }, get dohLedgerLoaded() { return dohLedgerLoaded; }, set dohLedgerLoaded(v) { dohLedgerLoaded = v; }, get dohLedger() { return dohLedger; }, set dohLedger(v) { dohLedger = v; }, get dohStorePath() { return dohStorePath; }, set dohStorePath(v) { dohStorePath = v; }, get dohSaveTimer() { return dohSaveTimer; }, set dohSaveTimer(v) { dohSaveTimer = v; }, get dohMode() { return dohMode; }, set dohMode(v) { dohMode = v; }, get dohProvider() { return dohProvider; }, set dohProvider(v) { dohProvider = v; }, get dohActive() { return dohActive; }, set dohActive(v) { dohActive = v; }, get recordRequestAttempt() { return recordRequestAttempt; }, set recordRequestAttempt(v) { recordRequestAttempt = v; }, get requestPipeline() { return requestPipeline; }, set requestPipeline(v) { requestPipeline = v; }, get buildRequestPipelineDeps() { return buildRequestPipelineDeps; }, set buildRequestPipelineDeps(v) { buildRequestPipelineDeps = v; }, get urlResolve() { return urlResolve; }, set urlResolve(v) { urlResolve = v; }, get headerGradeSaveTimer() { return headerGradeSaveTimer; }, set headerGradeSaveTimer(v) { headerGradeSaveTimer = v; }, get headerGradeStorePath() { return headerGradeStorePath; }, set headerGradeStorePath(v) { headerGradeStorePath = v; }, get headerGrades() { return headerGrades; }, set headerGrades(v) { headerGrades = v; }, get loadHeaderGrades() { return loadHeaderGrades; }, set loadHeaderGrades(v) { loadHeaderGrades = v; }, get MAX_HEADER_GRADE_HOSTS() { return MAX_HEADER_GRADE_HOSTS; }, set MAX_HEADER_GRADE_HOSTS(v) { MAX_HEADER_GRADE_HOSTS = v; }, get requestLogLoaded() { return requestLogLoaded; }, set requestLogLoaded(v) { requestLogLoaded = v; }, get requestLogStorePath() { return requestLogStorePath; }, set requestLogStorePath(v) { requestLogStorePath = v; }, get requestLogStore() { return requestLogStore; }, set requestLogStore(v) { requestLogStore = v; }, get requestLog() { return requestLog; }, set requestLog(v) { requestLog = v; }, get MAX_REQUEST_LOG_HOSTS() { return MAX_REQUEST_LOG_HOSTS; }, set MAX_REQUEST_LOG_HOSTS(v) { MAX_REQUEST_LOG_HOSTS = v; }, get requestLogSaveTimer() { return requestLogSaveTimer; }, set requestLogSaveTimer(v) { requestLogSaveTimer = v; }, get brandSpoofSaveTimer() { return brandSpoofSaveTimer; }, set brandSpoofSaveTimer(v) { brandSpoofSaveTimer = v; }, get brandSpoofStorePath() { return brandSpoofStorePath; }, set brandSpoofStorePath(v) { brandSpoofStorePath = v; }, get brandSpoofs() { return brandSpoofs; }, set brandSpoofs(v) { brandSpoofs = v; }, get loadBrandSpoofs() { return loadBrandSpoofs; }, set loadBrandSpoofs(v) { loadBrandSpoofs = v; }, get MAX_BRAND_SPOOF_HOSTS() { return MAX_BRAND_SPOOF_HOSTS; }, set MAX_BRAND_SPOOF_HOSTS(v) { MAX_BRAND_SPOOF_HOSTS = v; }, get clientCertStoreLoaded() { return clientCertStoreLoaded; }, set clientCertStoreLoaded(v) { clientCertStoreLoaded = v; }, get clientCertStorePath() { return clientCertStorePath; }, set clientCertStorePath(v) { clientCertStorePath = v; }, get clientCertStore() { return clientCertStore; }, set clientCertStore(v) { clientCertStore = v; }, get clientCertSaveTimer() { return clientCertSaveTimer; }, set clientCertSaveTimer(v) { clientCertSaveTimer = v; }, get pendingAuthChallenges() { return pendingAuthChallenges; }, set pendingAuthChallenges(v) { pendingAuthChallenges = v; }, get failAuthCallback() { return failAuthCallback; }, set failAuthCallback(v) { failAuthCallback = v; }, get netAuthGuard() { return netAuthGuard; }, set netAuthGuard(v) { netAuthGuard = v; }, get net() { return net; }, set net(v) { net = v; }, get app() { return app; }, set app(v) { app = v; }, get gpuAccessGuard() { return gpuAccessGuard; }, set gpuAccessGuard(v) { gpuAccessGuard = v; }, get gpuCrashState() { return gpuCrashState; }, set gpuCrashState(v) { gpuCrashState = v; }, get gpuInfoLastReport() { return gpuInfoLastReport; }, set gpuInfoLastReport(v) { gpuInfoLastReport = v; }, get GPU_INFO_REPORT_COOLDOWN_MS() { return GPU_INFO_REPORT_COOLDOWN_MS; }, set GPU_INFO_REPORT_COOLDOWN_MS(v) { GPU_INFO_REPORT_COOLDOWN_MS = v; }, get setupExtraSessionHardeningCtx() { return setupExtraSessionHardeningCtx; }, set setupExtraSessionHardeningCtx(v) { setupExtraSessionHardeningCtx = v; } });
const cosywinmainMod = require('./cosywinmain');
cosywinmainMod.bindDeps({ get readStoredSettings() { return readStoredSettings; }, set readStoredSettings(v) { readStoredSettings = v; }, get isSafeUrl() { return isSafeUrl; }, set isSafeUrl(v) { isSafeUrl = v; }, get createWindowCtx() { return createWindowCtx; }, set createWindowCtx(v) { createWindowCtx = v; }, get registerShortcutsCtx() { return registerShortcutsCtx; }, set registerShortcutsCtx(v) { registerShortcutsCtx = v; }, get urlResolve() { return urlResolve; }, set urlResolve(v) { urlResolve = v; }, get tabs() { return tabs; }, set tabs(v) { tabs = v; }, get TASK_MANAGER_URL() { return TASK_MANAGER_URL; }, set TASK_MANAGER_URL(v) { TASK_MANAGER_URL = v; }, get currentTabIndex() { return currentTabIndex; }, set currentTabIndex(v) { currentTabIndex = v; }, get switchToTab() { return switchToTab; }, set switchToTab(v) { switchToTab = v; }, get createNewTab() { return createNewTab; }, set createNewTab(v) { createNewTab = v; }, get TAB_OVERVIEW_URL() { return TAB_OVERVIEW_URL; }, set TAB_OVERVIEW_URL(v) { TAB_OVERVIEW_URL = v; }, get getHttpStatusCode() { return getHttpStatusCode; }, set getHttpStatusCode(v) { getHttpStatusCode = v; }, get getErrorMessage() { return getErrorMessage; }, set getErrorMessage(v) { getErrorMessage = v; }, get getBrowserErrorText() { return getBrowserErrorText; }, set getBrowserErrorText(v) { getBrowserErrorText = v; }, get sendToRenderer() { return sendToRenderer; }, set sendToRenderer(v) { sendToRenderer = v; }, get CRASH_WINDOW_MS() { return CRASH_WINDOW_MS; }, set CRASH_WINDOW_MS(v) { CRASH_WINDOW_MS = v; }, get CRASH_REASON_TEXT() { return CRASH_REASON_TEXT; }, set CRASH_REASON_TEXT(v) { CRASH_REASON_TEXT = v; }, get MAX_CRASH_AUTO_RECOVER() { return MAX_CRASH_AUTO_RECOVER; }, set MAX_CRASH_AUTO_RECOVER(v) { MAX_CRASH_AUTO_RECOVER = v; }, get mainWindow() { return mainWindow; }, set mainWindow(v) { mainWindow = v; }, get tabKeepsAlive() { return tabKeepsAlive; }, set tabKeepsAlive(v) { tabKeepsAlive = v; }, get updateBrowserViewBounds() { return updateBrowserViewBounds; }, set updateBrowserViewBounds(v) { updateBrowserViewBounds = v; }, get memorySaverEnabled() { return memorySaverEnabled; }, set memorySaverEnabled(v) { memorySaverEnabled = v; }, get MEMORY_SAVER_IDLE_MS() { return MEMORY_SAVER_IDLE_MS; }, set MEMORY_SAVER_IDLE_MS(v) { MEMORY_SAVER_IDLE_MS = v; }, get memorySaverTimer() { return memorySaverTimer; }, set memorySaverTimer(v) { memorySaverTimer = v; }, get MEMORY_SAVER_SWEEP_MS() { return MEMORY_SAVER_SWEEP_MS; }, set MEMORY_SAVER_SWEEP_MS(v) { MEMORY_SAVER_SWEEP_MS = v; }, get loadTabContentCtx() { return loadTabContentCtx; }, set loadTabContentCtx(v) { loadTabContentCtx = v; } });
const cosytabsmainMod = require('./cosytabsmain');
cosyipcwireMod.bootstrapRuntimeState();

// set-tab-muted 静音 / 取消静音指定标签（默认当前标签）。
// tabId 由渲染进程传入，统一转字符串比较，避免类型不一致误判。
// 每个源（origin）记住一个缩放系数，导航 / 刷新后自动恢复，行为对齐 Chrome。
const zoomFactorsByOrigin = new Map();
const MIN_ZOOM_FACTOR = 0.25;
const MAX_ZOOM_FACTOR = 5;
const MAX_REMEMBERED_ORIGINS = 500;
const zoomStorePath = path.join(app.getPath('userData'), 'zoom-store.json');
let zoomSaveTimer = null;

// loadZoomFactors 启动时从 userData 读取按站点记忆的缩放（对齐 Chrome 跨重启保留缩放）。
// 文件损坏 / 被外部塞非法内容时静默丢弃，绝不因此影响浏览器启动。

// persistZoomFactors 防抖落盘，避免连续放大缩小频繁写文件。

// adjustCurrentZoom 是菜单快捷键与 IPC 共用的唯一缩放入口：
// 统一用 setZoomFactor（不要混用 setZoomLevel，二者写同一底层值会互相覆盖），
// 计算结果按 origin 记忆、导航恢复、并持久化到磁盘。

cosyipcwireMod.registerMessagingIpc();

// 页内查找当前状态。查找栏输入会实时更新这里，供 F3 / Ctrl+G 继续查找、
// 以及切换标签后在新标签上自动重查使用。
let findState = { text: '', matchCase: false, wholeWord: false };
// 页内查找 IPC 的输入 / 频率守卫状态（查找栏全局唯一，用单实例即可）。
let findRateState = findGuard.createFindState(Date.now());

// applyFind 在当前活动标签上按 findState 执行一次查找。

const cosyipcwire2Mod = require('./cosyipcwire2');
cosyipcwire2Mod.bindDeps({
    get MAX_HISTORY_ENTRIES() { return MAX_HISTORY_ENTRIES; },
    get Menu() { return Menu; },
    get MenuItem() { return MenuItem; },
    get app() { return app; },
    get bookmarkBarVisible() { return bookmarkBarVisible; },
    set bookmarkBarVisible(v) { bookmarkBarVisible = v; },
    get bookmarks() { return bookmarks; },
    set bookmarks(v) { bookmarks = v; },
    get clipboard() { return clipboard; },
    get closeTab() { return closeTab; },
    get closeTabsByIds() { return closeTabsByIds; },
    get copyExtensionToStorage() { return copyExtensionToStorage; },
    get createContextMenu() { return createContextMenu; },
    get createNewTab() { return createNewTab; },
    get dialog() { return dialog; },
    get discardAllBackgroundTabs() { return discardAllBackgroundTabs; },
    get extensionStore() { return extensionStore; },
    get extensionsPath() { return extensionsPath; },
    get findGuard() { return findGuard; },
    get findRateState() { return findRateState; },
    set findRateState(v) { findRateState = v; },
    get findState() { return findState; },
    set findState(v) { findState = v; },
    get findTabIndexById() { return findTabIndexById; },
    get fs() { return fs; },
    get fsSync() { return fsSync; },
    get getCurrentTabWebContents() { return getCurrentTabWebContents; },
    get getLastClosedTab() { return getLastClosedTab; },
    get history() { return history; },
    set history(v) { history = v; },
    get ipcMain() { return ipcMain; },
    get isBookmarksFrameSender() { return isBookmarksFrameSender; },
    get isHistoryFrameSender() { return isHistoryFrameSender; },
    get isMainSender() { return isMainSender; },
    get isReadingListFrameSender() { return isReadingListFrameSender; },
    get isSafeEntryName() { return isSafeEntryName; },
    get isTabOverviewFrameSender() { return isTabOverviewFrameSender; },
    get ledgerStore() { return ledgerStore; },
    get mainWindow() { return mainWindow; },
    set mainWindow(v) { mainWindow = v; },
    get memorySaverEnabled() { return memorySaverEnabled; },
    set memorySaverEnabled(v) { memorySaverEnabled = v; },
    get openUrlFromInternalFrame() { return openUrlFromInternalFrame; },
    get path() { return path; },
    get planAndCloseTabs() { return planAndCloseTabs; },
    get readExtensionsConfig() { return readExtensionsConfig; },
    get readStoredSettings() { return readStoredSettings; },
    get readingList() { return readingList; },
    set readingList(v) { readingList = v; },
    get recordSecurityEvent() { return recordSecurityEvent; },
    get resetZoom() { return resetZoom; },
    get sanitizeBookmarkLike() { return sanitizeBookmarkLike; },
    get sanitizeSettings() { return sanitizeSettings; },
    get saveBookmarks() { return saveBookmarks; },
    get saveExtensionsConfig() { return saveExtensionsConfig; },
    get saveHistory() { return saveHistory; },
    get sendToRenderer() { return sendToRenderer; },
    get switchToTab() { return switchToTab; },
    get tabGroupModel() { return tabGroupModel; },
    get tabOverviewItem() { return tabOverviewItem; },
    get tabs() { return tabs; },
    set tabs(v) { tabs = v; },
    get toggleTabPinned() { return toggleTabPinned; },
    get unloadExtension() { return unloadExtension; },
    get validateExtensionFolder() { return validateExtensionFolder; },
    get zoomIn() { return zoomIn; },
    get zoomOut() { return zoomOut; },
});
cosyipcwire2Mod.registerFindIpc();

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

cosyipcwire2Mod.registerExtensionIpc();

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

cosyipcregisterMod.registerDownloadShelf();

// sanitizeBookmarkLike 把书签 / 稍后读条目收敛成可进内部页 DOM 的标量快照：
// url、title 限长，addedDate 只接受字符串。两个管理器历史上各自内联了同一段映射，
// 集中到这里，避免标题长度上限或类型收口在某一处被改漏。

// openUrlFromInternalFrame 是历史 / 书签 / 稍后读三个内部页“点击条目新开标签”的
// 公共内核：frameOk 是该页自己的帧来源判定；URL 必须过 isSafeUrl（http/https），
// cosy:// 内置页则交由 createNewTab 的 pageMap 白名单兜底，其余协议一律拒绝。
// 三个 handler 过去逐字复制了同一段校验，集中后任何收紧只需改这一处。

// 历史页快照：全量返回历史数组（上限 1000 条，磁盘加载已按 MAX_HISTORY_ENTRIES
// 截断）。只放行历史页帧 / 主窗口外壳；返回前对每条做类型收口，绝不让脏标题
// 或畸形 URL 进入内部页 DOM。
cosyipcwire2Mod.registerCertificateIpc();

// 稍后读新增（右键菜单“加入稍后读”/页面内部调用）：URL 必须经 isSafeUrl 校验
// （http/https），标题去控制字符并限长。已存在的同 URL 条目忽略（幂等）。

cosyipcregisterMod.registerTabSurfaces();

// ===== 自定义拦截规则 IPC =====
// 规则以字符串行表达：裸域名 / host:x / glob:https://*.x/* / path:https://x/ads/
// 所有写操作后立即持久化并重编译，webRequest 管道下一次判定即生效。

const cosyipcwire3Mod = require('./cosyipcwire3');
cosyipcwire3Mod.bindDeps({
    get SITE_DATA_MAX_NAMES() { return SITE_DATA_MAX_NAMES; },
    get SITE_DATA_MAX_ROWS() { return SITE_DATA_MAX_ROWS; },
    get SITE_DATA_SEARCH_MAX() { return SITE_DATA_SEARCH_MAX; },
    get SITE_DATA_STORAGES() { return SITE_DATA_STORAGES; },
    get SUGGEST_MAX_CHARS() { return SUGGEST_MAX_CHARS; },
    get app() { return app; },
    get blockRules() { return blockRules; },
    get blockTrackers() { return blockTrackers; },
    set blockTrackers(v) { blockTrackers = v; },
    get currentTabIndex() { return currentTabIndex; },
    set currentTabIndex(v) { currentTabIndex = v; },
    get customRules() { return customRules; },
    get customRulesSnapshot() { return customRulesSnapshot; },
    get fetchSearchSuggestions() { return fetchSearchSuggestions; },
    get hostMatch() { return hostMatch; },
    get ipcMain() { return ipcMain; },
    get isMainSender() { return isMainSender; },
    get ledgerStore() { return ledgerStore; },
    get normalizeCookieDomain() { return normalizeCookieDomain; },
    get path() { return path; },
    get persistCustomRules() { return persistCustomRules; },
    get pickCookieFields() { return pickCookieFields; },
    get recordSecurityEvent() { return recordSecurityEvent; },
    get removeCookieEntry() { return removeCookieEntry; },
    get sanitizeSettings() { return sanitizeSettings; },
    get searchProvider() { return searchProvider; },
    get searchProviderId() { return searchProviderId; },
    set searchProviderId(v) { searchProviderId = v; },
    get session() { return session; },
    get tabs() { return tabs; },
    set tabs(v) { tabs = v; },
});
cosyipcwire3Mod.registerBlockRulesIpc();

// ===== 保险库 IPC =====
// 写操作（创建/解锁/写入/删除）均走 COSY_ONLY 分级（见 channelpolicy）；读快照走
// GENERAL。任何 handler 都不回传密文与主密钥。
// vaultPasswordOK：主进程侧主密码收口校验（渲染层另有 UI 限制，此处纵深防御）。
// 规则：必须是字符串；1~256 个可见字符；不含控制字符/NUL；非纯空白；
// UTF-8 编码后不超过 1024 字节，防止超长输入拖垮 PBKDF2 慢化造成 DoS。

cosyipcregisterMod.registerSettingsPanels();

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

// 汇总每个域名下的 Cookie 数量与名称样本，供管理页列表使用。
cosyipcwire3Mod.registerSiteDataIpc();

// 地址栏搜索建议：端点来自 searchprovider 内置白名单（随默认搜索引擎切换），
// 不接受 renderer 传入的任意 URL，避免被当成 SSRF 跳板。返回严格限定为
// 字符串数组并限量。
const SUGGEST_MAX_CHARS = 200;
const SUGGEST_MAX_ITEMS = 8;
const SUGGEST_TIMEOUT_MS = 2500;

// 当前生效的默认搜索引擎 id；随 cosySettings.searchEngine 加载/保存，未知值
// 一律回落内核默认（bing）。
let searchProviderId = searchProvider.DEFAULT_PROVIDER_ID;

cosyipcwire3Mod.registerSearchSuggestIpc();
