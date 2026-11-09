'use strict';

const cosyguardmainMod = require('./cosyguardmain');
const cosyledgerchainmainMod = require('./cosyledgerchainmain');
const cosysettingsmainMod = require('./cosysettingsmain');
const cosytabsmainMod = require('./cosytabsmain');
const cosywinmainMod = require('./cosywinmain');

function noteGuardResult(...a) { return cosyguardmainMod.noteGuardResult(...a); }

function noteGuardDenied(...a) { return cosyguardmainMod.noteGuardDenied(...a); }

function allowPopupForTab(...a) { return cosyguardmainMod.allowPopupForTab(...a); }

function getContentsState(...a) { return cosyguardmainMod.getContentsState(...a); }

function reloadCustomRules(...a) { return cosyguardmainMod.reloadCustomRules(...a); }

function loadCustomRulesFromDisk(...a) { return cosyguardmainMod.loadCustomRulesFromDisk(...a); }

function persistCustomRules(...a) { return cosyguardmainMod.persistCustomRules(...a); }

function hostMatchesTracker(...a) { return cosyguardmainMod.hostMatchesTracker(...a); }

function isTrackerRequest(...a) { return cosyguardmainMod.isTrackerRequest(...a); }

function recordBlockedTracker(...a) { return cosyguardmainMod.recordBlockedTracker(...a); }

function topBlockedHosts(...a) { return cosyguardmainMod.topBlockedHosts(...a); }

function isTrackingQueryKey(...a) { return cosyguardmainMod.isTrackingQueryKey(...a); }

function stripTrackingFromUrl(...a) { return cosyguardmainMod.stripTrackingFromUrl(...a); }

function hostnameHasSuspiciousChars(...a) { return cosyguardmainMod.hostnameHasSuspiciousChars(...a); }

function analyzeHostForSpoof(...a) { return cosyguardmainMod.analyzeHostForSpoof(...a); }

function originOf(...a) { return cosyguardmainMod.originOf(...a); }

function sanitizeSpellcheckLanguages(...a) { return cosysettingsmainMod.sanitizeSpellcheckLanguages(...a); }

function applySpellcheckSettings(...a) { return cosysettingsmainMod.applySpellcheckSettings(...a); }

function readPersistedSettings(...a) { return cosysettingsmainMod.readPersistedSettings(...a); }

function isMainSender(...a) { return cosysettingsmainMod.isMainSender(...a); }

function isInternalFileFrame(...a) { return cosysettingsmainMod.isInternalFileFrame(...a); }

function sendToRenderer(...a) { return cosysettingsmainMod.sendToRenderer(...a); }

function shelfSnapshot(...a) { return cosysettingsmainMod.shelfSnapshot(...a); }

function sendShelf(...a) { return cosysettingsmainMod.sendShelf(...a); }

function downloadsStorePath(...a) { return cosysettingsmainMod.downloadsStorePath(...a); }

function persistDownloads(...a) { return cosysettingsmainMod.persistDownloads(...a); }

function notifyDownloadResult(...a) { return cosysettingsmainMod.notifyDownloadResult(...a); }

function getSafeDirs(...a) { return cosysettingsmainMod.getSafeDirs(...a); }

function isInSafeDirs(...a) { return cosysettingsmainMod.isInSafeDirs(...a); }

function getHttpStatusCode(...a) { return cosysettingsmainMod.getHttpStatusCode(...a); }

function getErrorMessage(...a) { return cosysettingsmainMod.getErrorMessage(...a); }

function getBrowserErrorText(...a) { return cosysettingsmainMod.getBrowserErrorText(...a); }

function isSafeUrl(...a) { return cosysettingsmainMod.isSafeUrl(...a); }

function sanitizePath(...a) { return cosysettingsmainMod.sanitizePath(...a); }

function isPathInDir(...a) { return cosysettingsmainMod.isPathInDir(...a); }

function realpathForContainment(...a) { return cosysettingsmainMod.realpathForContainment(...a); }

function isValidColor(...a) { return cosysettingsmainMod.isValidColor(...a); }

function getCurrentTabWebContents(...a) { return cosysettingsmainMod.getCurrentTabWebContents(...a); }

function toggleDevTools(...a) { return cosysettingsmainMod.toggleDevTools(...a); }

function goHome(...a) { return cosysettingsmainMod.goHome(...a); }

function addToHistory(...a) { return cosysettingsmainMod.addToHistory(...a); }

function saveHistory(...a) { return cosysettingsmainMod.saveHistory(...a); }

function loadHistory(...a) { return cosysettingsmainMod.loadHistory(...a); }

function saveBookmarks(...a) { return cosysettingsmainMod.saveBookmarks(...a); }

function loadBookmarks(...a) { return cosysettingsmainMod.loadBookmarks(...a); }

function saveReadingList(...a) { return cosysettingsmainMod.saveReadingList(...a); }

function loadReadingList(...a) { return cosysettingsmainMod.loadReadingList(...a); }

function saveSession(...a) { return cosysettingsmainMod.saveSession(...a); }

function loadSession(...a) { return cosysettingsmainMod.loadSession(...a); }

function clearSession(...a) { return cosysettingsmainMod.clearSession(...a); }

function addToRecentlyClosed(...a) { return cosysettingsmainMod.addToRecentlyClosed(...a); }

function getLastClosedTab(...a) { return cosysettingsmainMod.getLastClosedTab(...a); }

function isPrivateNetworkHost(...a) { return cosysettingsmainMod.isPrivateNetworkHost(...a); }

function readStoredSettings(...a) { return cosysettingsmainMod.readStoredSettings(...a); }

function loadHttpsExceptions(...a) { return cosyledgerchainmainMod.loadHttpsExceptions(...a); }

function persistHttpsExceptions(...a) { return cosyledgerchainmainMod.persistHttpsExceptions(...a); }

function isHttpExceptionHost(...a) { return cosyledgerchainmainMod.isHttpExceptionHost(...a); }

function loadUaPolicyStateFromDisk(...a) { return cosyledgerchainmainMod.loadUaPolicyStateFromDisk(...a); }

function persistUaPolicyState(...a) { return cosyledgerchainmainMod.persistUaPolicyState(...a); }

function persistRateLimitState(...a) { return cosyledgerchainmainMod.persistRateLimitState(...a); }

function applyUaPolicyToSession(...a) { return cosyledgerchainmainMod.applyUaPolicyToSession(...a); }

function resolveEffectiveUa(...a) { return cosyledgerchainmainMod.resolveEffectiveUa(...a); }

function applyRateLimitToItem(...a) { return cosyledgerchainmainMod.applyRateLimitToItem(...a); }

function atomicWriteJSON(...a) { return cosyledgerchainmainMod.atomicWriteJSON(...a); }

function loadVaultStateFromDisk(...a) { return cosyledgerchainmainMod.loadVaultStateFromDisk(...a); }

function persistVaultState(...a) { return cosyledgerchainmainMod.persistVaultState(...a); }

function persistCleanAudit(...a) { return cosyledgerchainmainMod.persistCleanAudit(...a); }

function persistVaultKey(...a) { return cosyledgerchainmainMod.persistVaultKey(...a); }

function maybeFallbackAfterUpgradeFailure(...a) { return cosyledgerchainmainMod.maybeFallbackAfterUpgradeFailure(...a); }

function applyDarkMode(...a) { return cosyledgerchainmainMod.applyDarkMode(...a); }

function loadPnaLedger(...a) { return cosyledgerchainmainMod.loadPnaLedger(...a); }

function persistPnaLedger(...a) { return cosyledgerchainmainMod.persistPnaLedger(...a); }

function pnaLedgerStats(...a) { return cosyledgerchainmainMod.pnaLedgerStats(...a); }

function recordPnaBlock(...a) { return cosyledgerchainmainMod.recordPnaBlock(...a); }

function loadFpLedger(...a) { return cosyledgerchainmainMod.loadFpLedger(...a); }

function persistFpLedger(...a) { return cosyledgerchainmainMod.persistFpLedger(...a); }

function applyWebRtcPolicy(...a) { return cosyledgerchainmainMod.applyWebRtcPolicy(...a); }

function loadDohLedger(...a) { return cosyledgerchainmainMod.loadDohLedger(...a); }

function persistDohLedger(...a) { return cosyledgerchainmainMod.persistDohLedger(...a); }

function dohStatus(...a) { return cosyledgerchainmainMod.dohStatus(...a); }

function applyWebRequestFiltering(...a) { return cosyledgerchainmainMod.applyWebRequestFiltering(...a); }

function originOfContents(...a) { return cosyledgerchainmainMod.originOfContents(...a); }

function persistHeaderGrades(...a) { return cosyledgerchainmainMod.persistHeaderGrades(...a); }

function listHeaderGrades(...a) { return cosyledgerchainmainMod.listHeaderGrades(...a); }

function clearHeaderGrades(...a) { return cosyledgerchainmainMod.clearHeaderGrades(...a); }

function getHeaderGradeStats(...a) { return cosyledgerchainmainMod.getHeaderGradeStats(...a); }

function loadRequestLog(...a) { return cosyledgerchainmainMod.loadRequestLog(...a); }

function persistRequestLog(...a) { return cosyledgerchainmainMod.persistRequestLog(...a); }

function listRequestLogEntries(...a) { return cosyledgerchainmainMod.listRequestLogEntries(...a); }

function getRequestLogStats(...a) { return cosyledgerchainmainMod.getRequestLogStats(...a); }

function clearRequestLog(...a) { return cosyledgerchainmainMod.clearRequestLog(...a); }

function persistBrandSpoofs(...a) { return cosyledgerchainmainMod.persistBrandSpoofs(...a); }

function listBrandSpoofEntries(...a) { return cosyledgerchainmainMod.listBrandSpoofEntries(...a); }

function getBrandSpoofStats(...a) { return cosyledgerchainmainMod.getBrandSpoofStats(...a); }

function clearBrandSpoofs(...a) { return cosyledgerchainmainMod.clearBrandSpoofs(...a); }

function loadClientCertChoices(...a) { return cosyledgerchainmainMod.loadClientCertChoices(...a); }

function persistClientCertChoices(...a) { return cosyledgerchainmainMod.persistClientCertChoices(...a); }

function rejectAuthChallenge(...a) { return cosyledgerchainmainMod.rejectAuthChallenge(...a); }

function getClientCertChoiceStats(...a) { return cosyledgerchainmainMod.getClientCertChoiceStats(...a); }

function setupNetworkStatus(...a) { return cosyledgerchainmainMod.setupNetworkStatus(...a); }

function setupSystemEventGuards(...a) { return cosyledgerchainmainMod.setupSystemEventGuards(...a); }

function setupExtraSessionHardening(...a) { return cosyledgerchainmainMod.setupExtraSessionHardening(...a); }

function getTabLayout(...a) { return cosywinmainMod.getTabLayout(...a); }

function getDefaultTabUrl(...a) { return cosywinmainMod.getDefaultTabUrl(...a); }

function createWindow(...a) { return cosywinmainMod.createWindow(...a); }

function registerShortcuts(...a) { return cosywinmainMod.registerShortcuts(...a); }

function getUrlProtocol(...a) { return cosywinmainMod.getUrlProtocol(...a); }

function openTaskManagerTab(...a) { return cosywinmainMod.openTaskManagerTab(...a); }

function openTabOverviewTab(...a) { return cosywinmainMod.openTabOverviewTab(...a); }

function showErrorPage(...a) { return cosywinmainMod.showErrorPage(...a); }

function pushNavState(...a) { return cosywinmainMod.pushNavState(...a); }

function recordCrash(...a) { return cosywinmainMod.recordCrash(...a); }

function canAutoRecover(...a) { return cosywinmainMod.canAutoRecover(...a); }

function destroyTabView(...a) { return cosywinmainMod.destroyTabView(...a); }

function rebuildCrashedTab(...a) { return cosywinmainMod.rebuildCrashedTab(...a); }

function handleRenderProcessGone(...a) { return cosywinmainMod.handleRenderProcessGone(...a); }

function discardTab(...a) { return cosywinmainMod.discardTab(...a); }

function reloadDiscardedTab(...a) { return cosywinmainMod.reloadDiscardedTab(...a); }

function sweepDiscardableTabs(...a) { return cosywinmainMod.sweepDiscardableTabs(...a); }

function startMemorySaver(...a) { return cosywinmainMod.startMemorySaver(...a); }

function discardAllBackgroundTabs(...a) { return cosywinmainMod.discardAllBackgroundTabs(...a); }

function buildTabPidMap(...a) { return cosywinmainMod.buildTabPidMap(...a); }

function loadTabContent(...a) { return cosywinmainMod.loadTabContent(...a); }

function showCosyError(...a) { return cosywinmainMod.showCosyError(...a); }

function savePinsNow(...a) { return cosytabsmainMod.savePinsNow(...a); }

function persistPins(...a) { return cosytabsmainMod.persistPins(...a); }

function loadStoredPins(...a) { return cosytabsmainMod.loadStoredPins(...a); }

function clearStoredPins(...a) { return cosytabsmainMod.clearStoredPins(...a); }

function findTabIndexById(...a) { return cosytabsmainMod.findTabIndexById(...a); }

function broadcastPinnedState(...a) { return cosytabsmainMod.broadcastPinnedState(...a); }

function applyPinnedState(...a) { return cosytabsmainMod.applyPinnedState(...a); }

function movePinnedTabsToFront(...a) { return cosytabsmainMod.movePinnedTabsToFront(...a); }

function pinTab(...a) { return cosytabsmainMod.pinTab(...a); }

function unpinTab(...a) { return cosytabsmainMod.unpinTab(...a); }

function toggleTabPinned(...a) { return cosytabsmainMod.toggleTabPinned(...a); }

function rehydratePinnedTabs(...a) { return cosytabsmainMod.rehydratePinnedTabs(...a); }

function ensurePinnedTabsOpened(...a) { return cosytabsmainMod.ensurePinnedTabsOpened(...a); }

function closeTabsByIds(...a) { return cosytabsmainMod.closeTabsByIds(...a); }

function planAndCloseTabs(...a) { return cosytabsmainMod.planAndCloseTabs(...a); }

function rehydrateTabGroups(...a) { return cosytabsmainMod.rehydrateTabGroups(...a); }

function sanitizeDownloadFilename(...a) { return cosytabsmainMod.sanitizeDownloadFilename(...a); }

function resolveUniqueDownloadPath(...a) { return cosytabsmainMod.resolveUniqueDownloadPath(...a); }

function rememberDownloadOrigin(...a) { return cosytabsmainMod.rememberDownloadOrigin(...a); }

function persistDownloadRisks(...a) { return cosytabsmainMod.persistDownloadRisks(...a); }

function recordDownloadRisk(...a) { return cosytabsmainMod.recordDownloadRisk(...a); }

function listDownloadRisks(...a) { return cosytabsmainMod.listDownloadRisks(...a); }

function clearDownloadRisks(...a) { return cosytabsmainMod.clearDownloadRisks(...a); }

function analyzeDownloadSafety(...a) { return cosytabsmainMod.analyzeDownloadSafety(...a); }

function handleDownloadEvent(...a) { return cosytabsmainMod.handleDownloadEvent(...a); }

function downloadJournalFileProbe(...a) { return cosytabsmainMod.downloadJournalFileProbe(...a); }

function attachDownloadManager(...a) { return cosytabsmainMod.attachDownloadManager(...a); }

function setupDownloadManager(...a) { return cosytabsmainMod.setupDownloadManager(...a); }

function formatSpeed(...a) { return cosytabsmainMod.formatSpeed(...a); }

function reviewToOpenUrl(...a) { return cosytabsmainMod.reviewToOpenUrl(...a); }

function resolveStartupDeepLink(...a) { return cosytabsmainMod.resolveStartupDeepLink(...a); }

function resolveStartupArgv(...a) { return cosytabsmainMod.resolveStartupArgv(...a); }

function originOfUrl(...a) { return cosytabsmainMod.originOfUrl(...a); }

function applyFind(...a) { return cosytabsmainMod.applyFind(...a); }

function createContextMenu(...a) { return cosytabsmainMod.createContextMenu(...a); }

function sanitizeSettings(...a) { return cosytabsmainMod.sanitizeSettings(...a); }

function sanitizeBookmarkLike(...a) { return cosytabsmainMod.sanitizeBookmarkLike(...a); }

function openUrlFromInternalFrame(...a) { return cosytabsmainMod.openUrlFromInternalFrame(...a); }

function addToReadingList(...a) { return cosytabsmainMod.addToReadingList(...a); }

function customRulesSnapshot(...a) { return cosytabsmainMod.customRulesSnapshot(...a); }

function vaultPasswordOK(...a) { return cosytabsmainMod.vaultPasswordOK(...a); }

module.exports = {
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
};
