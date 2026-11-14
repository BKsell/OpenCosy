'use strict';

const cosyguardmainMod = require('./cosyguardmain_core');
const cosysettingsmainMod = require('./cosysettingsmain_core');
const cosyledgerchainmainMod = require('./cosyledgerchainmain');
const cosywinmainMod = require('./cosywinmain');
const cosytabsmainMod = require('./cosytabsmain_core');

const DELEGATE_GROUPS = [
  [cosyguardmainMod, ['noteGuardResult', 'noteGuardDenied', 'allowPopupForTab', 'getContentsState',
    'reloadCustomRules', 'loadCustomRulesFromDisk', 'persistCustomRules', 'hostMatchesTracker',
    'isTrackerRequest', 'recordBlockedTracker', 'topBlockedHosts', 'isTrackingQueryKey',
    'stripTrackingFromUrl', 'hostnameHasSuspiciousChars', 'analyzeHostForSpoof', 'originOf' ]],
  [cosysettingsmainMod, ['sanitizeSpellcheckLanguages', 'applySpellcheckSettings',
    'readPersistedSettings', 'isMainSender', 'isInternalFileFrame', 'sendToRenderer',
    'shelfSnapshot', 'sendShelf', 'downloadsStorePath', 'persistDownloads', 'notifyDownloadResult',
    'getSafeDirs', 'isInSafeDirs', 'getHttpStatusCode', 'getErrorMessage', 'getBrowserErrorText',
    'isSafeUrl', 'sanitizePath', 'isPathInDir', 'realpathForContainment', 'isValidColor',
    'getCurrentTabWebContents', 'toggleDevTools', 'goHome', 'addToHistory', 'saveHistory',
    'loadHistory', 'saveBookmarks', 'loadBookmarks', 'saveReadingList', 'loadReadingList',
    'saveSession', 'loadSession', 'clearSession', 'addToRecentlyClosed', 'getLastClosedTab',
    'isPrivateNetworkHost', 'readStoredSettings' ]],
  [cosyledgerchainmainMod, ['loadHttpsExceptions', 'persistHttpsExceptions', 'isHttpExceptionHost',
    'loadUaPolicyStateFromDisk', 'persistUaPolicyState', 'persistRateLimitState',
    'applyUaPolicyToSession', 'resolveEffectiveUa', 'applyRateLimitToItem', 'atomicWriteJSON',
    'loadVaultStateFromDisk', 'persistVaultState', 'persistCleanAudit', 'persistVaultKey',
    'maybeFallbackAfterUpgradeFailure', 'applyDarkMode', 'loadPnaLedger', 'persistPnaLedger',
    'pnaLedgerStats', 'recordPnaBlock', 'loadFpLedger', 'persistFpLedger', 'applyWebRtcPolicy',
    'loadDohLedger', 'persistDohLedger', 'dohStatus', 'applyWebRequestFiltering', 'originOfContents',
    'persistHeaderGrades', 'listHeaderGrades', 'clearHeaderGrades', 'getHeaderGradeStats',
    'loadRequestLog', 'persistRequestLog', 'listRequestLogEntries', 'getRequestLogStats',
    'clearRequestLog', 'persistBrandSpoofs', 'listBrandSpoofEntries', 'getBrandSpoofStats',
    'clearBrandSpoofs', 'loadClientCertChoices', 'persistClientCertChoices', 'rejectAuthChallenge',
    'getClientCertChoiceStats', 'setupNetworkStatus', 'setupSystemEventGuards',
    'setupExtraSessionHardening' ]],
  [cosywinmainMod, ['getTabLayout', 'getDefaultTabUrl', 'createWindow', 'registerShortcuts',
    'getUrlProtocol', 'openTaskManagerTab', 'openTabOverviewTab', 'showErrorPage', 'pushNavState',
    'recordCrash', 'canAutoRecover', 'destroyTabView', 'rebuildCrashedTab',
    'handleRenderProcessGone', 'discardTab', 'reloadDiscardedTab', 'sweepDiscardableTabs',
    'startMemorySaver', 'discardAllBackgroundTabs', 'buildTabPidMap', 'loadTabContent',
    'showCosyError' ]],
  [cosytabsmainMod, ['savePinsNow', 'persistPins', 'loadStoredPins', 'clearStoredPins',
    'findTabIndexById', 'broadcastPinnedState', 'applyPinnedState', 'movePinnedTabsToFront',
    'pinTab', 'unpinTab', 'toggleTabPinned', 'rehydratePinnedTabs', 'ensurePinnedTabsOpened',
    'closeTabsByIds', 'planAndCloseTabs', 'rehydrateTabGroups', 'sanitizeDownloadFilename',
    'resolveUniqueDownloadPath', 'rememberDownloadOrigin', 'persistDownloadRisks',
    'recordDownloadRisk', 'listDownloadRisks', 'clearDownloadRisks', 'analyzeDownloadSafety',
    'handleDownloadEvent', 'downloadJournalFileProbe', 'attachDownloadManager',
    'setupDownloadManager', 'formatSpeed', 'reviewToOpenUrl', 'resolveStartupDeepLink',
    'resolveStartupArgv', 'originOfUrl', 'applyFind', 'createContextMenu', 'sanitizeSettings',
    'sanitizeBookmarkLike', 'openUrlFromInternalFrame', 'addToReadingList', 'customRulesSnapshot',
    'vaultPasswordOK' ]],
];

const delegates = {};
for (const [source, names] of DELEGATE_GROUPS) {
  for (const name of names) {
    delegates[name] = (...a) => source[name](...a);
  }
}

module.exports = delegates;
