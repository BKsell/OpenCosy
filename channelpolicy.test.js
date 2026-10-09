'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const cp = require('./channelpolicy');
const g = require('./ipcguard');

const SHELL = g.KIND_SHELL;
const COSY = g.KIND_COSY;
const ERR = g.KIND_INTERNAL_FILE;
const WEB = g.KIND_WEB;
const LOCAL = g.KIND_LOCAL_FILE;

test('channelTier 分级正确', () => {
  assert.equal(cp.channelTier('save-settings'), cp.TIER_SHELL_ONLY);
  assert.equal(cp.channelTier('clear-browsing-data'), cp.TIER_SHELL_ONLY);
  assert.equal(cp.channelTier('add-extension'), cp.TIER_SHELL_ONLY);
  assert.equal(cp.channelTier('remove-cert-exception'), cp.TIER_SHELL_ONLY);
  assert.equal(cp.channelTier('clear-cert-exceptions'), cp.TIER_SHELL_ONLY);
  assert.equal(cp.channelTier('hash-local-file'), cp.TIER_SHELL_ONLY);
  assert.equal(cp.channelTier('approve-cert-exception'), cp.TIER_CERT_FLOW);
  assert.equal(cp.channelTier('list-cert-exceptions'), cp.TIER_CERT_FLOW);
  // 未登记通道默认 shell-only
  assert.equal(cp.channelTier('some-brand-new-channel'), cp.TIER_SHELL_ONLY);
  assert.equal(cp.channelTier(''), cp.TIER_SHELL_ONLY);
  assert.equal(cp.channelTier(null), cp.TIER_SHELL_ONLY);
  // 通用浏览通道
  for (const ch of ['create-tab', 'reload-tab', 'navigate-back', 'find-in-page',
    'set-zoom', 'get-trackers', 'get-network-status', 'get-https-only',
    'retry-download', 'get-search-suggestions']) {
    assert.equal(cp.channelTier(ch), cp.TIER_GENERAL, ch);
  }
});

test('外壳可调用全部通道', () => {
  for (const ch of ['save-settings', 'approve-cert-exception', 'create-tab',
    'clear-browsing-data', 'unknown-channel']) {
    assert.equal(cp.frameAllows(SHELL, ch), true, ch);
  }
});

test('证书错误页只能放行/查询证书例外 + 通用浏览，不能管理/清数据', () => {
  assert.equal(cp.frameAllows(ERR, 'approve-cert-exception'), true);
  assert.equal(cp.frameAllows(ERR, 'list-cert-exceptions'), true);
  assert.equal(cp.frameAllows(ERR, 'reload-tab'), true);
  assert.equal(cp.frameAllows(ERR, 'retry-download'), true);
  // 删除/清空证书例外仍是外壳专属
  assert.equal(cp.frameAllows(ERR, 'remove-cert-exception'), false);
  assert.equal(cp.frameAllows(ERR, 'clear-cert-exceptions'), false);
  // 管理类一律拒绝
  for (const ch of ['save-settings', 'export-config', 'add-extension',
    'clear-browsing-data', 'clear-security-events', 'hash-local-file',
    'submit-network-auth', 'clear-remembered-certs']) {
    assert.equal(cp.frameAllows(ERR, ch), false, ch);
  }
});

test('cosy 新标签页不能走证书放行，只能通用浏览', () => {
  assert.equal(cp.frameAllows(COSY, 'create-tab'), true);
  assert.equal(cp.frameAllows(COSY, 'get-bookmarks'), true);
  assert.equal(cp.frameAllows(COSY, 'approve-cert-exception'), false);
  assert.equal(cp.frameAllows(COSY, 'list-cert-exceptions'), false);
  assert.equal(cp.frameAllows(COSY, 'clear-history'), false);
  assert.equal(cp.frameAllows(COSY, 'import-bookmarks'), false);
});

test('非受信帧在分级层也一律拒绝（双保险）', () => {
  for (const ch of ['create-tab', 'approve-cert-exception', 'reload-tab']) {
    assert.equal(cp.frameAllows(WEB, ch), false, 'web ' + ch);
    assert.equal(cp.frameAllows(LOCAL, ch), false, 'local ' + ch);
    assert.equal(cp.frameAllows(g.KIND_NONE, ch), false, 'none ' + ch);
  }
});

test('shell-only 集合不与 cert-flow 集合重叠', () => {
  for (const ch of cp.CERT_FLOW_CHANNELS) {
    assert.equal(cp.SHELL_ONLY_CHANNELS.has(ch), false, ch);
  }
});

test('全部证书例外相关通道都被显式定级（无遗漏成 general）', () => {
  const certChannels = [
    'approve-cert-exception', 'list-cert-exceptions', 'remove-cert-exception',
    'clear-cert-exceptions', 'get-cert-exception-stats',
  ];
  for (const ch of certChannels) {
    assert.notEqual(cp.channelTier(ch), cp.TIER_GENERAL, ch + ' 不应落入 general');
  }
});

test('四个分级集合两两不相交', () => {
  const all = [cp.SHELL_ONLY_CHANNELS, cp.CERT_FLOW_CHANNELS,
    cp.COSY_ONLY_CHANNELS, cp.GENERAL_CHANNELS];
  for (let i = 0; i < all.length; i++) {
    for (let j = i + 1; j < all.length; j++) {
      for (const ch of all[i]) assert.equal(all[j].has(ch), false, ch);
    }
  }
});

test('HTTPS 例外写操作仅 cosy 内置页，错误页/远程页不可写', () => {
  for (const ch of ['add-https-exception', 'remove-https-exception', 'clear-https-exceptions']) {
    assert.equal(cp.channelTier(ch), cp.TIER_COSY_ONLY, ch);
    assert.equal(cp.frameAllows(COSY, ch), true, 'cosy ' + ch);
    assert.equal(cp.frameAllows(ERR, ch), false, 'err ' + ch);
    assert.equal(cp.frameAllows(WEB, ch), false, 'web ' + ch);
    assert.equal(cp.frameAllows(LOCAL, ch), false, 'local ' + ch);
    assert.equal(cp.frameAllows(SHELL, ch), true, 'shell ' + ch);
  }
  // 只读列表是 general，证书错误页等受信帧也能读。
  assert.equal(cp.channelTier('list-https-exceptions'), cp.TIER_GENERAL);
  assert.equal(cp.frameAllows(ERR, 'list-https-exceptions'), true);
});

test('preload 白名单内每个通道都被显式分级（没有无意落入默认 shell-only 的通道）', () => {
  // 与 preload.js 的 allowedSendChannels / allowedInvokeChannels 保持同步。
  // report-csp-violation 由 allowAnyFrame 放行，不参与帧分级，单独豁免。
  const whitelist = [
    'window-control', 'toggle-tabbar-collapse', 'navigate-to-url', 'save-settings',
    'update-theme-color', 'get-settings', 'export-config', 'show-context-menu',
    'show-more-options-menu', 'get-download-info', 'start-download', 'show-save-dialog',
    'get-downloads', 'pause-download', 'resume-download', 'cancel-download',
    'retry-download', 'remove-download', 'open-file', 'open-folder', 'clear-downloads',
    'shelf-show-all', 'close-current-tab', 'find-in-page', 'stop-find',
    'reload-tab-by-id', 'reopen-tab-url', 'reset-trackers',
    'create-tab', 'switch-tab', 'close-tab', 'navigate-tab', 'navigate-back',
    'navigate-forward', 'reload-tab', 'stop-loading', 'duplicate-tab',
    'reopen-closed-tab', 'set-tab-muted', 'get-current-tab', 'get-all-tabs',
    'set-tab-pinned', 'toggle-tab-pinned', 'close-tabs-batch',
    'add-extension', 'get-extensions', 'toggle-extension', 'remove-extension',
    'browse-folder', 'get-bookmarks', 'export-bookmarks', 'import-bookmarks',
    'get-history', 'clear-history', 'clear-browsing-data', 'get-https-only',
    'get-network-status', 'open-external-url', 'permission-response', 'set-zoom',
    'get-download-shelf', 'clear-site-data', 'list-site-data', 'get-site-cookies',
    'delete-site-cookie', 'delete-site-cookies', 'clear-site-storage',
    'list-permission-decisions', 'reset-permission-decision',
    'clear-permission-decisions', 'get-protocol-decisions', 'clear-protocol-decision',
    'list-security-events', 'clear-security-events', 'list-csp-reports',
    'clear-csp-reports', 'remove-csp-report', 'get-csp-report-stats',
    'list-header-grades', 'clear-header-grades', 'get-header-grade-stats',
    'list-request-log', 'clear-request-log', 'get-request-log-stats',
    'list-brand-spoofs', 'clear-brand-spoofs', 'get-brand-spoof-stats',
    'approve-cert-exception', 'list-cert-exceptions', 'remove-cert-exception',
    'clear-cert-exceptions', 'get-cert-exception-stats', 'list-download-hashes',
    'verify-download-hash', 'remove-download-hash', 'clear-download-hashes',
    'hash-local-file', 'print-current-tab', 'get-search-suggestions',
    'discard-tab', 'discard-background-tabs', 'get-memory-saver', 'get-trackers',
    'get-spellcheck-info', 'submit-network-auth', 'cancel-network-auth',
    'choose-client-cert', 'cancel-client-cert', 'list-remembered-certs',
    'forget-remembered-cert', 'clear-remembered-certs', 'get-auth-stats',
    'list-cookie-hardening', 'get-cookie-hardening-stats', 'clear-cookie-hardening',
    'list-pna-blocks', 'get-pna-block-stats', 'clear-pna-blocks',
    'list-fingerprint-entries', 'get-fingerprint-stats', 'clear-fingerprint-entries',
    'get-doh-status', 'clear-doh-events', 'list-download-risks',
    'clear-download-risks', 'clean-share-url',
    'get-task-manager-processes', 'end-task-manager-tab',
    'list-https-exceptions', 'add-https-exception', 'remove-https-exception',
    'clear-https-exceptions',
    'get-reader-article',
  ];
  const classified = new Set([
    ...cp.SHELL_ONLY_CHANNELS, ...cp.CERT_FLOW_CHANNELS,
    ...cp.COSY_ONLY_CHANNELS, ...cp.GENERAL_CHANNELS,
  ]);
  const missing = [];
  for (const ch of whitelist) {
    if (!classified.has(ch)) missing.push(ch);
  }
  assert.deepEqual(missing, [], 'preload 白名单内每个通道都必须被显式分级');
});

test('clear-downloads 是破坏性清空动作，显式归 shell-only', () => {
  assert.equal(cp.channelTier('clear-downloads'), cp.TIER_SHELL_ONLY);
});

test('get-reader-article 只允许 cosy 内置页读取，网页 / 证书页拿不到正文', () => {
  assert.equal(cp.channelTier('get-reader-article'), cp.TIER_COSY_ONLY);
  assert.equal(cp.frameAllows(COSY, 'get-reader-article'), true);
  assert.equal(cp.frameAllows(SHELL, 'get-reader-article'), true);
  assert.equal(cp.frameAllows(WEB, 'get-reader-article'), false);
  assert.equal(cp.frameAllows(ERR, 'get-reader-article'), false);
  assert.equal(cp.frameAllows(LOCAL, 'get-reader-article'), false);
});
