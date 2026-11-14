'use strict';

// channelpolicy.js —— 入站 IPC 的“通道 × 帧来源”最小权限分级内核。
//
// 背景：ipcguard 解决了“远程网页 / 用户本地文件不能调 IPC”，但受信帧内部也不是
// 平权的。受信帧有三种：
//   shell         —— 主窗口外壳（设置、安全面板、书签/历史管理等真正的浏览器 UI）；
//   internal-file —— 应用包内置静态页（典型是标签里的证书错误页 src/error.html）；
//   cosy          —— cosy: 内置页（新标签页等）。
// 若对三者一视同仁，那么“任何一个内置页（未来可能被加进包里的静态页）被 XSS”就等价
// 于外壳被攻破：可以清浏览数据、删扩展、导出配置、清空安全台账、删除证书例外。
//
// 本模块把通道分成三级：
//   shell-only  —— 只允许外壳调用：设置/配置导出、扩展管理、清空各类数据与安全台账、
//                  记住的证书/网络认证凭据处置、本地文件哈希等强管理动作；
//   cert-flow   —— 外壳与“证书错误页（internal-file）”可调用：证书例外的查询与放行。
//                  错误页需要“继续前往”按钮，放行是它的正当功能；但删除/清空例外仍属
//                  shell-only。cosy 页不在此列；
//   general     —— 其余浏览类通道（标签导航、刷新、查找、缩放、下载基础操作等），受信
//                  帧都可用。
// 默认（未登记的通道）按 shell-only 处理：新通道默认不给内置页，宁紧勿松。

const {
  KIND_SHELL,
  KIND_COSY,
  KIND_INTERNAL_FILE,
} = require('./ipcguard_core');

const { CERT_FLOW_CHANNELS, COSY_ONLY_CHANNELS, SHELL_ONLY_CHANNELS, TIER_CERT_FLOW, TIER_COSY_ONLY, TIER_GENERAL, TIER_SHELL_ONLY } = require('./channelpolicy_frame_core');
const GENERAL_CHANNELS = new Set([
  // 标签导航
  'create-tab', 'switch-tab', 'close-tab', 'navigate-tab', 'navigate-back',
  'navigate-forward', 'reload-tab', 'stop-loading', 'duplicate-tab',
  'reopen-closed-tab', 'set-tab-muted', 'discard-tab', 'discard-background-tabs',
  'set-tab-pinned', 'toggle-tab-pinned', 'close-tabs-batch',
  'get-tab-groups', 'create-tab-group', 'add-tabs-to-group',
  'remove-tabs-from-group', 'move-tab-to-group', 'rename-tab-group',
  'set-tab-group-color', 'set-tab-group-collapsed', 'move-tab-group',
  'dissolve-tab-group',
  'close-current-tab', 'navigate-to-url', 'reload-tab-by-id', 'reopen-tab-url',
  'get-current-tab', 'get-all-tabs', 'search-tabs', 'print-current-tab',
  'get-recently-closed',
  // 外观 / 标签栏（非持久化敏感配置）
  'toggle-tabbar-collapse',
  // 地址栏 / 查找 / 缩放
  'find-in-page', 'stop-find', 'set-zoom', 'get-search-suggestions',
  'clean-share-url',
  // 菜单与文件选择（只读打开系统对话框，不做清除）
  'show-context-menu', 'show-more-options-menu', 'browse-folder',
  'open-external-url', 'open-file', 'open-folder',
  // 书签 / 历史只读
  'get-bookmarks', 'get-history',
  // 下载常规操作（非清除、非哈希）
  'get-download-info', 'start-download', 'show-save-dialog', 'save-current-page', 'get-downloads',
  'pause-download', 'resume-download', 'cancel-download', 'retry-download',
  'remove-download', 'shelf-show-all', 'get-download-shelf',
  // 页面状态只读
  'get-https-only', 'list-https-exceptions', 'get-network-status', 'get-memory-saver', 'get-trackers',
  'get-block-rules', 'export-block-rules',
  'get-spellcheck-info',
  // 保险库 / 清理中心只读快照（备份导出只回密文 JSON，不涉密钥）
  'vault-status', 'vault-list', 'vault-get', 'vault-export-backup',
  'cleaner-enumerate', 'cleaner-plan', 'cleaner-audit',
  // 任务管理器：进程指标只读；结束标签与 close-tab 同级（handler 内再限定只有
  // cosy://taskmanager 帧、且只能按稳定标签 id 关闭关联到标签的渲染进程）。
  'get-task-manager-processes', 'end-task-manager-tab',
  // 各类安全/隐私面板的“读”通道（清空类在 shell-only）
  'list-site-data', 'get-site-cookies',
  'list-permission-decisions', 'get-protocol-decisions',
  'list-security-events', 'list-csp-reports', 'get-csp-report-stats',
  'list-header-grades', 'get-header-grade-stats',
  'list-request-log', 'get-request-log-stats',
  'list-brand-spoofs', 'get-brand-spoof-stats',
  'list-download-hashes', 'verify-download-hash',
  'get-auth-stats', 'list-remembered-certs',
  'list-cookie-hardening', 'get-cookie-hardening-stats',
  'list-pna-blocks', 'get-pna-block-stats',
  'list-fingerprint-entries', 'get-fingerprint-stats',
  'get-doh-status', 'list-download-risks',
  // UA 策略 / 下载限速 / 搜索引擎的只读快照（写通道在 cosy-only）。
  'get-ua-policy', 'get-download-rate-limit',
  'get-search-provider', 'get-search-suggestions',
]);

/**
 * 返回通道所属的最小权限级别。未显式登记的通道一律按 shell-only 处理（默认拒绝给
 * 内置页），避免将来新增特权通道时被自动下放。
 * @param {string} channel
 * @returns {string}
 */
function channelTier(channel) {
  if (typeof channel !== 'string' || channel === '') return TIER_SHELL_ONLY;
  if (SHELL_ONLY_CHANNELS.has(channel)) return TIER_SHELL_ONLY;
  if (CERT_FLOW_CHANNELS.has(channel)) return TIER_CERT_FLOW;
  if (COSY_ONLY_CHANNELS.has(channel)) return TIER_COSY_ONLY;
  if (GENERAL_CHANNELS.has(channel)) return TIER_GENERAL;
  return TIER_SHELL_ONLY;
}

/**
 * 判定某种帧是否允许调用某通道。
 * 调用方应先用 ipcguard 确认帧是受信帧；本函数只负责受信帧内部的再分级。
 * @param {string} kind ipcguard 的帧类别
 * @param {string} channel 通道名
 * @returns {boolean}
 */
function frameAllows(kind, channel) {
  // 非受信帧一律不允许（双保险，正常情况下在 ipcguard 层就已被拦）。
  if (kind !== KIND_SHELL && kind !== KIND_COSY && kind !== KIND_INTERNAL_FILE) {
    return false;
  }
  if (kind === KIND_SHELL) return true; // 外壳拥有全部通道

  const tier = channelTier(channel);
  if (tier === TIER_SHELL_ONLY) return false;
  if (tier === TIER_GENERAL) return true;
  if (tier === TIER_COSY_ONLY) return kind === KIND_COSY;
  // cert-flow 只对证书错误页（internal-file）开放，cosy 新标签页等不需要。
  return tier === TIER_CERT_FLOW && kind === KIND_INTERNAL_FILE;
}

module.exports = {
  TIER_SHELL_ONLY,
  TIER_CERT_FLOW,
  TIER_COSY_ONLY,
  TIER_GENERAL,
  SHELL_ONLY_CHANNELS,
  CERT_FLOW_CHANNELS,
  COSY_ONLY_CHANNELS,
  GENERAL_CHANNELS,
  channelTier,
  frameAllows,
};
