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
} = require('./ipcguard');

const TIER_SHELL_ONLY = 'shell-only';
const TIER_CERT_FLOW = 'cert-flow';
const TIER_COSY_ONLY = 'cosy-only';
const TIER_GENERAL = 'general';

// 强管理 / 破坏性 / 凭据类通道：仅主窗口外壳。
const SHELL_ONLY_CHANNELS = new Set([
  // 窗口与设置
  'window-control',
  'save-settings',
  'get-settings',
  'export-config',
  'update-theme-color',
  // 扩展管理（加载/停用/移除扩展等同安装代码）
  'add-extension',
  'get-extensions',
  'toggle-extension',
  'remove-extension',
  // 书签/历史的写操作与批量数据清除
  'import-bookmarks',
  'export-bookmarks',
  'clear-history',
  'clear-browsing-data',
  // 站点数据 / Cookie / 存储清除
  'clear-site-data',
  'delete-site-cookie',
  'delete-site-cookies',
  'clear-site-storage',
  // 权限 / 外部协议决策的批量重置
  'reset-permission-decision',
  'clear-permission-decisions',
  'clear-protocol-decision',
  // 单条权限请求的应答也收口到外壳：否则被攻破的内置页可替用户自动“允许”权限
  'permission-response',
  'reset-trackers',
  // 安全/隐私台账的清空（防止内置页被攻破后销毁证据）
  'clear-downloads',
  'clear-security-events',
  'clear-csp-reports',
  'remove-csp-report',
  'clear-header-grades',
  'clear-request-log',
  'clear-brand-spoofs',
  'clear-download-hashes',
  'remove-download-hash',
  'clear-download-risks',
  'clear-cookie-hardening',
  'clear-pna-blocks',
  'clear-fingerprint-entries',
  'clear-doh-events',
  // 证书例外的“删除/清空”是管理动作（放行 approve 见 cert-flow）
  'remove-cert-exception',
  'clear-cert-exceptions',
  // 网络认证 / 客户端证书凭据
  'submit-network-auth',
  'cancel-network-auth',
  'choose-client-cert',
  'cancel-client-cert',
  'forget-remembered-cert',
  'clear-remembered-certs',
  // 对磁盘任意本地文件算哈希，属于文件读取能力，收口到外壳
  'hash-local-file',
]);

// 证书错误处理流：外壳 + 证书错误页（应用内置 internal-file）。
const CERT_FLOW_CHANNELS = new Set([
  'approve-cert-exception',
  'list-cert-exceptions',
  'get-cert-exception-stats',
  'cert-error-blocked',
  'cert-exception-updated',
]);

const COSY_ONLY_CHANNELS = new Set([
  'add-https-exception',
  'remove-https-exception',
  'clear-https-exceptions',
  // 阅读模式正文数据只允许 cosy://reader 等内置页读取（远程网页帧拿不到）。
  'get-reader-article',
]);

// 通用浏览能力：受信帧（外壳 / cosy 内置页 / 证书错误页）都可调用。只登记“读”与
// 常规浏览动作，任何带破坏性 / 凭据 / 配置写的通道都不放这里。
const GENERAL_CHANNELS = new Set([
  // 标签导航
  'create-tab', 'switch-tab', 'close-tab', 'navigate-tab', 'navigate-back',
  'navigate-forward', 'reload-tab', 'stop-loading', 'duplicate-tab',
  'reopen-closed-tab', 'set-tab-muted', 'discard-tab', 'discard-background-tabs',
  'close-current-tab', 'navigate-to-url', 'reload-tab-by-id', 'reopen-tab-url',
  'get-current-tab', 'get-all-tabs', 'print-current-tab',
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
  'get-download-info', 'start-download', 'show-save-dialog', 'get-downloads',
  'pause-download', 'resume-download', 'cancel-download', 'retry-download',
  'remove-download', 'shelf-show-all', 'get-download-shelf',
  // 页面状态只读
  'get-https-only', 'list-https-exceptions', 'get-network-status', 'get-memory-saver', 'get-trackers',
  'get-spellcheck-info',
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
