const {
  KIND_SHELL,
  KIND_COSY,
  KIND_INTERNAL_FILE,
} = require('./ipcguard_core');


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
  // 自定义拦截规则写通道：只允许安全内置页（cosy:// 帧）修改规则集。
  'add-block-rule',
  'remove-block-rule',
  'import-block-rules',
  'clear-block-rules',
  // 保险库写通道（创建/解锁/写入/删除/改密/备份合并）：涉及主密钥与敏感条目，只允许内置页。
  'vault-create',
  'vault-unlock',
  'vault-lock',
  'vault-set',
  'vault-update',
  'vault-delete',
  'vault-rekey',
  'vault-import-backup',
  // 清理执行 / 修剪审计：破坏性写，只允许内置页触发。
  'cleaner-execute',
  'cleaner-prune-audit',
  // UA 覆盖策略 / 下载限速的写通道：改的是全局隐私与带宽配置，只允许安全内置页
  // （cosy://privacy）修改，远程网页帧与普通内置页一律拿不到。
  'set-ua-policy',
  'reset-ua-policy',
  'set-download-rate-limit',
  'get-download-max-bytes',
  'set-download-max-bytes',
  'set-search-provider',
  'about-export-diagnostics',
  'about-snapshot',
  'audit-permission-decisions',
  'bookmarks-open-url',
  'bookmarks-remove',
  'bookmarks-rename',
  'bookmarks-snapshot',
  'clear-download-journal',
  'copy-text',
  'get-bookmark-bar-visible',
  'get-download-journal',
  'get-download-journal-export',
  'get-permission-risk-report',
  'get-security-posture',
  'history-clear-all',
  'history-delete-entries',
  'history-delete-entry',
  'history-export-json',
  'history-open-url',
  'history-snapshot',
  'pages-open',
  'pages-snapshot',
  'preview-random-ua',
  'prune-permission-decisions',
  'readinglist-add',
  'readinglist-clear',
  'readinglist-open-url',
  'readinglist-remove',
  'readinglist-snapshot',
  'reconcile-download-journal',
  'set-bookmark-bar-visible',
  'shortcuts-snapshot',
  'show-tab-context-menu',
  'tab-overview-activate',
  'tab-overview-capture',
  'tab-overview-close',
  'tab-overview-snapshot',
]);

// 通用浏览能力：受信帧（外壳 / cosy 内置页 / 证书错误页）都可调用。只登记“读”与
// 常规浏览动作，任何带破坏性 / 凭据 / 配置写的通道都不放这里。

module.exports = {
  TIER_SHELL_ONLY,
  TIER_CERT_FLOW,
  TIER_COSY_ONLY,
  TIER_GENERAL,
  SHELL_ONLY_CHANNELS,
  CERT_FLOW_CHANNELS,
  COSY_ONLY_CHANNELS,
};
