'use strict';


const SEVERITY_CRITICAL = 'critical';

const SEVERITY_WARN = 'warn';

// 精确匹配的危险开关名（不含前导 --，统一小写）。
const CRITICAL_SWITCHES = new Map([
  ['disable-web-security', '关闭同源策略，任意网页可跨域读取数据'],
  ['disable-site-isolation-trial', '关闭站点隔离，跨站进程共址'],
  ['disable-site-isolation', '关闭站点隔离'],
  ['allow-file-access-from-files', '允许 file:// 页面读取其它本地文件'],
  ['allow-file-access', '放开 file:// 访问限制'],
  ['allow-running-insecure-content', '允许 HTTPS 页面加载并执行 HTTP 活动内容'],
  ['ignore-certificate-errors', '全局忽略 TLS 证书错误，中间人可解密'],
  ['ignore-url-fetcher-cert-requests', '忽略证书校验'],
  ['ignore-certificate-errors-spki-list', '为指定公钥跳过证书校验'],
  ['no-sandbox', '关闭渲染/工具进程沙箱'],
  ['disable-gpu-sandbox', '关闭 GPU 进程沙箱'],
  ['disable-setuid-sandbox', '关闭 setuid 沙箱'],
  ['disable-namespace-sandbox', '关闭命名空间沙箱'],
  ['remote-debugging-port', '开放 CDP 远程调试端口，本机任意进程可完全控制浏览器'],
  ['remote-debugging-address', '把远程调试绑定到非回环地址'],
  ['remote-debugging-pipe', '通过管道开放 CDP 控制'],
  ['remote-allow-origins', '放宽 CDP/WebSocket 来源校验'],
  ['inspect', 'Node 检查器（主进程调试）开放'],
  ['inspect-brk', 'Node 检查器启动即停等待调试器'],
  ['proxy-server', '把全部流量强制指向指定代理（可被中间人）'],
  ['proxy-pac-url', '用攻击者 PAC 脚本决定代理路由'],
  ['host-resolver-rules', '重写主机解析，可把任意域名映射到攻击者 IP'],
  ['host-resolver-retry-attempts', '配合 resolver 投毒'],
  ['js-flags', '向 V8 注入参数（可暴露内部接口/关闭缓解）'],
  ['v8-flags', '向 V8 注入参数'],
  ['auth-server-whitelist', '扩大自动凭据协商白名单，外发 NTLM/Kerberos'],
  ['auth-negotiate-delegate-whitelist', '扩大凭据委派白名单'],
  ['explicitly-allowed-ports', '放行被封锁端口，配合内网钓鱼'],
  ['disable-features', '关闭指定安全特性（按值细分，见 analyzeFlag）'],
  ['enable-blink-features', '可开启 IDBInEdgeMode 等高风险 blink 特性'],
  ['enable-features', '强制启用实验特性（仅当命中已知危险值时拦）'],
  ['load-extension', '启动即静默加载未审查扩展'],
  ['disable-extensions-except', '配合加载指定本地扩展目录'],
  ['allow-no-sandbox-job', '配合 no-sandbox 降低作业对象保护'],
  ['disable-web-security-for-seo', '变体关闭同源策略'],
  ['test-type', '隐藏测试警告（常与其它危险开关连用，降硬）'],
  ['single-process', '单进程模式使站点隔离与沙箱失效'],
]);

// 仅 warn：不直接击穿安全模型，但会降低默认防护或留下指纹，记录即可。
const WARN_SWITCHES = new Map([
  ['disable-popup-blocking', '关闭弹窗拦截'],
  ['disable-prompt-on-repost', '关闭表单重复提交提示'],
  ['disable-default-apps', '改变默认应用处理'],
  ['disable-component-update', '关闭组件更新'],
  ['disable-background-networking', '关闭后台网络（可能阻断安全更新/吊销检查）'],
  ['disable-sync', '关闭账号同步'],
  ['password-store=basic', '改用更弱的口令存储后端'],
  ['use-mock-keychain', '使用 mock 密钥链'],
  ['disable-encryption', '关闭本地加密'],
  ['disable-crash-reporter', '关闭崩溃上报'],
  ['enable-logging', '开启可能含敏感 URL 的日志'],
  ['log-net-log', '导出含网络细节的 netlog'],
]);

// disable-features 里一旦出现这些安全相关特性，等同 critical。
const PROTECTED_FEATURES = new Set([
  'SameSiteByDefaultCookies',
  'CookiesWithoutSameSiteMustBeSecure',
  'CorsForContentScripts',
  'BlockInsecurePrivateNetworkRequests',
  'PrivateNetworkAccessChecks',
  'PrivateNetworkAccessSendPreflights',
  'IsolateOrigins',
  'site-per-process',
  'MixedContentAutoupgrade',
  'AutoupgradeMixedContent',
  'HttpsFirstModeV2ForTypicallySecureUsers',
  'HttpsUpgrades',
  'HttpsFirstBalancedModeAutoEnable',
  'TypedCredsProtection',
  'SpareRendererForSitePerProcess',
  'OriginKeyedProcessesByDefault',
  'CrossOriginOpenerPolicy',
  'CrossOriginResourcePolicy',
  'PostQuantumKyber',
]);

// tokenizeSwitchArgs 把一个参数序列切成 flag token。输入既可以是 process.argv（含可执行
// 文件与应用路径），也可以是 ELECTRON_EXTRA_LAUNCH_ARGS split 后的数组。以 -/-- 开头
// 的视为 flag，其余视为位置参数（跳过）。返回 [{raw,name,value,hasValue,source}]。
function tokenizeSwitchArgs(tokens, source) {
  const out = [];
  const list = Array.isArray(tokens) ? tokens : String(tokens || '').split(/\s+/);
  for (const rawToken of list) {
    const raw = String(rawToken || '');
    if (!raw.startsWith('-') || raw === '-' || raw === '--') continue;
    let body = raw.replace(/^--?/, '');
    let name = body;
    let value = '';
    let hasValue = false;
    const eq = body.indexOf('=');
    if (eq >= 0) {
      name = body.slice(0, eq);
      value = body.slice(eq + 1);
      hasValue = true;
    }
    out.push({ raw, name: name.toLowerCase(), value, hasValue, source: source || 'argv' });
  }
  return out;
}

// splitExtraLaunchArgs 解析 ELECTRON_EXTRA_LAUNCH_ARGS 环境变量。它按空白切分，支持
// 引号包裹的值（"--flag=a b"）。
function splitExtraLaunchArgs(envValue) {
  const s = String(envValue || '');
  const out = [];
  let cur = '';
  let q = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if ((ch === '"' || ch === "'") && (q === '' || q === ch)) {
      q = q === ch ? '' : ch;
      continue;
    }
    if (/\s/.test(ch) && q === '') {
      if (cur) { out.push(cur); cur = ''; }
      continue;
    }
    cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

// analyzeFlag 判定单个 flag。返回 {severity,code,reason} 或 null（安全）。
function analyzeFlag(flag) {
  // disable-features / enable-features 按“值里是否含受保护安全特性”细分。
  if (flag.name === 'disable-features' && flag.hasValue) {
    const hit = flag.value.split(/[,]/).map(x => x.trim())
      .find(f => PROTECTED_FEATURES.has(f));
    if (hit) {
      return { severity: SEVERITY_CRITICAL, code: 'switch-disables-protected-feature',
        reason: `关闭受保护安全特性: ${hit}` };
    }
    // 未命中已知受保护特性也降硬，但不阻断（整合包常带大量无关 disable-features）。
    return { severity: SEVERITY_WARN, code: 'switch-disable-features',
      reason: '通过 disable-features 调整特性（未命中受保护清单）' };
  }
  if (flag.name === 'enable-features' && flag.hasValue) {
    // 当前没有必须阻断的启用值；保留判定位，记录降硬即可。
    return null;
  }
  if (CRITICAL_SWITCHES.has(flag.name)) {
    return { severity: SEVERITY_CRITICAL, code: 'switch-critical',
      reason: CRITICAL_SWITCHES.get(flag.name) };
  }
  if (WARN_SWITCHES.has(flag.name)) {
    return { severity: SEVERITY_WARN, code: 'switch-warn',
      reason: WARN_SWITCHES.get(flag.name) };
  }
  return null;
}

module.exports = {
  CRITICAL_SWITCHES,
  PROTECTED_FEATURES,
  SEVERITY_CRITICAL,
  SEVERITY_WARN,
  WARN_SWITCHES,
  analyzeFlag,
  splitExtraLaunchArgs,
  tokenizeSwitchArgs
};
