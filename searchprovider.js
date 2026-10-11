'use strict';

// searchprovider.js —— 默认搜索引擎 / 搜索建议提供方内核。
//
// 威胁模型：地址栏搜索 URL 若由 renderer 自由指定，被攻破的内置页或恶意书签
// 可以把它改成任意 URL 模板，把"输入搜索词"变成一次任意 URL 跳转（甚至带
// 用户输入的 payload 打到内网）；建议接口同理，若端点可配，等于给 SSRF 开
// 后门。历史上 main.js 把建议端点写死为 Bing——安全但不可配置。
//
// 本内核做折中：提供一份内置 provider 白名单（仅允许 https、域名精确/子域
// 匹配、模板必须含 {q} 占位符），用户只能在这份白名单里切换，不能自定义
// 任意模板。模板校验对"可配置项"做最小信任，杜绝模板注入。
//
// 纯函数、无 IO、无网络，供 node:test 与 main.js 直接复用。

const SEARCH_MAX_QUERY = 2000;     // 搜索词上限（防止把巨串灌进 URL）
const SUGGEST_MAX_QUERY = 200;     // 建议词上限（沿用历史限制）
const TEMPLATE_MAX_LEN = 512;      // 模板长度上限
const HOST_MAX_LEN = 253;          // host 上限（DNS 规范）

// BUILTIN_PROVIDERS 是内置提供方。每个条目：
//   id        —— 稳定标识（持久化键）
//   name      —— 展示名
//   home      —— 首页（仅展示）
//   search    —— 搜索 URL 模板，{q} 为查询占位
//   suggest   —— 建议接口模板（可选；osjson/OpenSearch 均以 json 数组返回）
// 全部为 https 且 host 在 allowedHosts 覆盖范围内。
const BUILTIN_PROVIDERS = Object.freeze([
  {
    id: 'bing',
    name: '必应',
    home: 'https://www.bing.com',
    search: 'https://www.bing.com/search?q={q}',
    suggest: 'https://api.bing.com/osjson.aspx?query={q}',
  },
  {
    id: 'baidu',
    name: '百度',
    home: 'https://www.baidu.com',
    search: 'https://www.baidu.com/s?wd={q}',
    suggest: 'https://suggestion.baidu.com/su?wd={q}&json=1&ie=utf-8',
  },
  {
    id: 'google',
    name: '谷歌',
    home: 'https://www.google.com',
    search: 'https://www.google.com/search?q={q}',
    suggest: 'https://www.google.com/complete/search?client=firefox&q={q}',
  },
  {
    id: 'ddg',
    name: 'DuckDuckGo',
    home: 'https://duckduckgo.com',
    search: 'https://duckduckgo.com/?q={q}',
    suggest: 'https://duckduckgo.com/ac/?q={q}&type=list',
  },
]);

// allowedProviderHosts 由内置模板推导，供校验内核使用。
const allowedProviderHosts = Object.freeze([
  'www.bing.com', 'api.bing.com',
  'www.baidu.com', 'suggestion.baidu.com',
  'www.google.com',
  'duckduckgo.com',
]);

const DEFAULT_PROVIDER_ID = 'bing';

function hasControlChar(s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

// hostAllowed：host 精确或子域匹配白名单（label 边界，防前缀伪装）。
function hostAllowed(host, allow) {
  const h = String(host || '').toLowerCase();
  if (!h) return false;
  for (const a of allow) {
    if (h === a) return true;
    if (h.endsWith('.' + a)) return true;
  }
  return false;
}

// validateTemplate 校验 URL 模板：https、长度、含 {q}、host 在白名单、无控制
// 字符。占位符只认精确的 {q}；{q} 之外再出现任何 { } 组合视为可疑模板拒绝。
function validateTemplate(tpl, allow) {
  if (typeof tpl !== 'string' || tpl.length === 0 || tpl.length > TEMPLATE_MAX_LEN) {
    return { ok: false, reason: '模板长度非法' };
  }
  if (!tpl.startsWith('https://')) return { ok: false, reason: '模板必须为 HTTPS' };
  if (hasControlChar(tpl)) return { ok: false, reason: '模板含控制字符' };
  const rest = tpl.slice('https://'.length);
  const at = rest.indexOf('@');
  if (at >= 0) return { ok: false, reason: '模板不允许用户信息' };
  let host;
  const slash = rest.search(/[/?#]/);
  const hostPort = slash < 0 ? rest : rest.slice(0, slash);
  const colon = hostPort.lastIndexOf(':');
  if (colon > 0 && hostPort.indexOf(':', colon + 1) < 0) {
    host = hostPort.slice(0, colon);
  } else {
    host = hostPort;
  }
  host = host.replace(/\.$/, '');
  if (host === '' || host.length > HOST_MAX_LEN) return { ok: false, reason: 'host 非法' };
  if (!hostAllowed(host, allow)) return { ok: false, reason: 'host 不在白名单' };
  // 占位符检查：必须恰好一个 {q}，不允许其它花括号组合（防模板注入其它参数面）。
  const qCount = (tpl.match(/\{q\}/g) || []).length;
  if (qCount !== 1) return { ok: false, reason: '模板必须恰好包含一个 {q} 占位符' };
  if (/\{[^}]*\}/.test(tpl.replace(/\{q\}/g, ''))) return { ok: false, reason: '模板含未知占位符' };
  return { ok: true, host };
}

// providerById 返回内置 provider（深拷贝），未知 id 返回 null。
function providerById(id) {
  if (typeof id !== 'string' || id === '') return null;
  const p = BUILTIN_PROVIDERS.find(x => x.id === id);
  return p ? { ...p } : null;
}

// sanitizeProviderChoice 收敛持久化 / renderer 传入的 provider 选择：
// 未知 id 一律回落默认，保证脏数据不会把搜索引到白名单外。
function sanitizeProviderChoice(raw) {
  if (typeof raw !== 'string') return DEFAULT_PROVIDER_ID;
  return providerById(raw) ? raw : DEFAULT_PROVIDER_ID;
}

// sanitizeQuery 校验查询词：类型、长度、控制字符。
function sanitizeQuery(q, maxLen) {
  if (typeof q !== 'string' || q.trim() === '') return { ok: false, reason: '查询为空' };
  const trimmed = q.trim();
  if (trimmed.length > maxLen) return { ok: false, reason: `查询超过 ${maxLen} 字符` };
  if (hasControlChar(trimmed)) return { ok: false, reason: '查询含控制字符' };
  return { ok: true, q: trimmed };
}

// buildSearchUrl 依据 provider 与查询词生成搜索 URL；任一步校验失败返回 null。
function buildSearchUrl(id, q) {
  const provider = providerById(id);
  if (!provider) return null;
  const v = validateTemplate(provider.search, allowedProviderHosts);
  if (!v.ok) return null;
  const s = sanitizeQuery(q, SEARCH_MAX_QUERY);
  if (!s.ok) return null;
  return provider.search.replace('{q}', encodeURIComponent(s.q));
}

// buildSuggestUrl 同上，用于建议接口；provider 无 suggest 时返回 null。
function buildSuggestUrl(id, q) {
  const provider = providerById(id);
  if (!provider || typeof provider.suggest !== 'string' || provider.suggest === '') return null;
  const v = validateTemplate(provider.suggest, allowedProviderHosts);
  if (!v.ok) return null;
  const s = sanitizeQuery(q, SUGGEST_MAX_QUERY);
  if (!s.ok) return null;
  return provider.suggest.replace('{q}', encodeURIComponent(s.q));
}

// providerSummary 返回给 UI 的只读视图（不含模板，模板是内部细节）。
function providerSummary() {
  return BUILTIN_PROVIDERS.map(p => ({ id: p.id, name: p.name, home: p.home }));
}

// validateTemplatePublic 暴露给测试的模板校验入口。
function validateTemplatePublic(tpl, allow) {
  return validateTemplate(tpl, allow);
}

module.exports = {
  SEARCH_MAX_QUERY,
  SUGGEST_MAX_QUERY,
  TEMPLATE_MAX_LEN,
  HOST_MAX_LEN,
  BUILTIN_PROVIDERS,
  allowedProviderHosts,
  DEFAULT_PROVIDER_ID,
  hasControlChar,
  hostAllowed,
  validateTemplate,
  providerById,
  sanitizeProviderChoice,
  sanitizeQuery,
  buildSearchUrl,
  buildSuggestUrl,
  providerSummary,
  validateTemplatePublic,
};
