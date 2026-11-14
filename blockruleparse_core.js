const MAX_RULES = 2000;
const MAX_RULE_LEN = 256;
const MAX_FILE_BYTES = 256 * 1024; // 规则文件大小上限，防被外部写爆后整读入内存
const RULE_RE = /^(host|glob|path):/;

// 默认内置的少量"用户常需自定义"场景示例不落盘；规则集以用户数据为准。
function createEmptyRules() {
  return {
    version: 1,
    host: [],
    glob: [],
    path: [],
  };
}

// normalizeHostRule 校验并规范化 host 规则：小写、去尾点、去空格。
// 返回规范化值或 null（非法）。
function normalizeHostRule(raw) {
  if (typeof raw !== 'string') return null;
  const v = raw.trim().toLowerCase().replace(/\.+$/, '');
  if (!v || v.length > MAX_RULE_LEN) return null;
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(v)) return null;
  if (v.split('.').length < 2) return null; // 单段域名不允许，避免误拦整个 TLD 的代价
  return v;
}

function normalizeUrlRule(raw, requireWildcard) {
  if (typeof raw !== 'string') return null;
  const v = raw.trim();
  if (!v || v.length > MAX_RULE_LEN) return null;
  if (!/^https?:\/\//i.test(v)) return null;
  if (/[\s"'<>\\]/.test(v)) return null;
  if (v.includes('*') !== requireWildcard) return null;
  return v;
}

// normalizeGlobRule 校验 glob 模式：必须是 http(s) URL 模板，含 * 通配，字符集受限。
function normalizeGlobRule(raw) {
  return normalizeUrlRule(raw, true);
}

// normalizePathRule 校验 path 规则：host + 路径前缀。
function normalizePathRule(raw) {
  return normalizeUrlRule(raw, false);
}

// parseRuleLine 解析单行规则文本（支持 "host:evil.com" / "glob:https://*.x/*" / "path:https://x/ads/"）。
// 返回 { kind, value } 或 null。允许不带前缀的裸域名 → 视为 host 规则（最常用）。
function parseRuleLine(line) {
  if (typeof line !== 'string') return null;
  const t = line.trim();
  if (!t || t.startsWith('#')) return null;
  let kind = null;
  let value = t;
  const m = RULE_RE.exec(t);
  if (m) {
    kind = m[1];
    value = t.slice(m[0].length);
  } else if (!/^https?:/i.test(t)) {
    kind = 'host';
  } else {
    kind = 'path';
  }
  let norm;
  if (kind === 'host') norm = normalizeHostRule(value);
  else if (kind === 'glob') norm = normalizeGlobRule(value);
  else if (kind === 'path') norm = normalizePathRule(value);
  else return null;
  if (!norm) return null;
  return { kind, value: norm };
}

// addRule 向规则集添加一条；自动去重，返回 { ok, reason }。
function addRule(rules, raw) {
  const parsed = parseRuleLine(raw);
  if (!parsed) return { ok: false, reason: 'invalid-rule' };
  const list = rules[parsed.kind];
  if (list.includes(parsed.value)) return { ok: true, reason: 'duplicate' };
  const total = rules.host.length + rules.glob.length + rules.path.length;
  if (total >= MAX_RULES) return { ok: false, reason: 'limit' };
  list.push(parsed.value);
  return { ok: true, reason: 'added' };
}

// removeRule 移除一条规则；kind 缺省时三种类型都尝试。
function removeRule(rules, raw) {
  const t = String(raw || '').trim();
  if (!t) return false;
  const m = RULE_RE.exec(t);
  if (m) {
    const kind = m[1];
    const value = t.slice(m[0].length);
    const list = rules[kind];
    if (!list) return false;
    const idx = list.indexOf(value);
    if (idx < 0) return false;
    list.splice(idx, 1);
    return true;
  }
  let removed = false;
  for (const kind of ['host', 'glob', 'path']) {
    const idx = rules[kind].indexOf(t);
    if (idx >= 0) { rules[kind].splice(idx, 1); removed = true; }
  }
  return removed;
}

// importRulesText 从多行文本导入规则；逐条校验，返回统计。
function importRulesText(rules, text) {
  const lines = String(text || '').split(/\r?\n/);
  let added = 0, skipped = 0;
  for (const line of lines) {
    const r = addRule(rules, line);
    if (r.ok) added += 1;
    else if (line.trim() && !line.trim().startsWith('#')) skipped += 1;
  }
  return { added, skipped };
}

// exportRulesText 导出为文本（带类型前缀与注释头）。
function exportRulesText(rules) {
  const out = ['# OpenCosy 自定义拦截规则', '# host: 域名后缀（含子域）  glob: URL 通配  path: 域名+路径前缀'];
  for (const kind of ['host', 'glob', 'path']) {
    for (const v of rules[kind]) out.push(kind + ':' + v);
  }
  return out.join('\n') + '\n';
}

// ruleCount 规则总数。
function ruleCount(rules) {
  return rules.host.length + rules.glob.length + rules.path.length;
}

// globMatch 线性通配匹配：glob 里只有 '*' 是通配符（匹配任意长度的任意字符序列，
// 含空串），其余字符（包括 '?' '[' ']' 等正则元字符）一律按字面值比较，整体要求
// 全串匹配（等价于旧实现的 ^...$ 锚定）。
//
// 安全要点：旧实现把每个 '*' 编译成 '.*' 再 new RegExp，多个/相邻 '*' 会生成
// '.*.*.*' 这类嵌套量词。decideBlocked 跑在“每个子资源请求”的 webRequest 主进程
// 热路径上，一条 '*' 很多的 glob（可经 add/import-block-rules 或被同步的配置写入）
// 对一个不匹配的长 URL 会触发灾难性回溯，直接卡死整个 Electron 主进程。
// 这里改用经典“单星回溯点 + 双指针”迭代算法，时间随文本长度线性增长、占用常量
// 额外空间，结构上不可能出现指数级回溯。

module.exports = {
  MAX_RULES,
  MAX_RULE_LEN,
  MAX_FILE_BYTES,
  RULE_RE,
  createEmptyRules,
  normalizeHostRule,
  normalizeGlobRule,
  normalizePathRule,
  parseRuleLine,
  addRule,
  removeRule,
  importRulesText,
  exportRulesText,
  ruleCount,
};
