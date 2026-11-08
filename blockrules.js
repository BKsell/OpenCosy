'use strict';
// blockrules.js —— 自定义拦截规则内核。
//
// 内置追踪域列表（TRACKER_HOSTS）是静态的，用户无法覆盖特定站点或临时豁免，
// 也无法拦截内置列表没覆盖的私有追踪域。本模块提供：
//   - 三类规则：host（域名后缀，含子域）、glob（URL 通配模式）、path（域名+路径前缀）；
//   - 规则校验与去重（长度/字符集/条数上限），持久化到 userData/blockrules.json；
//   - 决策函数 decideBlocked：自定义规则优先，其次内置追踪域列表；
//   - 导入/导出：文本列表（一行一条），导入时逐条校验、跳过非法条目并回报计数。
//
// 纯内核，不触碰 Electron API；main.js 负责接线（IPC 与 webRequest）。

const fs = require('fs');
const path = require('path');

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

// normalizeGlobRule 校验 glob 模式：必须是 http(s) URL 模板，含 * 通配，字符集受限。
function normalizeGlobRule(raw) {
  if (typeof raw !== 'string') return null;
  const v = raw.trim();
  if (!v || v.length > MAX_RULE_LEN) return null;
  if (!/^https?:\/\//i.test(v)) return null;
  // 只允许 URL 安全字符与 * 通配；禁空格、控制字符、引号。
  if (/[\s"'<>\\]/.test(v)) return null;
  // 必须有 * 才称得上模式（纯固定 URL 用 path 规则更合适）。
  if (!v.includes('*')) return null;
  return v;
}

// normalizePathRule 校验 path 规则：host + 路径前缀。
function normalizePathRule(raw) {
  if (typeof raw !== 'string') return null;
  const v = raw.trim();
  if (!v || v.length > MAX_RULE_LEN) return null;
  if (!/^https?:\/\//i.test(v)) return null;
  if (/[\s"'<>\\]/.test(v)) return null;
  if (v.includes('*')) return null;
  return v;
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
function globMatch(pattern, text) {
  const pn = pattern.length;
  const tn = text.length;
  let p = 0;
  let t = 0;
  let star = -1; // 最近一个 '*' 在 pattern 中的位置
  let anchor = 0; // 该 '*' 当前吞到 text 的哪个位置
  while (t < tn) {
    if (p < pn && pattern[p] !== '*' && pattern[p] === text[t]) {
      p += 1;
      t += 1;
    } else if (p < pn && pattern[p] === '*') {
      star = p;
      anchor = t;
      p += 1; // 先尝试让 '*' 吞空串
    } else if (star !== -1) {
      // 失配：回到最近的 '*'，让它多吞一个字符再重试
      p = star + 1;
      anchor += 1;
      t = anchor;
    } else {
      return false;
    }
  }
  // 文本已吃完，pattern 剩余只允许是一连串 '*'
  while (p < pn && pattern[p] === '*') p += 1;
  return p === pn;
}

// compileRules 预编译 glob 匹配器（线性、有界），避免每次请求都重复构造。
function compileRules(rules) {
  return {
    host: new Set(rules.host.map(v => v.toLowerCase())),
    glob: rules.glob.map(v => ({ src: v, match: (u) => globMatch(v, u) })),
    path: rules.path.map(v => v.toLowerCase()),
  };
}

// hostMatchesCustom 自定义 host 规则匹配（含子域）。
// 返回命中的规则值（最长后缀匹配），未命中返回 null。
function hostMatchesCustom(hostname, hostSet) {
  const h = String(hostname || '').toLowerCase().replace(/\.+$/, '');
  if (!h) return null;
  if (hostSet.has(h)) return h;
  let dot = h.indexOf('.');
  while (dot >= 0) {
    const cand = h.slice(dot + 1);
    if (hostSet.has(cand)) return cand;
    dot = h.indexOf('.', dot + 1);
  }
  return null;
}

// pathMatchesCustom 域名+路径前缀匹配（URL 大小写不敏感化后比较）。
function pathMatchesCustom(rawUrl, pathRules) {
  if (!pathRules.length) return false;
  let u;
  try { u = new URL(rawUrl); } catch { return false; }
  const base = (u.origin + u.pathname).toLowerCase();
  for (const prefix of pathRules) {
    if (base.startsWith(prefix)) return true;
  }
  return false;
}

// decideBlocked 决策函数：
//   1. 自定义规则命中 → blockedBy='custom'；
//   2. 内置追踪域列表命中（仅子资源，由调用方把关 resourceType）→ blockedBy='builtin'；
//   3. 其余放行。
// 返回 null（放行）或 { blockedBy, rule }。
function decideBlocked(rawUrl, compiled, trackerHosts) {
  let host = '';
  try { host = new URL(rawUrl).hostname; } catch { return null; }
  const customHit = hostMatchesCustom(host, compiled.host);
  if (customHit) {
    return { blockedBy: 'custom', rule: customHit };
  }
  for (const g of compiled.glob) {
    if (g.match(rawUrl)) return { blockedBy: 'custom', rule: g.src };
  }
  if (pathMatchesCustom(rawUrl, compiled.path)) {
    const low = rawUrl.toLowerCase();
    const hit = compiled.path.find(p => low.startsWith(p));
    return { blockedBy: 'custom', rule: hit };
  }
  if (trackerHosts && trackerHosts.size) {
    const builtinHit = hostMatchesCustom(host, trackerHosts);
    if (builtinHit) return { blockedBy: 'builtin', rule: builtinHit };
  }
  return null;
}

// loadRules 从磁盘加载规则文件；文件缺失/损坏返回空规则集。
// 结构校验：必为对象、version 为 1、三类数组、元素为字符串且逐条可规范。
function loadRules(filePath) {
  const empty = createEmptyRules();
  try {
    const st = fs.statSync(filePath);
    if (!st.isFile() || st.size > MAX_FILE_BYTES) return empty;
    const text = fs.readFileSync(filePath, 'utf8');
    const data = JSON.parse(text);
    if (!data || typeof data !== 'object' || data.version !== 1) return empty;
    for (const kind of ['host', 'glob', 'path']) {
      if (!Array.isArray(data[kind])) return empty;
      for (const item of data[kind]) {
        if (typeof item !== 'string') return empty;
        if (kind === 'host' && !normalizeHostRule(item)) return empty;
        if (kind === 'glob' && !normalizeGlobRule(item)) return empty;
        if (kind === 'path' && !normalizePathRule(item)) return empty;
      }
      empty[kind] = data[kind].slice(0, MAX_RULES);
    }
    return empty;
  } catch (err) {
    return emptyRulesOrEmpty(err, empty);
  }
}

function emptyRulesOrEmpty(err, empty) {
  void err;
  return empty;
}

// saveRules 原子写规则文件：先写临时文件再 rename，避免半写损坏。
// 返回 { ok, reason }。
function saveRules(filePath, rules) {
  try {
    const dir = path.dirname(filePath);
    fs.mkdirSync(dir, { recursive: true });
    const tmp = path.join(dir, '.blockrules.' + process.pid + '.tmp');
    const json = JSON.stringify(rules, null, 2);
    fs.writeFileSync(tmp, json, 'utf8');
    fs.renameSync(tmp, filePath);
    return { ok: true };
  } catch (err) {
    try { fs.unlinkSync(path.join(path.dirname(filePath), '.blockrules.' + process.pid + '.tmp')); } catch { /* ignore */ }
    return { ok: false, reason: String(err && err.message || err) };
  }
}

// rulesDir 默认规则目录（userData 由调用方注入，保持内核可测）。
function defaultRulesFile(userDataDir) {
  return path.join(userDataDir, 'blockrules.json');
}

module.exports = {
  MAX_RULES,
  MAX_RULE_LEN,
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
  compileRules,
  globMatch,
  decideBlocked,
  loadRules,
  saveRules,
  defaultRulesFile,
  hostMatchesCustom,
};
