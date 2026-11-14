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

const { MAX_RULES, MAX_RULE_LEN, MAX_FILE_BYTES, createEmptyRules, normalizeHostRule, normalizeGlobRule, normalizePathRule, parseRuleLine, addRule, removeRule, importRulesText, exportRulesText, ruleCount } = require('./blockruleparse_core');

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
    const st = fs.lstatSync(filePath);
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
  let tmp = '';
  try {
    const dir = path.dirname(filePath);
    fs.mkdirSync(dir, { recursive: true });
    tmp = path.join(dir, '.blockrules.' + process.pid + '.' + Date.now().toString(36) + '.tmp');
    const json = JSON.stringify(rules, null, 2);
    fs.writeFileSync(tmp, json, 'utf8');
    const fd = fs.openSync(tmp, 'r+');
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(tmp, filePath);
    return { ok: true };
  } catch (err) {
    try { if (tmp) fs.unlinkSync(tmp); } catch { /* ignore */ }
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
