'use strict';

// csppolicy.js —— Content-Security-Policy 的结构化解析与风险评估内核（纯逻辑）。
//
// headergrade.js 只对 CSP 做“有没有 / 是否含 unsafe-inline”的粗判。本模块把整段
// 策略解析成 指令->来源列表 的结构，并逐条给出可执行的风险结论：
//   - script-src 放行 unsafe-inline / unsafe-eval / data: / 通配 / http(s): 兜底；
//   - 缺少 script-src（回退 default-src）、default-src；
//   - object-src 缺失（插件向量）、base-uri 缺失（base 标签劫持）、
//     frame-ancestors 缺失（点击劫持）；
//   - 重复指令（浏览器只认第一条，易误配）、未知指令拼写；
//     - nonce / hash 存在时的 unsafe-inline 兼容语义（CSP2+ 下安全）识别；
//   - Report-Only 不产生强制力。
// 全部按字符切分（split/trim/startsWith/includes），不使用正则。

const SEV = Object.freeze({ HIGH: 'high', MEDIUM: 'medium', LOW: 'low', INFO: 'info' });

const FINDING = Object.freeze({
  POLICY_EMPTY: 'csp-policy-empty',
  REPORT_ONLY: 'csp-report-only-not-enforced',
  MISSING_DEFAULT_SRC: 'csp-missing-default-src',
  MISSING_SCRIPT_SRC: 'csp-missing-script-src',
  SCRIPT_UNSAFE_INLINE: 'csp-script-unsafe-inline',
  SCRIPT_UNSAFE_EVAL: 'csp-script-unsafe-eval',
  SCRIPT_WILDCARD: 'csp-script-wildcard',
  SCRIPT_DATA_SCHEME: 'csp-script-data-scheme',
  SCRIPT_HTTP_SCHEME: 'csp-script-http-scheme',
  MISSING_OBJECT_SRC: 'csp-missing-object-src',
  MISSING_BASE_URI: 'csp-missing-base-uri',
  MISSING_FRAME_ANCESTORS: 'csp-missing-frame-ancestors',
  DUPLICATE_DIRECTIVE: 'csp-duplicate-directive',
  UNKNOWN_DIRECTIVE: 'csp-unknown-directive',
  NONCE_PRESENT: 'csp-nonce-present',
  STRICT_DYNAMIC: 'csp-strict-dynamic',
});

// 已知指令（fetch / navigation / 文档 / 其它），用于识别拼写错误。
const KNOWN_DIRECTIVES = new Set([
  'default-src', 'script-src', 'script-src-elem', 'script-src-attr',
  'style-src', 'style-src-elem', 'style-src-attr', 'img-src', 'font-src',
  'connect-src', 'media-src', 'object-src', 'prefetch-src', 'child-src',
  'frame-src', 'worker-src', 'manifest-src', 'navigate-to', 'form-action',
  'base-uri', 'frame-ancestors', 'sandbox', 'report-uri', 'report-to',
  'require-trusted-types-for', 'trusted-types', 'upgrade-insecure-requests',
  'block-all-mixed-content', 'plugin-types', 'referrer',
]);

const NONCE_PREFIX = "'nonce-";
const HASH_PREFIXES = ["'sha256-", "'sha384-", "'sha512-"];

// parseCsp 解析一段 CSP 头值。
function parseCsp(header) {
  const result = {
    directives: new Map(), // name -> [tokens]
    duplicates: [],
    unknown: [],
    nonceDirectives: [],
    hashDirectives: [],
    hasUnsafeInline: new Set(),
    hasUnsafeEval: new Set(),
  };
  if (typeof header !== 'string' || header.trim() === '') {
    result.empty = true;
    return result;
  }
  const parts = header.split(';');
  for (const part of parts) {
    const seg = part.trim();
    if (seg === '') continue;
    const sp = indexOfWhitespace(seg);
    let name, rest;
    if (sp < 0) { name = seg.toLowerCase(); rest = ''; }
    else { name = seg.slice(0, sp).toLowerCase(); rest = seg.slice(sp + 1); }
    const tokens = splitWhitespace(rest);

    if (!KNOWN_DIRECTIVES.has(name)) {
      result.unknown.push(name);
    }
    if (result.directives.has(name)) {
      result.duplicates.push(name);
    } else {
      result.directives.set(name, tokens);
    }
    for (const t of tokens) {
      const tl = t.toLowerCase();
      if (tl === "'unsafe-inline'") result.hasUnsafeInline.add(name);
      if (tl === "'unsafe-eval'") result.hasUnsafeEval.add(name);
      if (tl.startsWith(NONCE_PREFIX)) result.nonceDirectives.push(name);
      if (HASH_PREFIXES.some((p) => tl.startsWith(p))) result.hashDirectives.push(name);
    }
  }
  return result;
}

function indexOfWhitespace(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 32 || c === 9) return i;
  }
  return -1;
}

// splitWhitespace 按空格/制表/换行切分并丢弃空段，纯字符实现（不用正则）。
function splitWhitespace(s) {
  const out = [];
  let i = 0;
  while (i < s.length) {
    while (i < s.length && isWS(s.charCodeAt(i))) i++;
    const start = i;
    while (i < s.length && !isWS(s.charCodeAt(i))) i++;
    if (i > start) out.push(s.slice(start, i));
  }
  return out;
}

function isWS(c) {
  return c === 32 || c === 9 || c === 10 || c === 13 || c === 12;
}

// effectiveScriptSources 返回 script-src 来源；缺省时回退 default-src。
function effectiveScriptSources(parsed) {
  if (parsed.directives.has('script-src')) {
    return { name: 'script-src', tokens: parsed.directives.get('script-src'), fellBack: false };
  }
  if (parsed.directives.has('default-src')) {
    return { name: 'default-src', tokens: parsed.directives.get('default-src'), fellBack: true };
  }
  return { name: '', tokens: [], fellBack: false };
}

function sourcesContain(tokens, target) {
  const t = String(target).toLowerCase();
  return tokens.some((x) => String(x).toLowerCase() === t);
}
function sourcesContainPrefix(tokens, prefix) {
  const p = String(prefix).toLowerCase();
  return tokens.some((x) => String(x).toLowerCase().startsWith(p));
}

// analyzeCsp 给出结构化风险结论。enforced=false 表示该头是 Content-Security-Policy-
// Report-Only（调用方据头名传入）。
function analyzeCsp(header, enforced) {
  const findings = [];
  const add = (id, severity, directive, detail) =>
    findings.push({ id, severity, directive: directive || '', detail: detail || '' });

  const parsed = parseCsp(header);
  if (parsed.empty) {
    add(FINDING.POLICY_EMPTY, SEV.HIGH, '', '没有可解析的 CSP 策略');
    return { findings, parsed };
  }
  if (enforced === false) {
    add(FINDING.REPORT_ONLY, SEV.MEDIUM, '', 'Report-Only 模式只上报不阻断');
  }

  if (!parsed.directives.has('default-src')) {
    add(FINDING.MISSING_DEFAULT_SRC, SEV.MEDIUM, 'default-src', '缺少默认资源来源回退');
  }
  const script = effectiveScriptSources(parsed);
  if (script.name === '') {
    add(FINDING.MISSING_SCRIPT_SRC, SEV.HIGH, 'script-src', 'script-src 与 default-src 均缺失，脚本无白名单约束');
  }

  if (script.tokens.length > 0) {
    const hasNonce = script.tokens.some((t) => t.toLowerCase().startsWith(NONCE_PREFIX));
    const hasHash = script.tokens.some((t) => HASH_PREFIXES.some((p) => t.toLowerCase().startsWith(p)));
    // CSP2+: 同一 script-src 同时给 nonce/hash 与 unsafe-inline 时，浏览器忽略
    // unsafe-inline（对带 nonce 的浏览器），此时降级为信息而非高危。
    if (sourcesContain(script.tokens, "'unsafe-inline'")) {
      if (hasNonce || hasHash) {
        add(FINDING.SCRIPT_UNSAFE_INLINE, SEV.LOW, script.name, '存在 unsafe-inline，但同策略含 nonce/hash，现代浏览器会忽略它');
      } else {
        add(FINDING.SCRIPT_UNSAFE_INLINE, SEV.HIGH, script.name, '脚本来源允许 unsafe-inline，XSS 可直接内联执行');
      }
    }
    if (sourcesContain(script.tokens, "'unsafe-eval'")) {
      add(FINDING.SCRIPT_UNSAFE_EVAL, SEV.HIGH, script.name, '脚本来源允许 unsafe-eval，可动态执行字符串代码');
    }
    if (sourcesContain(script.tokens, '*') || sourcesContain(script.tokens, 'https:') ||
      sourcesContain(script.tokens, 'http:')) {
      add(FINDING.SCRIPT_WILDCARD, SEV.HIGH, script.name, '脚本来源使用通配或 http(s): 全协议兜底，等同放开任意主机');
    }
    if (sourcesContain(script.tokens, 'data:') || sourcesContainPrefix(script.tokens, 'data:')) {
      add(FINDING.SCRIPT_DATA_SCHEME, SEV.HIGH, script.name, '脚本来源允许 data:，可注入 data: URL 脚本');
    }
    if (sourcesContain(script.tokens, 'http:') || sourcesContain(script.tokens, 'https:')) {
      add(FINDING.SCRIPT_HTTP_SCHEME, SEV.MEDIUM, script.name, '脚本来源按 scheme 放行，不校验具体主机');
    }
    if (hasNonce) add(FINDING.NONCE_PRESENT, SEV.INFO, script.name, '脚本来源使用 nonce');
    if (sourcesContain(script.tokens, "'strict-dynamic'")) {
      add(FINDING.STRICT_DYNAMIC, SEV.INFO, script.name, '使用 strict-dynamic，主机白名单将被忽略');
    }
  }

  if (!parsed.directives.has('object-src')) {
    add(FINDING.MISSING_OBJECT_SRC, SEV.MEDIUM, 'object-src', '缺少 object-src，建议设为 \'none\' 关闭插件向量');
  }
  if (!parsed.directives.has('base-uri')) {
    add(FINDING.MISSING_BASE_URI, SEV.MEDIUM, 'base-uri', '缺少 base-uri，可被 <base> 劫持相对脚本地址');
  }
  if (!parsed.directives.has('frame-ancestors')) {
    add(FINDING.MISSING_FRAME_ANCESTORS, SEV.MEDIUM, 'frame-ancestors', '缺少 frame-ancestors，存在点击劫持面');
  }
  for (const d of parsed.duplicates) {
    add(FINDING.DUPLICATE_DIRECTIVE, SEV.LOW, d, '指令重复出现，浏览器通常只采用第一条');
  }
  for (const d of parsed.unknown) {
    add(FINDING.UNKNOWN_DIRECTIVE, SEV.LOW, d, '无法识别的指令名（可能拼写错误）');
  }
  return { findings, parsed };
}

// gradeFor 取最高严重级作为简评级：high>medium>low>info，无问题为 pass。
function gradeFor(findings) {
  let worst = '';
  const rank = { high: 3, medium: 2, low: 1, info: 0 };
  for (const f of findings) {
    if ((rank[f.severity] || 0) > (rank[worst] || -1)) worst = f.severity;
  }
  return worst === '' ? 'pass' : worst;
}

module.exports = {
  SEV, FINDING, KNOWN_DIRECTIVES,
  parseCsp, analyzeCsp, effectiveScriptSources, gradeFor,
};
