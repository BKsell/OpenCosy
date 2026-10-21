'use strict';

// formautofillguard.js —— 登录凭据自动填充的按源绑定与表单可信裁决内核。
//
// 威胁模型：
//   浏览器保存账号密码后会在登录页自动填充。自动填充一旦不做来源与表单校验：
//     1. 跨源泄露：凭据按裸域名/模糊后缀匹配，paypal.com.evil.net、子域上的
//        被攻陷页面、http 镜像页都能拿到 https 主站保存的密码；
//     2. 表单外带：页面本身同源，但 <form action="https://collector.evil/">
//        提交到第三方，填充等于把密码喂给外带端点；
//     3. 静默预填被脚本读取：页面一加载（无用户手势）就自动填入真实值，恶意
//        JS 直接读 input.value 窃走；现代缓解是“只在用户选择/交互后填充”；
//     4. 隐藏/伪装字段：不可见的 password 输入框、autocomplete 异常、多个密码
//        框，常被用来在一次交互里多抓一份凭据；
//     5. http 上下文：任何非安全上下文中的密码框都不应填充已保存凭据。
//
// 本模块只持有凭据的“元数据 + 句柄 id”（不接触密码明文，明文由凭据管理器保
// 管），裁决“某条凭据能否填进某个表单”，并校验保存请求的来源归属。纯函数。

const FILL = Object.freeze({
  ALLOW: 'allow',   // 可填充
  MANUAL: 'manual', // 需用户从候选中显式选择
  DENY: 'deny',     // 不得填充
});

// parseAuthority 从可能带路径的完整 URL 中提取 scheme://host:port 的权威部分。
// pageOrigin 必须是纯 origin，因此 parseOrigin 在其基础上额外拒绝路径。
function parseAuthority(rawUrl) {
  if (typeof rawUrl !== 'string') return null;
  const idx = rawUrl.indexOf('://');
  if (idx <= 0) return null;
  const scheme = rawUrl.slice(0, idx).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') return null;
  let rest = rawUrl.slice(idx + 3);
  let cut = rest.length;
  for (let i = 0; i < rest.length; i++) {
    const ch = rest[i];
    if (ch === '/' || ch === '?' || ch === '#') { cut = i; break; }
  }
  const auth = rest.slice(0, cut);
  if (auth === '' || auth.includes('@')) return null;
  let host = auth, port = 0;
  if (host[0] === '[') {
    const close = host.indexOf(']');
    if (close < 0) return null;
    host = host.slice(1, close);
    const tail = auth.slice(close + 1);
    if (tail.startsWith(':')) port = parsePortNum(tail.slice(1));
    else if (tail !== '') return null;
  } else {
    const c = auth.indexOf(':');
    if (c >= 0) { host = auth.slice(0, c); port = parsePortNum(auth.slice(c + 1)); }
  }
  if (host === '' || port < 0) return null;
  host = host.toLowerCase();
  if (host.length > 1 && host.endsWith('.')) host = host.slice(0, -1);
  return { scheme, host, port };
}

// 解析纯 origin 为 {scheme,host,port}，非法返回 null。纯字符切分。
function parseOrigin(origin) {
  if (typeof origin !== 'string') return null;
  const idx = origin.indexOf('://');
  if (idx <= 0) return null;
  // 纯 origin 不含路径/查询/锚点。
  const rest = origin.slice(idx + 3);
  if (rest === '' || rest.includes('/') || rest.includes('?') || rest.includes('#')) return null;
  return parseAuthority(origin);
}

function parsePortNum(s) {
  if (s === '') return 0;
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 48 || c > 57) return -1;
    n = n * 10 + (c - 48);
    if (n > 65535) return -1;
  }
  return n;
}

function originKey(origin) {
  const p = parseOrigin(origin);
  if (!p) return '';
  const def = p.scheme === 'https' ? 443 : 80;
  let k = p.scheme + '://' + p.host;
  if (p.port !== 0 && p.port !== def) k += ':' + p.port;
  return k;
}

// sameRegistrableScope 仅用于“同主机精确匹配”，本内核刻意不做可被绕过的
// eTLD+1 后缀推断：要求 host 与端口（在非默认时）完全一致。
function originsEqual(a, b) {
  return originKey(a) === originKey(b) && originKey(a) !== '';
}

// authorityObjectsEqual 比较两个已解析的权威对象（scheme/host/port 全等）。
function authorityObjectsEqual(a, b) {
  return !!a && !!b &&
    a.scheme === b.scheme && a.host === b.host && a.port === b.port;
}

// describeForm 汇总一个表单的客观可判属性（调用方从 DOM 采集，内核不碰 DOM）。
// {
//   pageOrigin, action (action 属性解析后的绝对 URL，缺省=提交回当前页),
//   method, isSecureContext, hasUserGesture,
//   fields: [{ type:'password'|'text'|'hidden', name, autocomplete, visible, editable }],
//   passwordFieldCount, visiblePasswordFieldCount
// }

// analyzeForm 只陈列客观风险信号，不替调用方下“是不是钓鱼”的定性结论。
// 返回 signals（字符串数组）。
function analyzeForm(form) {
  const signals = [];
  if (!form || typeof form !== 'object') {
    return ['form-missing'];
  }
  if (!form.isSecureContext) {
    signals.push('insecure-context');
  }
  const page = parseOrigin(form.pageOrigin);
  if (!page) {
    signals.push('bad-page-origin');
  }

  // action 缺省 = 提交回当前页（同源）。显式 action 才校验跨主机。
  if (form.action) {
    const action = parseAuthority(form.action);
    if (!action) {
      signals.push('bad-action-origin');
    } else {
      if (action.scheme !== 'https') signals.push('action-insecure-scheme');
      if (page && !authorityObjectsEqual(page, action)) {
        signals.push('action-cross-origin');
      }
    }
  }

  const fields = Array.isArray(form.fields) ? form.fields : [];
  let hiddenPassword = 0, passwordCount = 0, autocompleteOffPassword = 0;
  for (const f of fields) {
    if (!f || typeof f !== 'object') continue;
    if (f.type === 'password') {
      passwordCount++;
      if (f.visible === false || f.editable === false) hiddenPassword++;
      const ac = typeof f.autocomplete === 'string' ? f.autocomplete.toLowerCase().trim() : '';
      if (ac === 'off' || ac === 'false') autocompleteOffPassword++;
    }
    if (f.type === 'hidden') {
      const nm = String(f.name || '').toLowerCase();
      if (nm.includes('pass') || nm.includes('pwd') || nm.includes('secret') || nm.includes('token')) {
        signals.push('hidden-secret-named-field');
      }
    }
  }
  if (passwordCount === 0) signals.push('no-password-field');
  if (hiddenPassword > 0) signals.push('hidden-password-field');
  if (passwordCount >= 3) signals.push('many-password-fields');
  if (autocompleteOffPassword > 0 && passwordCount > 0) signals.push('autocomplete-off-password');
  if (form.hasUserGesture === false) signals.push('no-user-gesture');
  return signals;
}

// decideFill 裁决能否把某条凭据填进表单。
// credential: { id, origin(保存来源), username }；form 见 analyzeForm。
// 硬条件（任一命中直接 DENY）：非安全上下文、坏来源、action 跨源/非 https、
// 无密码字段、隐藏密码框、凭据来源与当前页非精确同源、http 页请求 https 凭据。
// 其次：无用户手势 → MANUAL（必须用户显式选择，不静默预填）。
function decideFill(credential, form) {
  const signals = analyzeForm(form);

  const hardDeny = [
    'form-missing', 'insecure-context', 'bad-page-origin', 'bad-action-origin',
    'action-insecure-scheme', 'action-cross-origin', 'no-password-field',
    'hidden-password-field',
  ];
  for (const s of hardDeny) {
    if (signals.includes(s)) return { decision: FILL.DENY, reason: s, signals };
  }

  if (!credential || typeof credential !== 'object' || !credential.id) {
    return { decision: FILL.DENY, reason: 'bad-credential', signals };
  }
  const credKey = originKey(credential.origin);
  const pageKey = originKey(form.pageOrigin);
  if (!credKey || credKey !== pageKey) {
    return { decision: FILL.DENY, reason: 'credential-origin-mismatch', signals };
  }

  // 无手势：不静默填充，降级为用户手动选择。
  if (signals.includes('no-user-gesture')) {
    return { decision: FILL.MANUAL, reason: 'requires-user-selection', signals };
  }
  // 其余可疑信号（多密码框/autocomplete=off/隐藏秘钥名字段）不硬拦，但要求
  // 用户手动确认，不自动填。
  const soft = ['many-password-fields', 'autocomplete-off-password', 'hidden-secret-named-field'];
  if (soft.some(s => signals.includes(s))) {
    return { decision: FILL.MANUAL, reason: 'ambiguous-form', signals };
  }
  return { decision: FILL.ALLOW, reason: '', signals };
}

// decideSave 裁决“是否允许为当前页保存一条新凭据”。保存同样严格按源绑定，
// 且要求安全上下文、可信表单信号，防止在钓鱼/跨源提交页静默学习密码。
function decideSave(form) {
  const signals = analyzeForm(Object.assign({ hasUserGesture: true }, form || {}));
  const hardDeny = [
    'form-missing', 'insecure-context', 'bad-page-origin', 'bad-action-origin',
    'action-insecure-scheme', 'action-cross-origin', 'no-password-field',
    'hidden-password-field',
  ];
  for (const s of hardDeny) {
    if (signals.includes(s)) return { allow: false, reason: s, signals };
  }
  return { allow: true, reason: '', signals };
}

// CredentialIndex 是按源精确绑定的凭据元数据索引（不含密码明文）。
class CredentialIndex {
  constructor() {
    // originKey -> Map(id -> {id, origin, username})
    this.byOrigin = new Map();
  }

  add(credential) {
    const key = originKey(credential && credential.origin);
    if (!key || !credential.id) return false;
    if (!this.byOrigin.has(key)) this.byOrigin.set(key, new Map());
    this.byOrigin.get(key).set(credential.id, {
      id: credential.id, origin: credential.origin, username: String(credential.username || ''),
    });
    return true;
  }

  // candidatesFor 只返回与页面精确同源的凭据，供手动选择列表使用。
  candidatesFor(pageOrigin) {
    const key = originKey(pageOrigin);
    const m = this.byOrigin.get(key);
    if (!m) return [];
    return Array.from(m.values()).map(c => ({ id: c.id, username: c.username }));
  }

  remove(id) {
    for (const m of this.byOrigin.values()) {
      if (m.delete(id)) return true;
    }
    return false;
  }

  clearOrigin(pageOrigin) {
    return this.byOrigin.delete(originKey(pageOrigin));
  }
}

module.exports = {
  FILL,
  parseOrigin,
  originKey,
  originsEqual,
  analyzeForm,
  decideFill,
  decideSave,
  CredentialIndex,
};
