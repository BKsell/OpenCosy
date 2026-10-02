'use strict';

// headergrade.js —— 远端站点“响应安全头”纯逻辑评级。
//
// 现代浏览器会替用户兜底很多东西，但一个站点自己有没有下发 HSTS / CSP /
// nosniff / 框架隔离等响应头，仍然直接决定用户在该站点上的暴露面。这里把
// “读响应头 → 打分 → 给修复建议”做成不依赖 Electron 的纯函数，主进程只负责
// 在 webRequest.onHeadersReceived 里喂原始响应头，单元测试可直接 node --test。
//
// 只评级远端 http(s) 顶层文档；内部 cosy:// 页面的头由我们自己强制注入，
// 不参与“给站点打分”。

const MAX_SCORE = 100;

// 单项检查定义。weight 为满分权重；evaluate 返回部分得分（0/half/full）。
const CHECKS = [
  {
    id: 'hsts',
    name: 'HTTP Strict Transport Security (HSTS)',
    weight: 20,
    advice: '缺少 HSTS 时，首次访问仍可能被 SSL 剥离；建议 max-age 至少 15552000（180 天）并带 includeSubDomains。',
  },
  {
    id: 'csp',
    name: 'Content-Security-Policy',
    weight: 20,
    advice: '缺少 CSP 时 XSS 得手后几乎没有第二道防线；建议至少给出 default-src / script-src 白名单，避免 script-src 里的 unsafe-inline。',
  },
  {
    id: 'nosniff',
    name: 'X-Content-Type-Options: nosniff',
    weight: 10,
    advice: '缺少 nosniff 时浏览器可能对非脚本响应做 MIME 嗅探并当脚本执行；固定下发 X-Content-Type-Options: nosniff。',
  },
  {
    id: 'framing',
    name: '点击劫持隔离（X-Frame-Options 或 CSP frame-ancestors）',
    weight: 10,
    advice: '页面可被任意站点 iframe 嵌套，存在点击劫持风险；下发 X-Frame-Options: DENY/SAMEORIGIN 或 CSP frame-ancestors。',
  },
  {
    id: 'referrer',
    name: 'Referrer-Policy',
    weight: 10,
    advice: '未限制 Referrer 时，跨站跳转可能泄露完整 URL；建议 strict-origin-when-cross-origin 或 no-referrer。',
  },
  {
    id: 'permissionsPolicy',
    name: 'Permissions-Policy',
    weight: 10,
    advice: '未用 Permissions-Policy 收敛时，被注入的第三方内容可申请摄像头/麦克风/地理定位等能力；默认全禁用、按需放开。',
  },
  {
    id: 'coop',
    name: 'Cross-Origin-Opener-Policy',
    weight: 10,
    advice: '缺少 COOP 时跨源弹窗可共享浏览上下文组，削弱侧信道隔离；建议 same-origin（需要弹窗联登的场景可用 same-origin-allow-popups）。',
  },
  {
    id: 'corp',
    name: 'Cross-Origin-Resource-Policy',
    weight: 5,
    advice: '文档/资源未声明 CORP，可能被跨源上下文加载；建议 same-origin 或 same-site。',
  },
  {
    id: 'coep',
    name: 'Cross-Origin-Embedder-Policy',
    weight: 5,
    advice: 'COEP 是可选的强隔离项（credentialless / require-corp），开启前需确认跨源资源都已显式放行；权重较低，不强制。',
  },
];

// getResponseHeader 以大小写不敏感方式取第一个响应头值并规范成字符串。
// Electron 的 responseHeaders 通常是 string[]，也兼容直接给字符串的情况。
function getResponseHeader(headers, name) {
  if (!headers || typeof headers !== 'object') return '';
  const target = String(name).toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() !== target) continue;
    const v = headers[key];
    if (Array.isArray(v)) return v.length ? String(v[0] || '') : '';
    return v == null ? '' : String(v);
  }
  return '';
}

function hasHeader(headers, name) {
  return getResponseHeader(headers, name).trim() !== '';
}

function letterForScore(percent) {
  if (percent >= 90) return 'A';
  if (percent >= 75) return 'B';
  if (percent >= 60) return 'C';
  if (percent >= 40) return 'D';
  return 'F';
}

// parseHstsMaxAge 解析 max-age=N，非法时返回 -1。
function parseHstsMaxAge(value) {
  const m = /max-age\s*=\s*(\d+)/i.exec(value || '');
  if (!m) return -1;
  const n = Number(m[1]);
  return Number.isFinite(n) ? n : -1;
}

// gradeSecurityHeaders 返回结构化评级。url 用于取 host / 判断明文传输，
// headers 为响应头对象。该函数无副作用、不抛错（脏输入按“未下发”处理）。
function gradeSecurityHeaders(url, headers) {
  let host = '';
  let scheme = '';
  try {
    const u = new URL(url);
    host = u.host;
    scheme = u.protocol.replace(':', '');
  } catch {
    host = String(url || '').slice(0, 253);
    scheme = '';
  }

  const hsts = getResponseHeader(headers, 'strict-transport-security');
  const csp = getResponseHeader(headers, 'content-security-policy');
  const xcto = getResponseHeader(headers, 'x-content-type-options').toLowerCase();
  const xfo = getResponseHeader(headers, 'x-frame-options').toUpperCase();
  const referrer = getResponseHeader(headers, 'referrer-policy').toLowerCase().trim();
  const permPolicy = getResponseHeader(headers, 'permissions-policy');
  const featurePolicy = getResponseHeader(headers, 'feature-policy'); // 旧名，降级认可
  const coop = getResponseHeader(headers, 'cross-origin-opener-policy').toLowerCase().trim();
  const corp = getResponseHeader(headers, 'cross-origin-resource-policy').toLowerCase().trim();
  const coep = getResponseHeader(headers, 'cross-origin-embedder-policy').toLowerCase().trim();

  const cspLower = csp.toLowerCase();
  const hasCsp = csp.trim() !== '';
  const cspHasSourceDirective = /(?:^|;)\s*(default-src|script-src)\s/.test(cspLower);
  const cspHasUnsafeInlineScript = /script-src[^;]*unsafe-inline/.test(cspLower);
  const frameAncestors = /frame-ancestors\s+[^;']+/.test(cspLower);

  const hstsMaxAge = parseHstsMaxAge(hsts);

  // 每项给 { score, status: pass|partial|missing, note }
  const results = {
    hsts: (() => {
      if (hstsMaxAge >= 15552000) return { score: 1, note: 'max-age 已达 180 天以上' };
      if (hstsMaxAge >= 0) return { score: 0.5, note: '已下发 HSTS，但 max-age 偏短' };
      return { score: 0, note: '' };
    })(),
    csp: (() => {
      if (!hasCsp) return { score: 0, note: '' };
      if (cspHasSourceDirective && !cspHasUnsafeInlineScript) return { score: 1, note: '含来源白名单且 script-src 未放行 unsafe-inline' };
      if (cspHasSourceDirective) return { score: 0.5, note: '含来源白名单，但 script-src 仍允许 unsafe-inline' };
      return { score: 0.5, note: '有 CSP 但缺少 default-src/script-src 收敛' };
    })(),
    nosniff: { score: xcto.includes('nosniff') ? 1 : 0, note: '' },
    framing: { score: (xfo === 'DENY' || xfo === 'SAMEORIGIN' || frameAncestors) ? 1 : 0, note: '' },
    referrer: (() => {
      if (!referrer || referrer === 'unsafe-url') return { score: 0, note: '' };
      return { score: 1, note: '' };
    })(),
    permissionsPolicy: { score: permPolicy.trim() !== '' ? 1 : (featurePolicy.trim() !== '' ? 0.5 : 0), note: featurePolicy && !permPolicy ? '仍在使用已弃用的 Feature-Policy' : '' },
    coop: (() => {
      if (coop === 'same-origin' || coop === 'same-origin-allow-popups') return { score: 1, note: '' };
      return { score: 0, note: '' };
    })(),
    corp: { score: (corp === 'same-origin' || corp === 'same-site') ? 1 : 0, note: '' },
    coep: { score: (coep === 'require-corp' || coep === 'credentialless') ? 1 : 0, note: '' },
  };

  const checks = CHECKS.map(def => {
    const r = results[def.id];
    const score = r.score * def.weight;
    return {
      id: def.id,
      name: def.name,
      weight: def.weight,
      score,
      status: r.score === 1 ? 'pass' : (r.score > 0 ? 'partial' : 'missing'),
      value: (() => {
        const raw = {
          hsts: hsts, csp, nosniff: getResponseHeader(headers, 'x-content-type-options'),
          framing: getResponseHeader(headers, 'x-frame-options'), referrer: getResponseHeader(headers, 'referrer-policy'),
          permissionsPolicy: permPolicy || featurePolicy, coop: getResponseHeader(headers, 'cross-origin-opener-policy'),
          corp: getResponseHeader(headers, 'cross-origin-resource-policy'),
          coep: getResponseHeader(headers, 'cross-origin-embedder-policy'),
        }[def.id];
        return raw ? String(raw).slice(0, 300) : '';
      })(),
      note: r.note || (r.score < 1 ? def.advice : ''),
    };
  });

  // 信息泄露类告警：单独列出，不直接扣主分（属纵深防御观察项）。
  const warnings = [];
  const poweredBy = getResponseHeader(headers, 'x-powered-by');
  if (poweredBy) warnings.push(`X-Powered-By 暴露技术栈：${poweredBy.slice(0, 80)}`);
  const server = getResponseHeader(headers, 'server');
  if (/\d+\.\d+/.test(server)) warnings.push(`Server 头带具体版本号，建议精简：${server.slice(0, 80)}`);
  if (hstsMaxAge >= 0 && !/includesubdomains/i.test(hsts)) {
    warnings.push('HSTS 未带 includeSubDomains，子域仍可能被剥离');
  }

  let score = 0;
  for (const c of checks) score += c.score;

  // 明文 HTTP 顶层文档：传输层不可信，硬封顶 C，且 HSTS 一项不可能真正生效。
  let cap = MAX_SCORE;
  if (scheme === 'http') cap = Math.min(cap, 59);
  score = Math.min(score, cap);

  const percent = Math.round((score / MAX_SCORE) * 100);
  return {
    host,
    scheme,
    score: Math.round(score),
    maxScore: MAX_SCORE,
    percent,
    grade: letterForScore(percent),
    insecureTransport: scheme === 'http',
    checks,
    warnings,
  };
}

module.exports = {
  MAX_SCORE,
  CHECKS,
  getResponseHeader,
  hasHeader,
  letterForScore,
  parseHstsMaxAge,
  gradeSecurityHeaders,
};
