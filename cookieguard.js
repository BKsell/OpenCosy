'use strict';

// cookieguard.js —— Set-Cookie 响应头加固的纯逻辑内核（不依赖 Electron）。
//
// 背景：现代浏览器默认“第三方 Cookie 随跨站请求发送/写入 + 没有 SameSite 就当
// 可跨站用”，是跨站追踪和 CSRF 的主要载体；而 __Host- / __Secure- 这两个 Cookie
// 名前缀是浏览器提供的“来源完整性”承诺（Secure、Path=/、不得带 Domain），
// 服务器一旦在不满足条件时使用，浏览器会静默丢弃，页面却往往毫无感知。
//
// 本模块只做确定性判定与改写，供主进程在 webRequest.onHeadersReceived 中对
// Set-Cookie 统一加固：
//   1. 跨站（第三方）上下文写入的 Cookie，开关打开时直接剥离；
//   2. SameSite=None 却缺 Secure：改成 SameSite=Lax（None 必须 Secure，否则
//      浏览器本来就会丢弃，Lax 至少保住第一方登录态）；
//   3. 没写 SameSite 的 Cookie 一律补 SameSite=Lax（对齐 Chrome 默认 Lax）；
//   4. 非安全上下文（http://）却带 Secure：该 Cookie 浏览器不会保存，剥离；
//   5. __Host- / __Secure- 前缀不满足约束时剥离并登记；
// 所有动作按主机聚合进台账，安全中心面板可查。

// 一个解析后的 Set-Cookie 条目。
//   nameValue : 第一个 '=' 之前名字之后的值组成的原始 "name=value" 片段；
//   name      : Cookie 名（未做大小写归一，Cookie 名大小写敏感）；
//   attrs     : 后续属性的原始片段数组（保留原文，改写时按序回拼）；
//   secure    : 是否带 Secure（无值开关）；
//   sameSite  : 'strict' | 'lax' | 'none' | ''（未声明）；
//   domainSet : 是否声明了 Domain；pathSet 是否声明了 Path。
function parseSetCookieEntry(rawLine) {
  const line = String(rawLine == null ? '' : rawLine).trim();
  if (!line) return null;

  const segments = line.split(';');
  const nameValue = (segments.shift() || '').trim();
  const eq = nameValue.indexOf('=');
  // 没有 '=' 或名字为空的 Set-Cookie 无法构成 Cookie，按无效处理。
  if (eq <= 0) return null;
  const name = nameValue.slice(0, eq).trim();
  if (!name) return null;

  const attrs = [];
  let secure = false;
  let sameSite = '';
  let domainSet = false;
  let pathSet = false;

  for (const seg of segments) {
    const rawAttr = seg.trim();
    if (!rawAttr) continue;
    attrs.push(rawAttr);
    const aeq = rawAttr.indexOf('=');
    const attrName = (aeq >= 0 ? rawAttr.slice(0, aeq) : rawAttr).trim().toLowerCase();
    const attrValue = aeq >= 0 ? rawAttr.slice(aeq + 1).trim() : '';
    if (attrName === 'secure') secure = true;
    else if (attrName === 'domain') domainSet = true;
    else if (attrName === 'path') pathSet = true;
    else if (attrName === 'samesite') {
      const v = attrValue.toLowerCase();
      if (v === 'strict' || v === 'lax' || v === 'none') sameSite = v;
      else if (v === '') sameSite = 'lax'; // “SameSite” 无值时按 Lax
      else sameSite = v; // 非法值保留，交给后续按 None/缺省逻辑处理
    }
  }

  return { name, nameValue, attrs, raw: line, secure, sameSite, domainSet, pathSet };
}

// 从 headers 里取出全部 Set-Cookie。Electron 回调里响应头键可能是
// 'Set-Cookie' 或 'set-cookie'，值为字符串或数组。
function extractSetCookieHeaders(headers) {
  if (!headers || typeof headers !== 'object') return [];
  const key = Object.prototype.hasOwnProperty.call(headers, 'set-cookie')
    ? 'set-cookie'
    : (Object.prototype.hasOwnProperty.call(headers, 'Set-Cookie') ? 'Set-Cookie' : '');
  if (!key) return [];
  const v = headers[key];
  if (Array.isArray(v)) return v.slice();
  if (typeof v === 'string') return [v];
  return [];
}

// registrableDomain 取主机的“主域”用于第一方/第三方比较：取最后两段。
// 对常见多级后缀（co.uk/com.cn）没有公共后缀表时会误判，因此这里只做
// “eTLD+1 近似”，跨站判定的权威信号仍交给 Chromium 的 isSameSite（通过
// details.siteForCookies / 同源比较），本函数仅用于聚合台账的展示归并。
const MULTI_PART_SUFFIX = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  'co.jp', 'com.au', 'com.br', 'co.kr',
]);
function registrableDomain(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/\.$/, '');
  const parts = h.split('.').filter(Boolean);
  if (parts.length <= 2) return h;
  const last2 = parts.slice(-2).join('.');
  if (MULTI_PART_SUFFIX.has(last2) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return last2;
}

// hostOf 从 URL 里安全取小写 hostname，失败返回 ''。
function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return ''; }
}

// isThirdPartyContext 判定该响应是否处于跨站（第三方）Cookie 上下文。
// 优先使用 Chromium 在 details 里给出的 siteForCookies（形如 https://host），
// 与响应 URL 的可注册域比较；缺失时回退到 documentURL/originURL。
function isThirdPartyContext(details) {
  const respHost = hostOf(details && details.url);
  if (!respHost) return false;
  const candidates = [details && details.siteForCookies,
    details && details.documentURL, details && details.originURL]
    .filter(u => typeof u === 'string' && /^https?:/i.test(u));
  const respReg = registrableDomain(respHost);
  for (const c of candidates) {
    const ctxHost = hostOf(c);
    if (!ctxHost) continue;
    // about:blank / 顶层初始化时 documentURL 可能就是响应自身，视为第一方。
    if (registrableDomain(ctxHost) !== respReg) return true;
  }
  return false;
}

// cookiePrefixViolation 校验 __Host- / __Secure- 名前缀约束。
// 返回 null 表示合规；否则返回违规原因码。
//   __Host-  ：必须 Secure、Path=/、不得带 Domain；
//   __Secure-：必须 Secure。
function cookiePrefixViolation(entry, isSecureResponse) {
  const n = entry.name;
  if (n.startsWith('__Host-')) {
    if (!isSecureResponse || !entry.secure) return 'host-prefix-not-secure';
    if (entry.domainSet) return 'host-prefix-domain';
    const pathAttr = entry.attrs
      .map(a => (a.indexOf('=') >= 0 ? a.trim() : ''))
      .find(a => a.slice(0, a.indexOf('=')).trim().toLowerCase() === 'path');
    const pathVal = pathAttr ? pathAttr.slice(pathAttr.indexOf('=') + 1).trim() : '';
    if (pathVal !== '/') return 'host-prefix-path';
    return null;
  }
  if (n.startsWith('__Secure-')) {
    if (!isSecureResponse || !entry.secure) return 'secure-prefix-not-secure';
    return null;
  }
  return null;
}

// 从原始属性里去掉所有 SameSite 属性，返回保留原文的其余属性。
function stripSameSiteAttrs(attrs) {
  return attrs.filter(a => {
    const name = (a.indexOf('=') >= 0 ? a.slice(0, a.indexOf('=')) : a).trim().toLowerCase();
    return name !== 'samesite';
  });
}

// hardenSetCookieHeader 对一条响应的全部 Set-Cookie 做加固。
//   headerLines : extractSetCookieHeaders 得到的字符串数组；
//   details     : onHeadersReceived 的 details（用于跨站判定与 URL）；
//   options     : { blockThirdParty:boolean, hardenSameSite:boolean }。
//     blockThirdParty：跨站上下文写入的 Cookie 是否剥离（默认 true）；
//     hardenSameSite ：是否补 SameSite=Lax / 修正 None 缺 Secure（默认 true）。
// 返回 { lines:string[], actions:Action[] }，lines 为应回写的 Set-Cookie 数组
// （被剥离的条目不出现）；actions 记录每个被处理 Cookie 的动作，供台账使用。
function hardenSetCookieHeader(headerLines, details, options) {
  const opts = Object.assign({ blockThirdParty: true, hardenSameSite: true }, options || {});
  const url = (details && details.url) || '';
  const isSecureResponse = /^https:/i.test(url);
  const host = hostOf(url);
  const crossSite = isThirdPartyContext(details);

  const out = [];
  const actions = [];

  for (const rawLine of headerLines) {
    const entry = parseSetCookieEntry(rawLine);
    if (!entry) {
      // 无法解析的畸形 Set-Cookie 原样保留，不在这里静默吞掉。
      out.push(rawLine);
      continue;
    }

    const pushAction = (action, reason) => actions.push({
      host,
      name: entry.name,
      action, // 'block-third-party' | 'drop-invalid-secure' | 'drop-prefix' |
      //       'samesite-none-to-lax' | 'samesite-default-lax'
      reason,
      crossSite,
      time: Date.now(),
    });

    // 1) 跨站上下文写入：开关打开即剥离整个第三方 Cookie。
    //    （SameSite=None 但缺 Secure 的跨站 Cookie 浏览器本就不收，同样剥离记账。）
    if (opts.blockThirdParty && crossSite) {
      pushAction('block-third-party', 'cross-site-set-cookie');
      continue;
    }

    // 2) 非安全上下文却带 Secure：浏览器不会保存，剥离以免产生“看似种下”的错觉。
    if (!isSecureResponse && entry.secure) {
      pushAction('drop-invalid-secure', 'secure-on-insecure-origin');
      continue;
    }

    // 3) 前缀完整性校验不通过：剥离并登记。
    const prefixIssue = cookiePrefixViolation(entry, isSecureResponse);
    if (prefixIssue) {
      pushAction('drop-prefix', prefixIssue);
      continue;
    }

    // 4) SameSite 加固（只改写，不剥离）；关闭 hardenSameSite 时原样保留。
    if (!opts.hardenSameSite) {
      out.push(entry.raw);
      continue;
    }

    let attrs = entry.attrs;
    if (entry.sameSite === 'none' && !entry.secure) {
      // SameSite=None 必须配 Secure；非 HTTPS 下 None 非法，降级为 Lax 保住登录。
      attrs = stripSameSiteAttrs(attrs);
      attrs.push('SameSite=Lax');
      pushAction('samesite-default-lax', 'samesite-none-without-secure');
      out.push([entry.nameValue, ...attrs].join('; '));
    } else if (entry.sameSite === '') {
      // 未声明 SameSite：对齐 Chrome 的默认 Lax。
      attrs.push('SameSite=Lax');
      pushAction('samesite-default-lax', 'samesite-missing-default-lax');
      out.push([entry.nameValue, ...attrs].join('; '));
    } else {
      out.push(entry.raw);
    }
  }

  return { lines: out, actions };
}

// createCookieLedger 是按“主机 + Cookie 名 + 原因”聚合的内存台账，
// 与主进程其它安全台账一致：最近 N 条、命中累加、可序列化落盘。
function createCookieLedger(maxRows) {
  const cap = Math.max(1, Number(maxRows) || 500);
  let rows = [];

  function keyOf(r) {
    return `${r.host}\u0000${r.name}\u0000${r.reason}`;
  }

  function add(action) {
    if (!action || typeof action.host !== 'string') return null;
    const now = Number(action.time) || Date.now();
    const rec = {
      host: String(action.host).slice(0, 255),
      name: String(action.name || '').slice(0, 255),
      action: String(action.action || '').slice(0, 64),
      reason: String(action.reason || '').slice(0, 64),
      crossSite: !!action.crossSite,
      hits: 1,
      lastTime: now,
    };
    const k = keyOf(rec);
    const idx = rows.findIndex(r => keyOf(r) === k);
    if (idx >= 0) {
      const old = rows[idx];
      old.hits += 1;
      old.lastTime = now;
      old.crossSite = rec.crossSite || old.crossSite;
      rows.splice(idx, 1);
      rows.push(old);
      const merged = rows[rows.length - 1];
      if (rows.length > cap) rows.splice(0, rows.length - cap);
      return merged;
    }
    rows.push(rec);
    if (rows.length > cap) rows.splice(0, rows.length - cap);
    return rec;
  }

  function addMany(actions) {
    const touched = [];
    for (const a of actions || []) {
      const r = add(a);
      if (r) touched.push(r);
    }
    return touched;
  }

  function stats() {
    const byReason = {};
    const hosts = new Set();
    let blocked = 0;
    let rewritten = 0;
    for (const r of rows) {
      byReason[r.reason] = (byReason[r.reason] || 0) + r.hits;
      hosts.add(r.host);
      if (r.action === 'samesite-default-lax') rewritten += r.hits;
      else blocked += r.hits;
    }
    return {
      entries: rows.length,
      hosts: hosts.size,
      blocked,
      rewritten,
      totalHits: blocked + rewritten,
      byReason,
    };
  }

  return {
    add,
    addMany,
    list: () => rows.slice().reverse(),
    clear: () => { rows = []; },
    stats,
    size: () => rows.length,
    toJSON: () => ({ version: 1, rows }),
    load(data) {
      rows = [];
      const arr = data && Array.isArray(data.rows) ? data.rows : null;
      if (!arr) return;
      for (const r of arr) {
        if (!r || typeof r !== 'object') continue;
        add({
          host: r.host, name: r.name, action: r.action, reason: r.reason,
          crossSite: r.crossSite, time: r.lastTime,
        });
      }
    },
  };
}

module.exports = {
  parseSetCookieEntry,
  extractSetCookieHeaders,
  registrableDomain,
  isThirdPartyContext,
  cookiePrefixViolation,
  hardenSetCookieHeader,
  createCookieLedger,
};
