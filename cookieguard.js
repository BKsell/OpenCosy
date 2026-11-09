
const { parseSetCookieEntry, extractSetCookieHeaders, MULTI_PART_SUFFIX, registrableDomain, hostOf, isThirdPartyContext, cookiePrefixViolation } = require('./cookiehelpers');
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
