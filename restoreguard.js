'use strict';

// restoreguard.js —— 退出 / 崩溃后“会话标签恢复”与“最近关闭标签”落盘读取的
// 写入净化 + 逐条校验 + 有界维护内核。
//
// 威胁模型：
//   OpenCosy 在退出时把仍打开的站点标签写到 userData/session.json（{url,title}
//   数组），启动时读回并重新打开；最近关闭标签则是内存里的 {url,title,closedAt}
//   栈。旧实现存在几个真实面：
//     1. saveSession 只用 isSafeUrl 过滤 url，title 原样写入；title 来自远端，可塞
//        NUL / CR / LF / ESC 等控制字符或数万字符超长标题，污染 session.json 与
//        启动恢复时的标签 UI（存储型 DoS / 终端转义注入）。
//     2. loadSession 只做 Array.isArray + length>0，再 .filter(isSafeUrl)，没有逐条
//        对象 / 字段类型校验：手改或崩溃损坏的 session.json 可塞入 null、数字、嵌套
//        数组，恢复时访问 tab.title 直接抛异常，阻断全部标签恢复。
//     3. 会话 / 最近关闭都没有条数硬上界，恶意页面诱导开海量标签会把 session.json
//        撑大，启动时一次性重建大量 WebContents，形成启动放大攻击。
//     4. 恢复只应承载 http/https 站点标签；file:/javascript:/data: 等内部或本地
//        scheme 不应在启动时被自动重新打开（本地文件自动加载是信息泄露 / 自动执行面）。
//   本内核只做纯函数，不碰文件系统与 Electron API；main.js 的 saveSession /
//   loadSession / addToRecentlyClosed / getLastClosedTab 复用这里的裁决。

// 恢复允许承载的协议：仅站点地址。
const ALLOWED_PROTOCOLS = Object.freeze(['http:', 'https:']);
const MAX_TITLE_CHARS = 300;
const MAX_URL_CHARS = 8192;
// 会话恢复最多重建的标签数：防止“开几十万标签→退出→启动”一次性放大。
const MAX_SESSION_TABS = 200;
// 最近关闭标签栈深度（与 main.js 历史常量保持一致）。
const MAX_RECENTLY_CLOSED = 10;

const SKIP_NOT_OBJECT = 'not-object';
const SKIP_BAD_URL = 'bad-url';
const SKIP_BAD_PROTOCOL = 'disallowed-protocol';
const SKIP_URL_TOO_LONG = 'url-too-long';
const SKIP_BAD_TIME = 'bad-time';

const constants = Object.freeze({
  ALLOWED_PROTOCOLS,
  MAX_TITLE_CHARS,
  MAX_URL_CHARS,
  MAX_SESSION_TABS,
  MAX_RECENTLY_CLOSED,
  SKIP_NOT_OBJECT,
  SKIP_BAD_URL,
  SKIP_BAD_PROTOCOL,
  SKIP_URL_TOO_LONG,
  SKIP_BAD_TIME,
});

function stripControlChars(s) {
  return String(s).replace(/[\u0000-\u001F\u007F]/g, '');
}

function collapseSpaces(s) {
  return s.replace(/\s+/g, ' ').trim();
}

// sanitizeRestoreTitle 清洗恢复标签标题：制表 / 换行 / 回车先归一为空格，再删除其余
// 控制字符，压空白，截断上界。非字符串给空串。
function sanitizeRestoreTitle(rawTitle) {
  let t = typeof rawTitle === 'string' ? rawTitle : '';
  t = t.replace(/[\t\n\r]+/g, ' ');
  t = collapseSpaces(stripControlChars(t));
  if (t.length > MAX_TITLE_CHARS) t = t.slice(0, MAX_TITLE_CHARS);
  return t;
}

// sanitizeRestoreUrl 校验可恢复的标签 URL：仅 http/https、可解析、长度有界、host
// 非空。返回 {ok,url,reason}。
function sanitizeRestoreUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0) {
    return { ok: false, url: '', reason: SKIP_BAD_URL };
  }
  if (rawUrl.length > MAX_URL_CHARS) {
    return { ok: false, url: '', reason: SKIP_URL_TOO_LONG };
  }
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    return { ok: false, url: '', reason: SKIP_BAD_URL };
  }
  if (!ALLOWED_PROTOCOLS.includes(u.protocol)) {
    return { ok: false, url: '', reason: SKIP_BAD_PROTOCOL };
  }
  if (!u.hostname) {
    return { ok: false, url: '', reason: SKIP_BAD_URL };
  }
  return { ok: true, url: u.href, reason: '' };
}

function fallbackTitleFor(u) {
  try {
    return u.hostname.replace(/^www\./i, '') || u.href;
  } catch {
    return u.href;
  }
}

// sanitizeSessionTab 校验并规范化单个待恢复标签 {url,title}。
// url 非法整条丢弃；title 净化，空则用 host 兜底。
function sanitizeSessionTab(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, tab: null, reason: SKIP_NOT_OBJECT };
  }
  const su = sanitizeRestoreUrl(input.url);
  if (!su.ok) return { ok: false, tab: null, reason: su.reason };
  let u;
  try {
    u = new URL(su.url);
  } catch {
    return { ok: false, tab: null, reason: SKIP_BAD_URL };
  }
  let title = sanitizeRestoreTitle(input.title);
  if (!title) title = fallbackTitleFor(u);
  return { ok: true, tab: { url: su.url, title }, reason: '' };
}

// sanitizeSessionList 读取 session.json 的总入口：任意 JSON 值收敛成干净标签数组。
// 非数组视为空（无法恢复）；逐条校验，非法丢弃；截断到 MAX_SESSION_TABS。
// 返回 {tabs,dropped}。
function sanitizeSessionList(rawList) {
  const tabs = [];
  let dropped = 0;
  if (Array.isArray(rawList)) {
    for (const raw of rawList) {
      const r = sanitizeSessionTab(raw);
      if (!r.ok) {
        dropped += 1;
        continue;
      }
      if (tabs.length >= MAX_SESSION_TABS) {
        dropped += 1;
        continue;
      }
      tabs.push(r.tab);
    }
  }
  return { tabs, dropped };
}

// isValidClosedAt 判定最近关闭条目的 closedAt 是否为有限非负毫秒时间戳。
function isValidClosedAt(v) {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0;
}

// sanitizeClosedTab 校验并规范化最近关闭条目 {url,title,closedAt}。
// closedAt 非法 / 缺失时用 now 补（now 必须是有限毫秒时间戳）。
function sanitizeClosedTab(input, now) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, tab: null, reason: SKIP_NOT_OBJECT };
  }
  const base = sanitizeSessionTab(input);
  if (!base.ok) return { ok: false, tab: null, reason: base.reason };
  const closedAt = isValidClosedAt(input.closedAt) ? input.closedAt : now;
  return { ok: true, tab: { url: base.tab.url, title: base.tab.title, closedAt }, reason: '' };
}

// createRecentlyClosedState 生成独立的最近关闭栈（items 为入栈顺序，末尾最新）。
function createRecentlyClosedState(initialItems) {
  const items = Array.isArray(initialItems) ? initialItems.slice(0, MAX_RECENTLY_CLOSED) : [];
  return { items };
}

// pushRecentlyClosed 关闭一个标签时入栈：净化后压到末尾，超深丢弃最旧（队首）。
// 返回 {status,tab}：status 为 'pushed' | 'rejected'。
function pushRecentlyClosed(state, input, now) {
  if (!state || !Array.isArray(state.items)) {
    return { status: 'rejected', tab: null, reason: SKIP_NOT_OBJECT };
  }
  const r = sanitizeClosedTab(input, now);
  if (!r.ok) return { status: 'rejected', tab: null, reason: r.reason };
  state.items.push(r.tab);
  if (state.items.length > MAX_RECENTLY_CLOSED) state.items.shift();
  return { status: 'pushed', tab: r.tab, reason: '' };
}

// popLastClosed 弹出最近关闭的标签（末尾最新）；栈空返回 null。
function popLastClosed(state) {
  if (!state || !Array.isArray(state.items) || state.items.length === 0) return null;
  return state.items.pop();
}

// sanitizeRecentlyClosedList 把任意 JSON 值收敛成干净的最近关闭栈，逐条净化并截断。
function sanitizeRecentlyClosedList(rawList, now) {
  const items = [];
  let dropped = 0;
  if (Array.isArray(rawList)) {
    for (const raw of rawList) {
      const r = sanitizeClosedTab(raw, now);
      if (!r.ok) {
        dropped += 1;
        continue;
      }
      if (items.length >= MAX_RECENTLY_CLOSED) {
        dropped += 1;
        continue;
      }
      items.push(r.tab);
    }
  }
  return { items, dropped };
}

module.exports = Object.freeze(Object.assign({
  stripControlChars,
  collapseSpaces,
  sanitizeRestoreTitle,
  sanitizeRestoreUrl,
  sanitizeSessionTab,
  sanitizeSessionList,
  isValidClosedAt,
  sanitizeClosedTab,
  createRecentlyClosedState,
  pushRecentlyClosed,
  popLastClosed,
  sanitizeRecentlyClosedList,
}, constants));
