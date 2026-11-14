const { stripControlChars, collapseSpaces, sanitizeDisplayTitle, fallbackTitleFor } = require('./modutil_core');
const urlEntry = require('./urlentryguard_core');


// bookmarkguard.js —— 书签（收藏夹）落盘 / 读取 / 导入合并的“写入净化 + 逐条校验
// + 去重 + 有界维护”内核。
//
// 威胁模型：
//   OpenCosy 把书签以 {url,title,addedDate} 数组的形式写到 userData/bookmarks.json，
//   旧实现 saveBookmarks 原样 JSON.stringify、loadBookmarks 直接 JSON.parse 后赋值，
//   存在几个真实面：
//     1. bookmarks.json 不是信任边界内的数据：它可被用户手改、被同步盘上的其它机器
//        写入、被恶意进程替换，也可能因崩溃写到一半变成截断 JSON。读入时若不做
//        Array.isArray 与逐条字段校验，脏数据（对象、null、数字、嵌套数组）会直接进
//        渲染层书签 UI，触发渲染异常或让后续 saveBookmarks 写出坏结构。
//     2. 书签 url 与 title 半受远端控制：批量收藏“全部标签”时 title 来自各页面，
//        可塞入 NUL / CR / LF / ESC 等控制字符、数万字符超长标题（存储型 DoS），
//        也可把 file:/javascript:/data: 等内部 / 危险 scheme 混进可被点击 / 导出 /
//        同步的书签。书签只应承载 http/https 站点地址。
//     3. 书签数组没有硬上界：恶意页面诱导循环注入或手改出几十万条，会把
//        bookmarks.json 与书签侧栏内存撑大。
//     4. 批量收藏 / HTML 导入若不去重，会产生大量同 url 重复项，放大写盘与侧栏渲染。
//   本内核只做纯函数，不碰文件系统与 Electron API，便于穷举单测；main.js 的
//   saveBookmarks / loadBookmarks / 批量收藏 / 导入复用这里的裁决。

// 书签允许承载的协议（站点地址）。其余 scheme 一律不入书签。
const ALLOWED_PROTOCOLS = Object.freeze(['http:', 'https:']);
// 单条标题最大字符数（按 code unit 计，与历史内核一致）。
const MAX_TITLE_CHARS = 300;
// 单条 URL 最大字符数；超过的拒绝（异常 / 超长跟踪链接不进书签）。
const MAX_URL_CHARS = 8192;
// 书签总条数硬上界，超出丢弃最末（批量收藏 / 导入时尤其关键）。
const MAX_BOOKMARK_ITEMS = 5000;

const SKIP_NOT_OBJECT = 'not-object';
const SKIP_BAD_URL = 'bad-url';
const SKIP_BAD_PROTOCOL = 'disallowed-protocol';
const SKIP_URL_TOO_LONG = 'url-too-long';
const SKIP_BAD_DATE = 'bad-date';

const constants = Object.freeze({
  ALLOWED_PROTOCOLS,
  MAX_TITLE_CHARS,
  MAX_URL_CHARS,
  MAX_BOOKMARK_ITEMS,
  SKIP_NOT_OBJECT,
  SKIP_BAD_URL,
  SKIP_BAD_PROTOCOL,
  SKIP_URL_TOO_LONG,
  SKIP_BAD_DATE,
});

// stripControlChars 去掉会破坏文本展示 / 文件结构的控制字符，保留正常空白与
// Unicode；NUL 一并移除。

// collapseSpaces 把连续空白压成单个空格并去掉首尾空白。

// sanitizeBookmarkTitle 清洗书签标题：制表 / 换行 / 回车先归一为空格，再删除其余
// 控制字符，最后压缩空白并截断上界。非字符串给空串（书签允许标题为空，由调用方
// 决定是否回退用 host 展示）。
function sanitizeBookmarkTitle(rawTitle) {
  return sanitizeDisplayTitle(rawTitle, MAX_TITLE_CHARS);
}

// sanitizeBookmarkUrl 校验并规范化书签 URL。
// 返回 {ok,url,reason}：只接受 http/https、可解析、长度有界、host 非空的地址。
function sanitizeBookmarkUrl(rawUrl) {
  return urlEntry.sanitizeWebUrl(rawUrl, {
    empty: SKIP_BAD_URL,
    tooLong: SKIP_URL_TOO_LONG,
    badUrl: SKIP_BAD_URL,
    badProtocol: SKIP_BAD_PROTOCOL,
  }, MAX_URL_CHARS);
}

// isValidISOTimestamp 判定一个值是否为可被 Date 解析、时间有限的 ISO 字符串。
// 书签 addedDate 统一存 new Date().toISOString()，读入脏数据时不能信任该字段。
function isValidISOTimestamp(v) {
  if (typeof v !== 'string' || v.length === 0) return false;
  const t = Date.parse(v);
  return Number.isFinite(t);
}

// fallbackTitleFor 标题为空时用 URL 的 host 兜底，保证书签栏始终有可读文案。

// sanitizeBookmarkItem 校验并规范化单条书签。input 期望 {url,title,addedDate}。
//   - url 必须是合法 http/https，否则整条丢弃（ok=false 带 reason）；
//   - title 净化，空则用 host 兜底；
//   - addedDate 非法 / 缺失时用 now 补，绝不把不可解析时间写回。
// now 必须是有限毫秒时间戳（调用方传 Date.now()）。
function sanitizeBookmarkItem(input, now) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, item: null, reason: SKIP_NOT_OBJECT };
  }
  const su = sanitizeBookmarkUrl(input.url);
  if (!su.ok) return { ok: false, item: null, reason: su.reason };

  let u;
  try {
    u = new URL(su.url);
  } catch {
    return { ok: false, item: null, reason: SKIP_BAD_URL };
  }

  let title = sanitizeBookmarkTitle(input.title);
  if (!title) title = fallbackTitleFor(u);

  let addedDate;
  if (isValidISOTimestamp(input.addedDate)) {
    addedDate = new Date(Date.parse(input.addedDate)).toISOString();
  } else {
    addedDate = new Date(now).toISOString();
  }

  return { ok: true, item: { url: su.url, title, addedDate }, reason: '' };
}

// createBookmarkState 生成独立书签状态（items 为有序数组）。

module.exports = {
  ALLOWED_PROTOCOLS,
  MAX_TITLE_CHARS,
  MAX_URL_CHARS,
  MAX_BOOKMARK_ITEMS,
  SKIP_NOT_OBJECT,
  SKIP_BAD_URL,
  SKIP_BAD_PROTOCOL,
  SKIP_URL_TOO_LONG,
  SKIP_BAD_DATE,
  constants,
  sanitizeBookmarkTitle,
  sanitizeBookmarkUrl,
  isValidISOTimestamp,
  sanitizeBookmarkItem,
};
