/* jsonimportguard.js —— 浏览器端“JSON 导入”净化内核。
 *
 * 使用方：新标签页磁贴备份导入（importTiles）等所有“用户选一个 JSON 文件，
 * 本地 JSON.parse 后信任其内容”的入口。
 *
 * 裸 JSON.parse 的隐患（本内核全部封死）：
 *  1. 嵌套深度无上限 -> 超深数组触发 V8 栈溢出（RangeError），恶意备份文件可让页面崩溃；
 *  2. 元素数量无上限 -> "[1,1,1,...]" 膨胀成千万级元素，撑爆内存；
 *  3. 字段不过滤 -> name/color 直接进 innerHTML 有 XSS 面，url 非白名单协议会放行
 *     javascript:/data: 等危险链接（旧实现靠调用方自觉 isSafeUrl）。
 *
 * 导出（浏览器全局）：window.OpenCosyJsonImport。
 */
(function (global) {
  'use strict';

  const LIMITS = Object.freeze({
    maxChars: 1 * 1024 * 1024, // 文本长度上限 1MiB（磁贴备份远小于此）
    maxDepth: 40,              // 嵌套深度上限
    maxElements: 50000,        // 元素（数组项/键值对）总数上限
    maxItems: 1000,            // 净化后磁贴条数上限
    maxNameLen: 64,
    maxUrlLen: 2048,
  });
  const SAFE_PROTOCOLS = new Set(['http:', 'https:']);
  const COLOR_RE = /^#[0-9a-fA-F]{3,8}$/;

  // ---- 有界 JSON 解析（递归下降，同源策略：深度/元素/字符串长度全部设限） ----
  function parseBounded(text, limits) {
    let pos = 0;
    let elements = 0;
    const len = text.length;

    function fail(msg) {
      throw new Error('JSON 解析失败：' + msg + '（位置 ' + pos + '）');
    }
    function skipWs() {
      while (pos < len) {
        const c = text.charCodeAt(pos);
        if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) pos++;
        else break;
      }
    }
    function bump() {
      elements++;
      if (elements > limits.maxElements) fail('元素数量超过上限 ' + limits.maxElements);
    }
    function parseString() {
      if (text.charCodeAt(pos) !== 0x22) fail('期望字符串起始引号');
      pos++;
      const start = pos;
      while (pos < len) {
        const c = text.charCodeAt(pos);
        if (c === 0x22) {
          const raw = text.slice(start, pos);
          pos++;
          if (raw.indexOf('\\') === -1) return raw;
          try {
            return JSON.parse('"' + raw + '"');
          } catch (_) {
            fail('字符串转义非法');
          }
        }
        if (c < 0x20) fail('字符串内出现未转义控制字符');
        pos++;
        if (pos - start > limits.maxChars) fail('字符串过长');
      }
      fail('字符串未闭合');
    }
    function parseNumber() {
      const start = pos;
      if (text[pos] === '-') pos++;
      while (pos < len && /[0-9]/.test(text[pos])) pos++;
      if (text[pos] === '.') {
        pos++;
        while (pos < len && /[0-9]/.test(text[pos])) pos++;
      }
      if (text[pos] === 'e' || text[pos] === 'E') {
        pos++;
        if (text[pos] === '+' || text[pos] === '-') pos++;
        while (pos < len && /[0-9]/.test(text[pos])) pos++;
      }
      const raw = text.slice(start, pos);
      if (!raw || raw === '-') fail('数字格式非法');
      const v = Number(raw);
      if (!Number.isFinite(v)) fail('数字超出有限范围');
      return v;
    }
    function parseKeyword(word, value) {
      if (text.slice(pos, pos + word.length) !== word) fail('期望 ' + word);
      pos += word.length;
      return value;
    }
    function parseValue(depth) {
      if (depth > limits.maxDepth) fail('嵌套深度超过上限 ' + limits.maxDepth);
      skipWs();
      if (pos >= len) fail('意外的输入结尾');
      const c = text[pos];
      if (c === '{') {
        pos++;
        bump();
        const obj = {};
        skipWs();
        if (text[pos] === '}') { pos++; return obj; }
        while (true) {
          skipWs();
          const key = parseString();
          skipWs();
          if (text[pos] !== ':') fail('期望冒号');
          pos++;
          const val = parseValue(depth + 1);
          bump();
          if (!Object.prototype.hasOwnProperty.call(obj, key)) obj[key] = val;
          skipWs();
          if (text[pos] === ',') { pos++; continue; }
          if (text[pos] === '}') { pos++; return obj; }
          fail('对象内期望逗号或右花括号');
        }
      }
      if (c === '[') {
        pos++;
        bump();
        const arr = [];
        skipWs();
        if (text[pos] === ']') { pos++; return arr; }
        while (true) {
          arr.push(parseValue(depth + 1));
          bump();
          skipWs();
          if (text[pos] === ',') { pos++; continue; }
          if (text[pos] === ']') { pos++; return arr; }
          fail('数组内期望逗号或右方括号');
        }
      }
      if (c === '"') return parseString();
      if (c === '-' || /[0-9]/.test(c)) return parseNumber();
      if (text.startsWith('true', pos)) return parseKeyword('true', true);
      if (text.startsWith('false', pos)) return parseKeyword('false', false);
      if (text.startsWith('null', pos)) return parseKeyword('null', null);
      fail('无法识别的值');
    }

    const value = parseValue(0);
    skipWs();
    if (pos !== len) fail('存在多余尾部内容');
    return value;
  }

  // ---- 字段净化 ----
  function stripControlChars(s) {
    return String(s).replace(/[\u0000-\u001f\u007f\u009f]/g, '').trim();
  }
  function truncateRunes(s, n) {
    const t = String(s);
    if (t.length <= n) return t;
    // 简单按码元截断即可；代理对截断产生的半个字符由浏览器自行替换为 �，
    // 不会构成注入面（后续所有消费点都是 textContent / escapeHtml）。
    return t.slice(0, n);
  }
  function safeTileURL(raw) {
    if (typeof raw !== 'string') return null;
    const s = raw.trim();
    if (!s || s.length > LIMITS.maxUrlLen) return null;
    let u;
    try { u = new URL(s); } catch (_) { return null; }
    if (!SAFE_PROTOCOLS.has(u.protocol)) return null;
    if (!u.hostname) return null;
    return u.toString();
  }

  // sanitizeTile 把一条原始磁贴记录压成 { name, url, color, letter }；非法返回 null。
  function sanitizeTile(raw) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
    const url = safeTileURL(raw.url);
    if (!url) return null;
    const name = truncateRunes(stripControlChars(raw.name || url), LIMITS.maxNameLen) || url;
    const color = typeof raw.color === 'string' && COLOR_RE.test(raw.color.trim()) ? raw.color.trim() : '';
    const letter = truncateRunes(stripControlChars(raw.letter || name.charAt(0).toUpperCase()), 2);
    return { name, url, color, letter };
  }

  // parseTiles(text) -> { ok, items, order, error }
  // items 为已净化的磁贴数组（最多 maxItems 条）；order 为可选排序数组（最多 200 条
  // 纯字符串，与 OpenCosy 现有 ORDER_KEY 契约一致）；任何阶段失败返回 error 与 ok:false。
  function parseTiles(text, opts) {
    const limits = Object.assign({}, LIMITS, opts || {});
    if (typeof text !== 'string' || text.length === 0) return { ok: false, error: '备份文件为空' };
    if (text.length > limits.maxChars) {
      return { ok: false, error: '备份文件过大（上限 1MiB）' };
    }
    let data;
    try {
      data = parseBounded(text, limits);
    } catch (e) {
      return { ok: false, error: e && e.message ? e.message : 'JSON 解析失败' };
    }
    const incoming = Array.isArray(data) ? data : (data && Array.isArray(data.customs) ? data.customs : null);
    if (!incoming) return { ok: false, error: '备份文件里没有磁贴列表' };
    const items = [];
    for (const raw of incoming) {
      const tile = sanitizeTile(raw);
      if (tile) {
        items.push(tile);
        if (items.length >= limits.maxItems) break;
      }
    }
    const order = [];
    if (data && Array.isArray(data.order)) {
      for (const u of data.order) {
        if (typeof u === 'string' && u.length <= limits.maxUrlLen) {
          order.push(u);
          if (order.length >= 200) break;
        }
      }
    }
    return { ok: true, items, order, error: null };
  }

  global.OpenCosyJsonImport = {
    LIMITS,
    parseTiles,
    sanitizeTile,
    safeTileURL,
    stripControlChars,
    truncateRunes,
  };
})(typeof window !== 'undefined' ? window : globalThis);
