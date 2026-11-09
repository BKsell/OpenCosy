// ---- 有界 JSON 解析内核 ----
// 书签 JSON 来自任意来源，裸 JSON.parse 存在两个真实风险：
//  1. 嵌套深度无上限 -> 超深数组/对象让 V8 栈溢出（RangeError），可被恶意文件触发；
//  2. 元素数量无上限 -> 大数组反复 push 撑内存（虽然外层有文件字节上限，但 8MiB
//     的 "[1,1,1,...]" 能展开成千万级元素，摊薄不了内存压力）。
// 因此这里用带深度/元素/字符串长度上限的手写解析器替代 JSON.parse，
// 解析失败与超限都抛带中文描述的 Error，与既有错误契约一致。
const JSON_MAX_DEPTH = 40;
const JSON_MAX_ELEMENTS = 200000;
const JSON_MAX_STRING_CHARS = 1024 * 1024;

function parseBoundedJSON(text) {
  let pos = 0;
  let elements = 0;
  const len = text.length;

  function fail(msg) {
    throw new Error(`JSON 解析失败：${msg}（位置 ${pos}）`);
  }

  function skipWs() {
    while (pos < len) {
      const c = text.charCodeAt(pos);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) pos++;
      else break;
    }
  }

  function parseString() {
    if (text.charCodeAt(pos) !== 0x22) fail('期望字符串起始引号');
    pos++;
    const start = pos;
    let out = '';
    while (pos < len) {
      const c = text.charCodeAt(pos);
      if (c === 0x22) {
        const raw = text.slice(start, pos);
        pos++;
        if (raw.indexOf('\\') === -1) return raw;
        try {
          return JSON.parse(`"${raw}"`);
        } catch (_) {
          fail('字符串转义非法');
        }
      }
      if (c < 0x20) fail('字符串内出现未转义控制字符');
      pos++;
      if (pos - start > JSON_MAX_STRING_CHARS) fail('字符串过长');
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
    if (text.slice(pos, pos + word.length) !== word) fail(`期望 ${word}`);
    pos += word.length;
    return value;
  }

  function parseValue(depth) {
    if (depth > JSON_MAX_DEPTH) fail(`嵌套深度超过上限 ${JSON_MAX_DEPTH}`);
    skipWs();
    if (pos >= len) fail('意外的输入结尾');
    const c = text[pos];
    if (c === '{') {
      pos++;
      elements++;
      if (elements > JSON_MAX_ELEMENTS) fail(`元素数量超过上限 ${JSON_MAX_ELEMENTS}`);
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
        elements++;
        if (elements > JSON_MAX_ELEMENTS) fail(`元素数量超过上限 ${JSON_MAX_ELEMENTS}`);
        if (!Object.prototype.hasOwnProperty.call(obj, key)) obj[key] = val;
        skipWs();
        if (text[pos] === ',') { pos++; continue; }
        if (text[pos] === '}') { pos++; return obj; }
        fail('对象内期望逗号或右花括号');
      }
    }
    if (c === '[') {
      pos++;
      elements++;
      if (elements > JSON_MAX_ELEMENTS) fail(`元素数量超过上限 ${JSON_MAX_ELEMENTS}`);
      const arr = [];
      skipWs();
      if (text[pos] === ']') { pos++; return arr; }
      while (true) {
        arr.push(parseValue(depth + 1));
        elements++;
        if (elements > JSON_MAX_ELEMENTS) fail(`元素数量超过上限 ${JSON_MAX_ELEMENTS}`);
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

// parseJSONBookmarks 解析 OpenCosy 自身导出的 JSON 书签文件。

module.exports = {
  JSON_MAX_DEPTH,
  JSON_MAX_ELEMENTS,
  JSON_MAX_STRING_CHARS,
  parseBoundedJSON,
};
