'use strict';

const test = require('node:test');
const assert = require('node:assert');
const reader = require('./reader');

test('safeHref 只放行 http/https，挡掉危险与相对链接', () => {
  assert.equal(reader.safeHref('https://example.com/a'), 'https://example.com/a');
  assert.equal(reader.safeHref('http://example.com'), 'http://example.com');
  for (const bad of [
    'javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    'data:text/html,<script>',
    'vbscript:msgbox',
    '//example.com/a',
    '/local/path',
    '#fragment',
    '   java\tscript:alert(1)',
  ]) {
    assert.equal(reader.safeHref(bad), '', `应拒绝: ${bad}`);
  }
});

test('safeImageSrc 要求绝对 http/https', () => {
  assert.equal(reader.safeImageSrc('https://img.test/a.png'), 'https://img.test/a.png');
  assert.equal(reader.safeImageSrc('/rel.png'), '');
  assert.equal(reader.safeImageSrc('javascript:x'), '');
});

test('collapseSpaces 折叠各类空白且不用正则', () => {
  assert.equal(reader.collapseSpaces('a   b'), 'a b');
  assert.equal(reader.collapseSpaces('a\t\nb　　c'), 'a b c'); // 含 Tab/换行/全角空格
  assert.equal(reader.collapseSpaces('   leading'), 'leading');
});

test('scoreContainer：链接农场被惩罚，语义 article 加权', () => {
  const prose = {
    textLength: 1200, paragraphCount: 10, linkTextLength: 40,
    semanticArticle: false, semanticMain: false, noise: false,
    textSample: '这是一段。正常的，正文；包含很多标点和内容。'.repeat(20),
  };
  const linkFarm = {
    textLength: 1200, paragraphCount: 0, linkTextLength: 1180,
    semanticArticle: false, semanticMain: false, noise: false, textSample: 'x',
  };
  const article = { ...prose, semanticArticle: true, textSample: 'y' };
  assert.ok(reader.scoreContainer(prose) > reader.scoreContainer(linkFarm));
  assert.ok(reader.scoreContainer(article) > reader.scoreContainer(prose));
  const nav = { ...prose, noise: true };
  assert.ok(reader.scoreContainer(nav) < reader.scoreContainer(prose));
});

test('cleanTitle 去掉短站名后缀，保留长标题', () => {
  assert.equal(reader.cleanTitle('文章标题 - 某站'), '文章标题');
  const longTail = '主标题后面这一整段文字明显超过二十四个字它不是站名而是真正标题的一部分';
  assert.equal(reader.cleanTitle('正文 | ' + longTail), '正文 | ' + longTail);
  assert.equal(reader.cleanTitle('   多   空格   标题 '), '多 空格 标题');
});

test('estimateReadMinutes 至少 1 分钟', () => {
  assert.equal(reader.estimateReadMinutes(0), 1);
  assert.equal(reader.estimateReadMinutes(450), 1);
  assert.equal(reader.estimateReadMinutes(900), 2);
});

test('白名单集合覆盖关键标签', () => {
  assert.ok(reader.SKIP_TAGS.has('script'));
  assert.ok(reader.SKIP_TAGS.has('iframe'));
  assert.ok(reader.NOISE_TAGS.has('nav'));
  assert.ok(reader.OUTPUT_BLOCK_TAGS.has('p'));
  assert.ok(reader.OUTPUT_INLINE_TAGS.has('a'));
  assert.ok(!reader.OUTPUT_BLOCK_TAGS.has('div'));
});

// ---- 精简假 DOM：仅实现抽取脚本实际用到的接口，用于在 node 里端到端验证安全保证 ----

function makeNodeFilter() {
  return { SHOW_TEXT: 4 };
}

function textOf(el) {
  let s = '';
  for (const child of el.childNodes) {
    if (child.nodeType === 3) s += child.nodeValue;
    else if (child.nodeType === 1) s += textOf(child);
  }
  return s;
}

// 去掉假 DOM 选择器属性值两端可能包裹的单 / 双引号（字符处理，不用正则）。
function stripQuotes(s) {
  if (s.length >= 2) {
    const first = s[0];
    const last = s[s.length - 1];
    if ((first === '"' || first === "'") && first === last) return s.slice(1, -1);
  }
  return s;
}

function parseSimpleSelector(token) {
  const t = token.trim();
  const lb = t.indexOf('[');
  if (lb < 0) return { tag: t, attr: null, val: null };
  const tag = t.slice(0, lb);
  let inner = t.slice(lb + 1, t.lastIndexOf(']'));
  let attr = inner;
  let val = null;
  const eq = inner.indexOf('=');
  if (eq >= 0) {
    attr = inner.slice(0, eq);
    val = stripQuotes(inner.slice(eq + 1));
  }
  return { tag, attr, val };
}

function matchSelector(el, token) {
  const want = parseSimpleSelector(token);
  if (want.tag && el.tagName.toLowerCase() !== want.tag) return false;
  if (want.attr) {
    const actual = el.attributes[want.attr];
    if (actual === undefined) return false;
    if (want.val !== null && actual !== want.val) return false;
  }
  return true;
}

function makeElement(doc, tagName, attributes) {
  const el = {
    nodeType: 1,
    tagName: tagName.toUpperCase(),
    attributes: Object.assign({}, attributes),
    childNodes: [],
    ownerDocument: doc,
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(this.attributes, name)
        ? this.attributes[name] : null;
    },
    get textContent() { return textOf(this); },
  };
  el.appendChild = child => {
    child.parentNode = el;
    el.childNodes.push(child);
    return child;
  };
  function collect(list, out) {
    for (const c of list) {
      if (c.nodeType === 1) {
        out.push(c);
        collect(c.childNodes, out);
      }
    }
  }
  el.getElementsByTagName = name => {
    const out = [];
    for (const c of el.childNodes) {
      if (c.nodeType === 1) {
        if (c.tagName.toLowerCase() === name.toLowerCase()) out.push(c);
        collect(c.childNodes, out);
      }
    }
    return out;
  };
  el.querySelectorAll = sel => {
    const tokens = sel.split(',').map(s => s.trim()).filter(Boolean);
    const all = [];
    collect(el.childNodes, all);
    return all.filter(node => tokens.some(tk => matchSelector(node, tk)));
  };
  el.querySelector = sel => el.querySelectorAll(sel)[0] || null;
  doc._register(el);
  return el;
}

function makeText(value) {
  return { nodeType: 3, nodeValue: value, childNodes: [] };
}

function buildFakeDocument() {
  global.NodeFilter = makeNodeFilter();
  const doc = {
    nodeType: 9,
    title: '一篇真正的新闻正文 - 示例新闻网',
    location: { href: 'https://news.example.test/article/1' },
    _all: new Set(),
    _register(el) { this._all.add(el); },
    createElement(tag) { return makeElement(this, tag, {}); },
    createTreeWalker(root) {
      const texts = [];
      const walk = node => {
        for (const c of node.childNodes) {
          if (c.nodeType === 3) texts.push(c);
          else if (c.nodeType === 1) walk(c);
        }
      };
      walk(root);
      let i = 0;
      return { nextNode: () => (i < texts.length ? texts[i++] : null) };
    },
  };
  doc.querySelectorAll = sel => {
    const tokens = sel.split(',').map(s => s.trim()).filter(Boolean);
    return [...doc._all].filter(node => tokens.some(tk => matchSelector(node, tk)));
  };
  doc.querySelector = sel => doc.querySelectorAll(sel)[0] || null;
  return doc;
}

function runExtract(doc) {
  // 用与线上同一份脚本体，注入假 document / NodeFilter 执行（不做任何字符串替换）。
  // 生成完整 IIFE 仅用于确认产物可被解析。
  new Function(reader.buildReaderExtractScript()); // eslint-disable-line no-new-func
  const fn = new Function('document', 'NodeFilter', reader.buildReaderExtractScriptBody());
  return fn(doc, global.NodeFilter);
}

test('端到端：恶意脚本/事件/危险链接在阅读树中被彻底剥离', () => {
  const doc = buildFakeDocument();
  const body = makeElement(doc, 'body', {});
  doc.body = body;

  const nav = makeElement(doc, 'nav', {});
  nav.appendChild(makeText('首页 关于 登录'));
  body.appendChild(nav);

  const article = makeElement(doc, 'div', { class: 'post' });
  const p1 = makeElement(doc, 'p', {});
  p1.appendChild(makeText('这是第一段足够长的正文内容，用来证明抽取器能够识别真正的文章主体而不是导航栏。'));
  article.appendChild(p1);

  const p2 = makeElement(doc, 'p', {});
  p2.appendChild(makeText('第二段里混有一个安全链接 '));
  const goodLink = makeElement(doc, 'a', { href: 'https://good.example.test/page' });
  goodLink.appendChild(makeText('可信站点'));
  p2.appendChild(goodLink);
  p2.appendChild(makeText(' 和一个危险链接 '));
  const evilLink = makeElement(doc, 'a', { href: 'javascript:alert(document.cookie)' });
  evilLink.appendChild(makeText('点我中毒'));
  p2.appendChild(evilLink);
  p2.appendChild(makeText(' 以及内联强调。'));
  const strong = makeElement(doc, 'strong', {});
  strong.appendChild(makeText('重点结论'));
  p2.appendChild(strong);
  article.appendChild(p2);

  // 脚本与事件属性必须被丢弃。
  const script = makeElement(doc, 'script', {});
  script.appendChild(makeText('window.__pwned = true'));
  article.appendChild(script);
  const trap = makeElement(doc, 'img', { src: 'javascript:alert(1)', onerror: 'alert(1)' });
  article.appendChild(trap);
  const goodImg = makeElement(doc, 'img', { src: 'https://img.example.test/a.png', alt: '配图' });
  article.appendChild(goodImg);

  // 补足段落数量与长度，确保 article 被选为最佳容器。
  for (let i = 0; i < 4; i++) {
    const pp = makeElement(doc, 'p', {});
    pp.appendChild(makeText('补充段落编号 ' + i + '，这一段也有足够多的真实文字内容用于参与正文打分。'));
    article.appendChild(pp);
  }
  body.appendChild(article);

  const result = runExtract(doc);
  assert.equal(result.ok, true);
  assert.ok(result.wordCount >= reader.READER_MIN_ARTICLE_CHARS);
  assert.equal(result.title, '一篇真正的新闻正文');

  const flat = JSON.stringify(result.contentNodes);
  assert.ok(!flat.includes('javascript:'), '阅读树不得包含 javascript: 链接');
  assert.ok(!flat.includes('__pwned'), 'script 文本不得进入阅读树');
  assert.ok(!flat.includes('onerror'), '事件属性名不得进入阅读树');
  assert.ok(flat.includes('https://good.example.test/page'), '安全 http(s) 链接应保留');
  assert.ok(flat.includes('https://img.example.test/a.png'), '安全图片应保留');
  assert.ok(flat.includes('重点结论'), '白名单内联标签文本应保留');
  assert.ok(!flat.includes('首页 关于 登录'), 'nav 噪音不应进入正文');
});

test('端到端：正文过短时返回 ok:false 或回退段落', () => {
  const doc = buildFakeDocument();
  const body = makeElement(doc, 'body', {});
  doc.body = body;
  const div = makeElement(doc, 'div', {});
  div.appendChild(makeText('太短'));
  body.appendChild(div);
  const result = runExtract(doc);
  assert.ok(typeof result.ok === 'boolean');
  assert.ok(Array.isArray(result.contentNodes));
});
