'use strict';

const test = require('node:test');
const assert = require('node:assert');

const ts = require('./tabsearch');

// mkTab 快速构造一条标签；title/url 缺省给空串，便于聚焦被测字段。
function mkTab(id, title, url, extra) {
  return Object.assign({ id, title: title || '', url: url || '' }, extra || {});
}

test('tokenize 折叠连续空白、转小写并按首次出现去重', () => {
  assert.deepStrictEqual(ts.tokenize('  Hello   world hello\tWORLD\n'),
    ['hello', 'world']);
  assert.deepStrictEqual(ts.tokenize('a\u3000b'), ['a', 'b']); // 全角空格也切词
  assert.deepStrictEqual(ts.tokenize('\t\n\r\f\v'), []);
});

test('tokenize 对非字符串与空值安全返回空数组', () => {
  assert.deepStrictEqual(ts.tokenize(null), []);
  assert.deepStrictEqual(ts.tokenize(undefined), []);
  assert.deepStrictEqual(ts.tokenize(12345), []);
  assert.deepStrictEqual(ts.tokenize({}), []);
});

test('tokenize 裁剪超长查询', () => {
  const long = 'a'.repeat(ts.MAX_QUERY_LEN + 50);
  const toks = ts.tokenize(long);
  assert.strictEqual(toks.length, 1);
  assert.strictEqual(toks[0].length, ts.MAX_QUERY_LEN);
});

test('isWordBoundary 识别开头与非字母数字边界', () => {
  assert.strictEqual(ts.isWordBoundary('github', 0), true);
  assert.strictEqual(ts.isWordBoundary('github docs', 7), true);  // 空格之后
  assert.strictEqual(ts.isWordBoundary('a/b', 2), true);         // '/' 之后
  assert.strictEqual(ts.isWordBoundary('my-docs', 3), true);     // '-' 之后
  assert.strictEqual(ts.isWordBoundary('github', 2), false);     // 't' 之后非边界
});

test('scoreInText 起始命中得分最高', () => {
  const s = ts.scoreInText('github docs', 'github',
    ts.SCORE.TITLE_PREFIX, ts.SCORE.TITLE_WORD, ts.SCORE.TITLE_CONTAINS);
  assert.strictEqual(s, ts.SCORE.TITLE_PREFIX);
});

test('scoreInText 词边界命中居中、普通包含最低，未命中为 0', () => {
  assert.strictEqual(ts.scoreInText('my github page', 'github',
    100, 60, 30), 60);
  // token 夹在单词中间（前一字符是字母）才算普通包含命中。
  assert.strictEqual(ts.scoreInText('axgithubbing', 'github',
    100, 60, 30), 30);
  assert.strictEqual(ts.scoreInText('nothing', 'github', 100, 60, 30), 0);
  assert.strictEqual(ts.scoreInText('', 'x', 100, 60, 30), 0);
});

test('hostRange 解析普通网址主机名', () => {
  const hr = ts.hostRange('https://www.example.com/path?q=1');
  assert.ok(hr);
  assert.strictEqual(hr.host, 'www.example.com');
});

test('hostRange 去除端口与 userinfo', () => {
  const hr = ts.hostRange('https://user:pass@host.example:8443/a');
  assert.ok(hr);
  assert.strictEqual(hr.host, 'host.example');
});

test('hostRange 对无 scheme 或空主机返回 null', () => {
  assert.strictEqual(ts.hostRange('about:blank'), null);
  assert.strictEqual(ts.hostRange('https:///nohost'), null);
});

test('scoreUrl 主机名开头命中得 HOST_PREFIX', () => {
  assert.strictEqual(ts.scoreUrl('https://example.com/x', 'example'),
    ts.SCORE.HOST_PREFIX);
});

test('scoreUrl 主机名点边界命中得主机包含分', () => {
  assert.strictEqual(ts.scoreUrl('https://www.example.com/', 'example'),
    ts.SCORE.HOST_CONTAINS);
});

test('scoreUrl 仅路径命中得 URL_CONTAINS，未命中为 0', () => {
  assert.strictEqual(ts.scoreUrl('https://example.com/downloads', 'downloads'),
    ts.SCORE.URL_CONTAINS);
  assert.strictEqual(ts.scoreUrl('https://example.com/', 'zzz'), 0);
});

test('scoreUrl 对 about:/cosy: 等非标准网址退化为整段匹配', () => {
  assert.strictEqual(ts.scoreUrl('about:blank', 'blank'), ts.SCORE.URL_CONTAINS);
  assert.strictEqual(ts.scoreUrl('cosy://settings/security', 'security'),
    ts.SCORE.URL_CONTAINS);
});

test('scoreTab 多关键字 AND：任一关键字缺失即排除（-1）', () => {
  const tab = ts.normalizeTab(mkTab('1', 'GitHub Docs', 'https://github.com/docs'), 0);
  assert.ok(ts.scoreTab(tab, ts.tokenize('github docs')) > 0);
  assert.strictEqual(ts.scoreTab(tab, ts.tokenize('github youtube')), -1);
});

test('scoreTab 标题命中权重高于仅网址命中', () => {
  const inTitle = ts.normalizeTab(mkTab('a', 'download manager', 'https://x.test/'), 0);
  const inUrl = ts.normalizeTab(mkTab('b', 'home', 'https://x.test/download'), 1);
  const st = ts.scoreTab(inTitle, ['download']);
  const su = ts.scoreTab(inUrl, ['download']);
  assert.ok(st > su);
});

test('scoreTab 完整短语在标题开头给额外加分', () => {
  const phrase = ts.normalizeTab(mkTab('a', 'new tab settings page', ''), 0);
  const scattered = ts.normalizeTab(mkTab('b', 'settings of a new tab', ''), 1);
  const sp = ts.scoreTab(phrase, ['new', 'tab', 'settings']);
  const ss = ts.scoreTab(scattered, ['new', 'tab', 'settings']);
  assert.ok(sp > ss);
});

test('normalizeTab 容忍脏数据：非对象、非字符串、缺失字段', () => {
  const n = ts.normalizeTab(null, 3);
  assert.strictEqual(n.index, 3);
  assert.strictEqual(n.title, '');
  assert.strictEqual(n.url, '');
  assert.strictEqual(n.pinned, false);
  const n2 = ts.normalizeTab({ id: 9, title: 123, url: ['x'], pinned: 1 }, 0);
  assert.strictEqual(n2.id, 9);
  assert.strictEqual(n2.title, '');
  assert.strictEqual(n2.url, '');
  assert.strictEqual(n2.pinned, true);
});

test('searchTabs 空查询：固定标签优先、其余保持原顺序', () => {
  const tabs = [
    mkTab('a', 'Alpha', 'https://a.test/'),
    mkTab('b', 'Beta', 'https://b.test/', { pinned: true }),
    mkTab('c', 'Gamma', 'https://c.test/'),
  ];
  const r = ts.searchTabs(tabs, '');
  assert.strictEqual(r[0].id, 'b');           // 固定第一
  assert.deepStrictEqual(r.slice(1).map(x => x.id), ['a', 'c']); // 其余原顺序
});

test('searchTabs 标题相关度优先于网址相关度', () => {
  const tabs = [
    mkTab('u', 'Home', 'https://music.example/library'),
    mkTab('t', 'Music Library', 'https://other.test/'),
  ];
  const r = ts.searchTabs(tabs, 'music library');
  assert.strictEqual(r[0].id, 't');
});

test('searchTabs 多关键字 AND 过滤不含全部关键字的标签', () => {
  const tabs = [
    mkTab('a', 'GitHub Pull Requests', 'https://github.com/'),
    mkTab('b', 'GitHub Issues', 'https://github.com/issues'),
  ];
  const r = ts.searchTabs(tabs, 'github pull');
  assert.deepStrictEqual(r.map(x => x.id), ['a']);
});

test('searchTabs 同分时保持输入顺序稳定（固定标签仅微小领先）', () => {
  const tabs = [
    mkTab('a', 'same word here', ''),
    mkTab('b', 'same word here', '', { pinned: true }),
  ];
  const r = ts.searchTabs(tabs, 'same');
  assert.strictEqual(r[0].id, 'b'); // 固定同分微调领先
  assert.strictEqual(r[1].id, 'a');
});

test('searchTabs 大小写不敏感且保留结果展示字段', () => {
  const tabs = [mkTab('a', 'GITHUB', 'https://GitHub.COM/Repo')];
  const r = ts.searchTabs(tabs, 'github');
  assert.strictEqual(r.length, 1);
  assert.strictEqual(r[0].title, 'GITHUB');
  assert.strictEqual(r[0].url, 'https://GitHub.COM/Repo');
  assert.strictEqual(r[0].id, 'a');
});

test('searchTabs 结果数量受 MAX_RESULTS 限制', () => {
  const tabs = [];
  for (let i = 0; i < ts.MAX_RESULTS + 20; i++) {
    tabs.push(mkTab('id' + i, 'common title ' + i, 'https://x.test/' + i));
  }
  const r = ts.searchTabs(tabs, 'common');
  assert.strictEqual(r.length, ts.MAX_RESULTS);
});

test('searchTabs 输入标签数受 MAX_TAB_INPUT 限制且不抛错', () => {
  const tabs = [];
  for (let i = 0; i < ts.MAX_TAB_INPUT + 50; i++) {
    tabs.push(mkTab('id' + i, 'uniq' + i, ''));
  }
  const r = ts.searchTabs(tabs, 'uniq');
  assert.ok(r.length <= ts.MAX_RESULTS);
  assert.ok(r.length > 0);
});

test('searchTabs 对非数组输入返回空数组', () => {
  assert.deepStrictEqual(ts.searchTabs(null, 'x'), []);
  assert.deepStrictEqual(ts.searchTabs(undefined, 'x'), []);
  assert.deepStrictEqual(ts.searchTabs('notarray', 'x'), []);
});

test('searchTabs 无命中返回空数组', () => {
  const tabs = [mkTab('a', 'Alpha', 'https://a.test/')];
  assert.deepStrictEqual(ts.searchTabs(tabs, 'zzzzz'), []);
});
