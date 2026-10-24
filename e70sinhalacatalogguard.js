'use strict'

// e70sinhalacatalogguard.js —— 僧伽罗文字码位目录。
//
// 威胁模型：
//   僧伽罗文在机器字段无正当用途且渲染依赖字体，
//   应直接拒绝。纯字符查表，不用正则。

const E70T18_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T18_BLOCK = Object.freeze([
  'U+0D80',
  'U+0D81',
  'U+0D82',
  'U+0D83',
  'U+0D84',
  'U+0D85',
  'U+0D86',
  'U+0D87',
  'U+0D88',
  'U+0D89',
  'U+0D8A',
  'U+0D8B',
  'U+0D8C',
  'U+0D8D',
  'U+0D8E',
  'U+0D8F',
  'U+0D90',
  'U+0D91',
  'U+0D92',
  'U+0D93',
  'U+0D94',
  'U+0D95',
  'U+0D96',
  'U+0D97',
  'U+0D98',
  'U+0D99',
  'U+0D9A',
  'U+0D9B',
  'U+0D9C',
  'U+0D9D',
  'U+0D9E',
  'U+0D9F',
  'U+0DA0',
  'U+0DA1',
  'U+0DA2',
  'U+0DA3',
  'U+0DA4',
  'U+0DA5',
  'U+0DA6',
  'U+0DA7',
  'U+0DA8',
  'U+0DA9',
  'U+0DAA',
  'U+0DAB',
  'U+0DAC',
  'U+0DAD',
  'U+0DAE',
  'U+0DAF',
  'U+0DB0',
  'U+0DB1',
  'U+0DB2',
  'U+0DB3',
  'U+0DB4',
  'U+0DB5',
  'U+0DB6',
  'U+0DB7',
  'U+0DB8',
  'U+0DB9',
  'U+0DBA',
  'U+0DBB',
  'U+0DBC',
  'U+0DBD',
  'U+0DBE',
  'U+0DBF',
  'U+0DC0',
  'U+0DC1',
  'U+0DC2',
  'U+0DC3',
  'U+0DC4',
  'U+0DC5',
  'U+0DC6',
  'U+0DC7',
  'U+0DC8',
  'U+0DC9',
  'U+0DCA',
  'U+0DCB',
  'U+0DCC',
  'U+0DCD',
  'U+0DCE',
  'U+0DCF',
  'U+0DD0',
  'U+0DD1',
  'U+0DD2',
  'U+0DD3',
  'U+0DD4',
  'U+0DD5',
  'U+0DD6',
  'U+0DD7',
  'U+0DD8',
  'U+0DD9',
  'U+0DDA',
  'U+0DDB',
  'U+0DDC',
  'U+0DDD',
  'U+0DDE',
  'U+0DDF',
  'U+0DE0',
  'U+0DE1',
  'U+0DE2',
  'U+0DE3',
  'U+0DE4',
  'U+0DE5',
  'U+0DE6',
  'U+0DE7',
  'U+0DE8',
  'U+0DE9',
  'U+0DEA',
  'U+0DEB',
  'U+0DEC',
  'U+0DED',
  'U+0DEE',
  'U+0DEF',
  'U+0DF0',
  'U+0DF1',
  'U+0DF2',
  'U+0DF3',
  'U+0DF4',
  'U+0DF5',
  'U+0DF6',
  'U+0DF7',
  'U+0DF8',
  'U+0DF9',
  'U+0DFA',
  'U+0DFB',
  'U+0DFC',
  'U+0DFD',
  'U+0DFE',
  'U+0DFF',
])

const E70T18_WARN = Object.freeze([
])

const E70T18_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T18Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T18In (list, v) {
  for (const x of list) { if (E70T18Lower(x) === v) return true }
  return false
}

function E70T18Classify (tok) {
  const v = E70T18Lower(String(tok == null ? '' : tok))
  if (E70T18In(E70T18_BLOCK, v)) return E70T18_CLASS.BLOCK
  if (E70T18In(E70T18_WARN, v)) return E70T18_CLASS.WARN
  if (E70T18In(E70T18_ALLOW, v)) return E70T18_CLASS.ALLOW
  return E70T18_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T18_CLASS: E70T18_CLASS,
  E70T18_BLOCK: E70T18_BLOCK,
  E70T18_WARN: E70T18_WARN,
  E70T18_ALLOW: E70T18_ALLOW,
  E70T18Classify: E70T18Classify
})
