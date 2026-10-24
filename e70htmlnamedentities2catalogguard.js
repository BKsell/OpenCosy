'use strict'

// e70htmlnamedentities2catalogguard.js —— 扩展 HTML 命名实体目录。
//
// 威胁模型：
//   &lpar; &rpar; &semi; 等命名实体由 HTML 解析器还原为标点，纯字节匹配会漏报，
//   危险字符命名实体应阻断。纯字符查表，不用正则。

const E70HN2_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70HN2_BLOCK = Object.freeze([
  '&lpar;',
  '&rpar;',
  '&period;',
  '&equals;',
  '&commat;',
  '&lbrace;',
  '&rbrace;',
])

const E70HN2_WARN = Object.freeze([
  '&excl;',
  '&num;',
  '&dollar;',
  '&percnt;',
  '&ast;',
  '&plus;',
  '&comma;',
  '&colon;',
  '&semi;',
  '&lowbar;',
  '&tilde;',
])

const E70HN2_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70HN2Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70HN2In (list, v) {
  for (const x of list) { if (E70HN2Lower(x) === v) return true }
  return false
}

function E70HN2Classify (tok) {
  const v = E70HN2Lower(String(tok == null ? '' : tok))
  if (E70HN2In(E70HN2_BLOCK, v)) return E70HN2_CLASS.BLOCK
  if (E70HN2In(E70HN2_WARN, v)) return E70HN2_CLASS.WARN
  if (E70HN2In(E70HN2_ALLOW, v)) return E70HN2_CLASS.ALLOW
  return E70HN2_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70HN2_CLASS: E70HN2_CLASS,
  E70HN2_BLOCK: E70HN2_BLOCK,
  E70HN2_WARN: E70HN2_WARN,
  E70HN2_ALLOW: E70HN2_ALLOW,
  E70HN2Classify: E70HN2Classify
})
