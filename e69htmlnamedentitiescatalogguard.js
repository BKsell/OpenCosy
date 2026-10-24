'use strict'

// e69htmlnamedentitiescatalogguard.js —— HTML 命名实体字节目录。
//
// 威胁模型：
//   &quot; &lt; &sol; &Tab; 等命名实体由 HTML 解析器还原为危险字符，纯字节匹配会漏报，
//   危险字符命名实体应阻断。纯字符查表，不用正则。

const E69HNE_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69HNE_BLOCK = Object.freeze([
  '&NewLine;',
  '&quot;',
  '&apos;',
  '&sol;',
  '&lt;',
  '&gt;',
  '&bsol;',
])

const E69HNE_WARN = Object.freeze([
  '&Tab;',
  '&amp;',
])

const E69HNE_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69HNELower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69HNEIn (list, v) {
  for (const x of list) { if (E69HNELower(x) === v) return true }
  return false
}

function E69HNEClassify (tok) {
  const v = E69HNELower(String(tok == null ? '' : tok))
  if (E69HNEIn(E69HNE_BLOCK, v)) return E69HNE_CLASS.BLOCK
  if (E69HNEIn(E69HNE_WARN, v)) return E69HNE_CLASS.WARN
  if (E69HNEIn(E69HNE_ALLOW, v)) return E69HNE_CLASS.ALLOW
  return E69HNE_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69HNE_CLASS: E69HNE_CLASS,
  E69HNE_BLOCK: E69HNE_BLOCK,
  E69HNE_WARN: E69HNE_WARN,
  E69HNE_ALLOW: E69HNE_ALLOW,
  E69HNEClassify: E69HNEClassify
})
