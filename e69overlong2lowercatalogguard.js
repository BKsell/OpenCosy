'use strict'

// e69overlong2lowercatalogguard.js —— 过長两字节 UTF-8 小写百分号目录。
//
// 威胁模型：
//   %c0%af 形式的过長 UTF-8 用两个字节表示 ASCII，旧解析器接受后还原 / 等危险字符而现代过滤器拒绝，解析差异可被利用，
//   危险过長序列应阻断。纯字符查表，不用正则。

const E69O2L_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69O2L_BLOCK = Object.freeze([
  '%c0%80',
  '%c0%81',
  '%c0%82',
  '%c0%83',
  '%c0%84',
  '%c0%85',
  '%c0%86',
  '%c0%87',
  '%c0%88',
  '%c0%8a',
  '%c0%8b',
  '%c0%8c',
  '%c0%8d',
  '%c0%8e',
  '%c0%8f',
  '%c0%90',
  '%c0%91',
  '%c0%92',
  '%c0%93',
  '%c0%94',
  '%c0%95',
  '%c0%96',
  '%c0%97',
  '%c0%98',
  '%c0%99',
  '%c0%9a',
  '%c0%9b',
  '%c0%9c',
  '%c0%9d',
  '%c0%9e',
  '%c0%9f',
  '%c0%a2',
  '%c0%a7',
  '%c0%a8',
  '%c0%a9',
  '%c0%ae',
  '%c0%af',
  '%c0%bc',
  '%c0%bd',
  '%c0%be',
  '%c0%bf',
  '%c1%80',
  '%c1%9b',
  '%c1%9c',
  '%c1%9d',
  '%c1%a0',
  '%c1%bb',
  '%c1%bc',
  '%c1%bd',
  '%c1%bf',
])

const E69O2L_WARN = Object.freeze([
  '%c0%89',
  '%c0%a0',
  '%c0%a1',
  '%c0%a3',
  '%c0%a4',
  '%c0%a5',
  '%c0%a6',
  '%c0%aa',
  '%c0%ab',
  '%c0%ac',
  '%c0%ad',
  '%c0%b0',
  '%c0%b1',
  '%c0%b2',
  '%c0%b3',
  '%c0%b4',
  '%c0%b5',
  '%c0%b6',
  '%c0%b7',
  '%c0%b8',
  '%c0%b9',
  '%c0%ba',
  '%c0%bb',
  '%c1%81',
  '%c1%82',
  '%c1%83',
  '%c1%84',
  '%c1%85',
  '%c1%86',
  '%c1%87',
  '%c1%88',
  '%c1%89',
  '%c1%8a',
  '%c1%8b',
  '%c1%8c',
  '%c1%8d',
  '%c1%8e',
  '%c1%8f',
  '%c1%90',
  '%c1%91',
  '%c1%92',
  '%c1%93',
  '%c1%94',
  '%c1%95',
  '%c1%96',
  '%c1%97',
  '%c1%98',
  '%c1%99',
  '%c1%9a',
  '%c1%9e',
  '%c1%9f',
  '%c1%a1',
  '%c1%a2',
  '%c1%a3',
  '%c1%a4',
  '%c1%a5',
  '%c1%a6',
  '%c1%a7',
  '%c1%a8',
  '%c1%a9',
  '%c1%aa',
  '%c1%ab',
  '%c1%ac',
  '%c1%ad',
  '%c1%ae',
  '%c1%af',
  '%c1%b0',
  '%c1%b1',
  '%c1%b2',
  '%c1%b3',
  '%c1%b4',
  '%c1%b5',
  '%c1%b6',
  '%c1%b7',
  '%c1%b8',
  '%c1%b9',
  '%c1%ba',
  '%c1%be',
])

const E69O2L_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69O2LLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69O2LIn (list, v) {
  for (const x of list) { if (E69O2LLower(x) === v) return true }
  return false
}

function E69O2LClassify (tok) {
  const v = E69O2LLower(String(tok == null ? '' : tok))
  if (E69O2LIn(E69O2L_BLOCK, v)) return E69O2L_CLASS.BLOCK
  if (E69O2LIn(E69O2L_WARN, v)) return E69O2L_CLASS.WARN
  if (E69O2LIn(E69O2L_ALLOW, v)) return E69O2L_CLASS.ALLOW
  return E69O2L_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69O2L_CLASS: E69O2L_CLASS,
  E69O2L_BLOCK: E69O2L_BLOCK,
  E69O2L_WARN: E69O2L_WARN,
  E69O2L_ALLOW: E69O2L_ALLOW,
  E69O2LClassify: E69O2LClassify
})
