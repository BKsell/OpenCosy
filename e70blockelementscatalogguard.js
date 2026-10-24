'use strict'

// e70blockelementscatalogguard.js —— 方块元号码位目录。
//
// 威胁模型：
//   方块元字符用于拼接伪界面，在标识符/路径中无正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const E70T46_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T46_BLOCK = Object.freeze([
  'U+2580',
  'U+2581',
  'U+2582',
  'U+2583',
  'U+2584',
  'U+2585',
  'U+2586',
  'U+2587',
  'U+2588',
  'U+2589',
  'U+258A',
  'U+258B',
  'U+258C',
  'U+258D',
  'U+258E',
  'U+258F',
  'U+2590',
  'U+2591',
  'U+2592',
  'U+2593',
  'U+2594',
  'U+2595',
  'U+2596',
  'U+2597',
  'U+2598',
  'U+2599',
  'U+259A',
  'U+259B',
  'U+259C',
  'U+259D',
  'U+259E',
  'U+259F',
])

const E70T46_WARN = Object.freeze([
])

const E70T46_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T46Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T46In (list, v) {
  for (const x of list) { if (E70T46Lower(x) === v) return true }
  return false
}

function E70T46Classify (tok) {
  const v = E70T46Lower(String(tok == null ? '' : tok))
  if (E70T46In(E70T46_BLOCK, v)) return E70T46_CLASS.BLOCK
  if (E70T46In(E70T46_WARN, v)) return E70T46_CLASS.WARN
  if (E70T46In(E70T46_ALLOW, v)) return E70T46_CLASS.ALLOW
  return E70T46_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T46_CLASS: E70T46_CLASS,
  E70T46_BLOCK: E70T46_BLOCK,
  E70T46_WARN: E70T46_WARN,
  E70T46_ALLOW: E70T46_ALLOW,
  E70T46Classify: E70T46Classify
})
