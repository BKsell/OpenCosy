'use strict'

// e68blockelementscatalogguard.js —— 方块元素码位目录。
//
// 威胁模型：
//   方块元素在终端可覆盖/遮挡既有文本，用于进度条欺骗与内容隐藏，
//   应按码点判定。纯字符查表，不用正则。

const E68R32_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E68R32_BLOCK = Object.freeze([
])

const E68R32_WARN = Object.freeze([
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

const E68R32_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E68R32Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E68R32In (list, v) {
  for (const x of list) { if (E68R32Lower(x) === v) return true }
  return false
}

function E68R32Classify (tok) {
  const v = E68R32Lower(String(tok == null ? '' : tok).trim())
  if (E68R32In(E68R32_BLOCK, v)) return E68R32_CLASS.BLOCK
  if (E68R32In(E68R32_WARN, v)) return E68R32_CLASS.WARN
  if (E68R32In(E68R32_ALLOW, v)) return E68R32_CLASS.ALLOW
  return E68R32_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E68R32_CLASS: E68R32_CLASS,
  E68R32_BLOCK: E68R32_BLOCK,
  E68R32_WARN: E68R32_WARN,
  E68R32_ALLOW: E68R32_ALLOW,
  E68R32Classify: E68R32Classify
})
