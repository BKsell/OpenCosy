'use strict'

// e69bopomofocatalogguard.js —— 注音符号码位目录。
//
// 威胁模型：
//   注音符号在常规标识符中无正当用途，可承载隐藏数据，
//   应拒绝。纯字符查表，不用正则。

const E69T27_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T27_BLOCK = Object.freeze([
  'U+3100',
  'U+3101',
  'U+3102',
  'U+3103',
  'U+3104',
  'U+3105',
  'U+3106',
  'U+3107',
  'U+3108',
  'U+3109',
  'U+310A',
  'U+310B',
  'U+310C',
  'U+310D',
  'U+310E',
  'U+310F',
  'U+3110',
  'U+3111',
  'U+3112',
  'U+3113',
  'U+3114',
  'U+3115',
  'U+3116',
  'U+3117',
  'U+3118',
  'U+3119',
  'U+311A',
  'U+311B',
  'U+311C',
  'U+311D',
  'U+311E',
  'U+311F',
  'U+3120',
  'U+3121',
  'U+3122',
  'U+3123',
  'U+3124',
  'U+3125',
  'U+3126',
  'U+3127',
  'U+3128',
  'U+3129',
  'U+312A',
  'U+312B',
  'U+312C',
  'U+312D',
  'U+312E',
  'U+312F',
])

const E69T27_WARN = Object.freeze([
])

const E69T27_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T27Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T27In (list, v) {
  for (const x of list) { if (E69T27Lower(x) === v) return true }
  return false
}

function E69T27Classify (tok) {
  const v = E69T27Lower(String(tok == null ? '' : tok))
  if (E69T27In(E69T27_BLOCK, v)) return E69T27_CLASS.BLOCK
  if (E69T27In(E69T27_WARN, v)) return E69T27_CLASS.WARN
  if (E69T27In(E69T27_ALLOW, v)) return E69T27_CLASS.ALLOW
  return E69T27_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T27_CLASS: E69T27_CLASS,
  E69T27_BLOCK: E69T27_BLOCK,
  E69T27_WARN: E69T27_WARN,
  E69T27_ALLOW: E69T27_ALLOW,
  E69T27Classify: E69T27Classify
})
