'use strict'

// e69hiraganacatalogguard.js —— 平假名码位目录。
//
// 威胁模型：
//   平假名不应出现在机器标识符/路径/命令中，可用于在该类字段隐藏非预期数据，
//   机器字段应拒绝。纯字符查表，不用正则。

const E69T25_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T25_BLOCK = Object.freeze([
  'U+3040',
  'U+3041',
  'U+3042',
  'U+3043',
  'U+3044',
  'U+3045',
  'U+3046',
  'U+3047',
  'U+3048',
  'U+3049',
  'U+304A',
  'U+304B',
  'U+304C',
  'U+304D',
  'U+304E',
  'U+304F',
  'U+3050',
  'U+3051',
  'U+3052',
  'U+3053',
  'U+3054',
  'U+3055',
  'U+3056',
  'U+3057',
  'U+3058',
  'U+3059',
  'U+305A',
  'U+305B',
  'U+305C',
  'U+305D',
  'U+305E',
  'U+305F',
  'U+3060',
  'U+3061',
  'U+3062',
  'U+3063',
  'U+3064',
  'U+3065',
  'U+3066',
  'U+3067',
  'U+3068',
  'U+3069',
  'U+306A',
  'U+306B',
  'U+306C',
  'U+306D',
  'U+306E',
  'U+306F',
  'U+3070',
  'U+3071',
  'U+3072',
  'U+3073',
  'U+3074',
  'U+3075',
  'U+3076',
  'U+3077',
  'U+3078',
  'U+3079',
  'U+307A',
  'U+307B',
  'U+307C',
  'U+307D',
  'U+307E',
  'U+307F',
  'U+3080',
  'U+3081',
  'U+3082',
  'U+3083',
  'U+3084',
  'U+3085',
  'U+3086',
  'U+3087',
  'U+3088',
  'U+3089',
  'U+308A',
  'U+308B',
  'U+308C',
  'U+308D',
  'U+308E',
  'U+308F',
  'U+3090',
  'U+3091',
  'U+3092',
  'U+3093',
  'U+3094',
  'U+3095',
  'U+3096',
  'U+3097',
  'U+3098',
  'U+3099',
  'U+309A',
  'U+309B',
  'U+309C',
  'U+309D',
  'U+309E',
  'U+309F',
])

const E69T25_WARN = Object.freeze([
])

const E69T25_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T25Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T25In (list, v) {
  for (const x of list) { if (E69T25Lower(x) === v) return true }
  return false
}

function E69T25Classify (tok) {
  const v = E69T25Lower(String(tok == null ? '' : tok))
  if (E69T25In(E69T25_BLOCK, v)) return E69T25_CLASS.BLOCK
  if (E69T25In(E69T25_WARN, v)) return E69T25_CLASS.WARN
  if (E69T25In(E69T25_ALLOW, v)) return E69T25_CLASS.ALLOW
  return E69T25_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T25_CLASS: E69T25_CLASS,
  E69T25_BLOCK: E69T25_BLOCK,
  E69T25_WARN: E69T25_WARN,
  E69T25_ALLOW: E69T25_ALLOW,
  E69T25Classify: E69T25Classify
})
