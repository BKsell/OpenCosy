'use strict'

// e69hangulcompatjamocatalogguard.js —— 谚文兼容 Jamo 码位目录。
//
// 威胁模型：
//   兼容 Jamo 与现代 Jamo 码点不同但可能规范化等价，混排可绕过匹配，
//   机器字段应拒绝。纯字符查表，不用正则。

const E69T28_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T28_BLOCK = Object.freeze([
  'U+3130',
  'U+3131',
  'U+3132',
  'U+3133',
  'U+3134',
  'U+3135',
  'U+3136',
  'U+3137',
  'U+3138',
  'U+3139',
  'U+313A',
  'U+313B',
  'U+313C',
  'U+313D',
  'U+313E',
  'U+313F',
  'U+3140',
  'U+3141',
  'U+3142',
  'U+3143',
  'U+3144',
  'U+3145',
  'U+3146',
  'U+3147',
  'U+3148',
  'U+3149',
  'U+314A',
  'U+314B',
  'U+314C',
  'U+314D',
  'U+314E',
  'U+314F',
  'U+3150',
  'U+3151',
  'U+3152',
  'U+3153',
  'U+3154',
  'U+3155',
  'U+3156',
  'U+3157',
  'U+3158',
  'U+3159',
  'U+315A',
  'U+315B',
  'U+315C',
  'U+315D',
  'U+315E',
  'U+315F',
  'U+3160',
  'U+3161',
  'U+3162',
  'U+3163',
  'U+3164',
  'U+3165',
  'U+3166',
  'U+3167',
  'U+3168',
  'U+3169',
  'U+316A',
  'U+316B',
  'U+316C',
  'U+316D',
  'U+316E',
  'U+316F',
  'U+3170',
  'U+3171',
  'U+3172',
  'U+3173',
  'U+3174',
  'U+3175',
  'U+3176',
  'U+3177',
  'U+3178',
  'U+3179',
  'U+317A',
  'U+317B',
  'U+317C',
  'U+317D',
  'U+317E',
  'U+317F',
  'U+3180',
  'U+3181',
  'U+3182',
  'U+3183',
  'U+3184',
  'U+3185',
  'U+3186',
  'U+3187',
  'U+3188',
  'U+3189',
  'U+318A',
  'U+318B',
  'U+318C',
  'U+318D',
  'U+318E',
  'U+318F',
])

const E69T28_WARN = Object.freeze([
])

const E69T28_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T28Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T28In (list, v) {
  for (const x of list) { if (E69T28Lower(x) === v) return true }
  return false
}

function E69T28Classify (tok) {
  const v = E69T28Lower(String(tok == null ? '' : tok))
  if (E69T28In(E69T28_BLOCK, v)) return E69T28_CLASS.BLOCK
  if (E69T28In(E69T28_WARN, v)) return E69T28_CLASS.WARN
  if (E69T28In(E69T28_ALLOW, v)) return E69T28_CLASS.ALLOW
  return E69T28_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T28_CLASS: E69T28_CLASS,
  E69T28_BLOCK: E69T28_BLOCK,
  E69T28_WARN: E69T28_WARN,
  E69T28_ALLOW: E69T28_ALLOW,
  E69T28Classify: E69T28Classify
})
