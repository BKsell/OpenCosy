'use strict'

// e70cyrillicextbcatalogguard.js —— 西里尔扩展 B 码位目录。
//
// 威胁模型：
//   扩展 B 西里尔字符含与拉丁近似字形，常规字段无正当用途，
//   机器字段应拒绝。纯字符查表，不用正则。

const E70T58_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T58_BLOCK = Object.freeze([
  'U+A640',
  'U+A641',
  'U+A642',
  'U+A643',
  'U+A644',
  'U+A645',
  'U+A646',
  'U+A647',
  'U+A648',
  'U+A649',
  'U+A64A',
  'U+A64B',
  'U+A64C',
  'U+A64D',
  'U+A64E',
  'U+A64F',
  'U+A650',
  'U+A651',
  'U+A652',
  'U+A653',
  'U+A654',
  'U+A655',
  'U+A656',
  'U+A657',
  'U+A658',
  'U+A659',
  'U+A65A',
  'U+A65B',
  'U+A65C',
  'U+A65D',
  'U+A65E',
  'U+A65F',
  'U+A660',
  'U+A661',
  'U+A662',
  'U+A663',
  'U+A664',
  'U+A665',
  'U+A666',
  'U+A667',
  'U+A668',
  'U+A669',
  'U+A66A',
  'U+A66B',
  'U+A66C',
  'U+A66D',
  'U+A66E',
  'U+A66F',
  'U+A670',
  'U+A671',
  'U+A672',
  'U+A673',
  'U+A674',
  'U+A675',
  'U+A676',
  'U+A677',
  'U+A678',
  'U+A679',
  'U+A67A',
  'U+A67B',
  'U+A67C',
  'U+A67D',
  'U+A67E',
  'U+A67F',
  'U+A680',
  'U+A681',
  'U+A682',
  'U+A683',
  'U+A684',
  'U+A685',
  'U+A686',
  'U+A687',
  'U+A688',
  'U+A689',
  'U+A68A',
  'U+A68B',
  'U+A68C',
  'U+A68D',
  'U+A68E',
  'U+A68F',
  'U+A690',
  'U+A691',
  'U+A692',
  'U+A693',
  'U+A694',
  'U+A695',
  'U+A696',
  'U+A697',
  'U+A698',
  'U+A699',
  'U+A69A',
  'U+A69B',
  'U+A69C',
  'U+A69D',
  'U+A69E',
  'U+A69F',
])

const E70T58_WARN = Object.freeze([
])

const E70T58_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T58Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T58In (list, v) {
  for (const x of list) { if (E70T58Lower(x) === v) return true }
  return false
}

function E70T58Classify (tok) {
  const v = E70T58Lower(String(tok == null ? '' : tok))
  if (E70T58In(E70T58_BLOCK, v)) return E70T58_CLASS.BLOCK
  if (E70T58In(E70T58_WARN, v)) return E70T58_CLASS.WARN
  if (E70T58In(E70T58_ALLOW, v)) return E70T58_CLASS.ALLOW
  return E70T58_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T58_CLASS: E70T58_CLASS,
  E70T58_BLOCK: E70T58_BLOCK,
  E70T58_WARN: E70T58_WARN,
  E70T58_ALLOW: E70T58_ALLOW,
  E70T58Classify: E70T58Classify
})
