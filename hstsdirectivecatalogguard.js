'use strict'

// hstsdirectivecatalogguard.js —— HSTS 指令风险目录。
//
// 威胁模型：
//   max-age=0 等于关闭 HSTS；缺 includeSubDomains/preload 对高安全域需复核，长 max-age 强策略放行。纯字符查表，不用正则。

const HST_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const HST_BLOCK = Object.freeze([
  'max-age=0',
])

const HST_WARN = Object.freeze([
  'max-age=300',
  'max-age=86400',
  'max-age=2592000',
  'max-age=31536000',
])

const HST_ALLOW = Object.freeze([
  'max-age=63072000',
  'max-age=126144000',
  'max-age=630720000',
  'includeSubDomains',
  'preload',
])

function HSTLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function HSTIn (list, v) {
  for (const x of list) { if (HSTLower(x) === v) return true }
  return false
}

function HSTClassify (tok) {
  const v = HSTLower(String(tok == null ? '' : tok).trim())
  if (HSTIn(HST_BLOCK, v)) return HST_CLASS.BLOCK
  if (HSTIn(HST_WARN, v)) return HST_CLASS.WARN
  if (HSTIn(HST_ALLOW, v)) return HST_CLASS.ALLOW
  return HST_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  HST_CLASS: HST_CLASS,
  HST_BLOCK: HST_BLOCK,
  HST_WARN: HST_WARN,
  HST_ALLOW: HST_ALLOW,
  HSTClassify: HSTClassify
})
