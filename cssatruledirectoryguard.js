'use strict'

// cssatruledirectoryguard.js —— CSS @规则风险目录。
//
// 威胁模型：
//   @import 可外连、@namespace 可改变匹配、@font-face 可外连字体；@media/@supports 等结构化规则常规。纯字符查表，不用正则。

const CAR_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const CAR_BLOCK = Object.freeze([
  '@import',
  '@namespace',
])

const CAR_WARN = Object.freeze([
  '@font-face',
  '@font-feature-values',
  '@font-palette-values',
  '@page',
  '@viewport',
  '@counter-style',
  '@property',
  '@layer',
  '@container',
  '@scope',
  '@starting-style',
])

const CAR_ALLOW = Object.freeze([
  '@media',
  '@supports',
  '@keyframes',
  '@-webkit-keyframes',
  '@charset',
  '@document',
  '@host',
  '@slotted',
  '@page-margin',
  '@color-profile',
])

function CARLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function CARIn (list, v) {
  for (const x of list) { if (CARLower(x) === v) return true }
  return false
}

function CARClassify (tok) {
  const v = CARLower(String(tok == null ? '' : tok).trim())
  if (CARIn(CAR_BLOCK, v)) return CAR_CLASS.BLOCK
  if (CARIn(CAR_WARN, v)) return CAR_CLASS.WARN
  if (CARIn(CAR_ALLOW, v)) return CAR_CLASS.ALLOW
  return CAR_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  CAR_CLASS: CAR_CLASS,
  CAR_BLOCK: CAR_BLOCK,
  CAR_WARN: CAR_WARN,
  CAR_ALLOW: CAR_ALLOW,
  CARClassify: CARClassify
})
