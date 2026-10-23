'use strict'

// cssinjectionsinkcatalogguard.js —— CSS 注入 Sink 目录。
//
// 威胁模型：
//   cssText/setProperty/insertRule 注入 url()/@import/expression 可外发数据或在旧引擎执行，
//   应用 classList 切换预定义类。纯字符查表，不用正则。

const CSSI_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const CSSI_BLOCK = Object.freeze([
  'csstext',
  '@import',
  'expression',
  'javascript:',
  'setproperty-url',
])

const CSSI_WARN = Object.freeze([
  'insertrule',
  'style.csstext',
])

const CSSI_ALLOW = Object.freeze([
  'classlist',
])

function CSSILower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function CSSIIn (list, v) {
  for (const x of list) { if (CSSILower(x) === v) return true }
  return false
}

function CSSIClassify (tok) {
  const v = CSSILower(String(tok == null ? '' : tok).trim())
  if (CSSIIn(CSSI_BLOCK, v)) return CSSI_CLASS.BLOCK
  if (CSSIIn(CSSI_WARN, v)) return CSSI_CLASS.WARN
  if (CSSIIn(CSSI_ALLOW, v)) return CSSI_CLASS.ALLOW
  return CSSI_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  CSSI_CLASS: CSSI_CLASS,
  CSSI_BLOCK: CSSI_BLOCK,
  CSSI_WARN: CSSI_WARN,
  CSSI_ALLOW: CSSI_ALLOW,
  CSSIClassify: CSSIClassify
})
