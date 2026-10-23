'use strict'

// historylengthcrossleakcatalogguard.js —— 历史/帧计数跨站泄露目录。
//
// 威胁模型：
//   history.length、跨站 frame 加载计数与 performance 条目可推断用户访问历史，
//   敏感页应隔离并加 COOP。纯字符查表，不用正则。

const HLE_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const HLE_BLOCK = Object.freeze([
  'history.length',
  'frame-count-probe',
  'performance-entries-cross',
  'navigation-leak',
])

const HLE_WARN = Object.freeze([
  'window.length',
])

const HLE_ALLOW = Object.freeze([
  'isolated',
  'coop',
])

function HLELower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function HLEIn (list, v) {
  for (const x of list) { if (HLELower(x) === v) return true }
  return false
}

function HLEClassify (tok) {
  const v = HLELower(String(tok == null ? '' : tok).trim())
  if (HLEIn(HLE_BLOCK, v)) return HLE_CLASS.BLOCK
  if (HLEIn(HLE_WARN, v)) return HLE_CLASS.WARN
  if (HLEIn(HLE_ALLOW, v)) return HLE_CLASS.ALLOW
  return HLE_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  HLE_CLASS: HLE_CLASS,
  HLE_BLOCK: HLE_BLOCK,
  HLE_WARN: HLE_WARN,
  HLE_ALLOW: HLE_ALLOW,
  HLEClassify: HLEClassify
})
