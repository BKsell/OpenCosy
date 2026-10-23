'use strict'

// vibrationabusepatterncatalogguard.js —— 振动滥用目录。
//
// 威胁模型：
//   navigator.vibrate 长/循环模式可做侧信道或持续骚扰，
//   应短时并允许系统忽略。纯字符查表，不用正则。

const VIB_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const VIB_BLOCK = Object.freeze([
  'long-pattern',
  'loop-vibrate',
  'vibrate-fingerprint',
  'vibrate-spam',
])

const VIB_WARN = Object.freeze([
  'short-burst',
])

const VIB_ALLOW = Object.freeze([
  'short',
])

function VIBLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function VIBIn (list, v) {
  for (const x of list) { if (VIBLower(x) === v) return true }
  return false
}

function VIBClassify (tok) {
  const v = VIBLower(String(tok == null ? '' : tok).trim())
  if (VIBIn(VIB_BLOCK, v)) return VIB_CLASS.BLOCK
  if (VIBIn(VIB_WARN, v)) return VIB_CLASS.WARN
  if (VIBIn(VIB_ALLOW, v)) return VIB_CLASS.ALLOW
  return VIB_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  VIB_CLASS: VIB_CLASS,
  VIB_BLOCK: VIB_BLOCK,
  VIB_WARN: VIB_WARN,
  VIB_ALLOW: VIB_ALLOW,
  VIBClassify: VIBClassify
})
