'use strict'

// audiosignalfingerprintcatalogguard.js —— Audio 指纹目录。
//
// 威胁模型：
//   AudioContext 振荡器 + Analyser 读频响差异可做无状态指纹，
//   应降低精度或不读取。纯字符查表，不用正则。

const AFP_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const AFP_BLOCK = Object.freeze([
  'audiocontext-fingerprint',
  'oscillator-analyser',
  'createport-entropy',
  'copysamplerange',
])

const AFP_WARN = Object.freeze([
  'offlinecontext-entropy',
])

const AFP_ALLOW = Object.freeze([
  'not-read',
  'reduced-precision',
])

function AFPLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function AFPIn (list, v) {
  for (const x of list) { if (AFPLower(x) === v) return true }
  return false
}

function AFPClassify (tok) {
  const v = AFPLower(String(tok == null ? '' : tok).trim())
  if (AFPIn(AFP_BLOCK, v)) return AFP_CLASS.BLOCK
  if (AFPIn(AFP_WARN, v)) return AFP_CLASS.WARN
  if (AFPIn(AFP_ALLOW, v)) return AFP_CLASS.ALLOW
  return AFP_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  AFP_CLASS: AFP_CLASS,
  AFP_BLOCK: AFP_BLOCK,
  AFP_WARN: AFP_WARN,
  AFP_ALLOW: AFP_ALLOW,
  AFPClassify: AFPClassify
})
