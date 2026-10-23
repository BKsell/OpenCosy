'use strict'

// screencapturesystemaudiocatalogguard.js —— 屏幕采集范围目录。
//
// 威胁模型：
//   prefer-current-tab/system 音频与全屏捕获会记录跨应用内容，
//   应最小到标签页并瞬时授权。纯字符查表，不用正则。

const SCR_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const SCR_BLOCK = Object.freeze([
  'prefer-current-tab',
  'system-audio',
  'monitor-surfaces',
  'prefer-display',
])

const SCR_WARN = Object.freeze([
  'audio-loopback',
])

const SCR_ALLOW = Object.freeze([
  'tab-only',
  'transient',
])

function SCRLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function SCRIn (list, v) {
  for (const x of list) { if (SCRLower(x) === v) return true }
  return false
}

function SCRClassify (tok) {
  const v = SCRLower(String(tok == null ? '' : tok).trim())
  if (SCRIn(SCR_BLOCK, v)) return SCR_CLASS.BLOCK
  if (SCRIn(SCR_WARN, v)) return SCR_CLASS.WARN
  if (SCRIn(SCR_ALLOW, v)) return SCR_CLASS.ALLOW
  return SCR_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  SCR_CLASS: SCR_CLASS,
  SCR_BLOCK: SCR_BLOCK,
  SCR_WARN: SCR_WARN,
  SCR_ALLOW: SCR_ALLOW,
  SCRClassify: SCRClassify
})
