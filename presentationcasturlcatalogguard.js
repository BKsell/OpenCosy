'use strict'

// presentationcasturlcatalogguard.js —— Presentation 投屏目录。
//
// 威胁模型：
//   PresentationRequest 投屏到任意 cast URL、自动 reconnect 可把页面内容投到不受控设备，
//   应用户选择并可断开。纯字符查表，不用正则。

const PRES_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const PRES_BLOCK = Object.freeze([
  'cast-url-input',
  'reconnect-automatic',
  'presentationrequest-any',
])

const PRES_WARN = Object.freeze([
  'availability-monitor',
])

const PRES_ALLOW = Object.freeze([
  'user-selected',
  'controls',
])

function PRESLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function PRESIn (list, v) {
  for (const x of list) { if (PRESLower(x) === v) return true }
  return false
}

function PRESClassify (tok) {
  const v = PRESLower(String(tok == null ? '' : tok).trim())
  if (PRESIn(PRES_BLOCK, v)) return PRES_CLASS.BLOCK
  if (PRESIn(PRES_WARN, v)) return PRES_CLASS.WARN
  if (PRESIn(PRES_ALLOW, v)) return PRES_CLASS.ALLOW
  return PRES_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  PRES_CLASS: PRES_CLASS,
  PRES_BLOCK: PRES_BLOCK,
  PRES_WARN: PRES_WARN,
  PRES_ALLOW: PRES_ALLOW,
  PRESClassify: PRESClassify
})
