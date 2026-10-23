'use strict'

// framecrossnavigationcatalogguard.js —— 跨框导航 Sink 目录。
//
// 威胁模型：
//   写 window.frames[i].location 或 contentWindow 可跨框导航钓鱼，
//   应在同源沙箱内并校验。纯字符查表，不用正则。

const FSO_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const FSO_BLOCK = Object.freeze([
  'frame-location-write',
  'contentwindow-navigate',
  'frames[0].location',
])

const FSO_WARN = Object.freeze([
  'contentwindow',
])

const FSO_ALLOW = Object.freeze([
  'same-origin-sandbox',
])

function FSOLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function FSOIn (list, v) {
  for (const x of list) { if (FSOLower(x) === v) return true }
  return false
}

function FSOClassify (tok) {
  const v = FSOLower(String(tok == null ? '' : tok).trim())
  if (FSOIn(FSO_BLOCK, v)) return FSO_CLASS.BLOCK
  if (FSOIn(FSO_WARN, v)) return FSO_CLASS.WARN
  if (FSOIn(FSO_ALLOW, v)) return FSO_CLASS.ALLOW
  return FSO_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  FSO_CLASS: FSO_CLASS,
  FSO_BLOCK: FSO_BLOCK,
  FSO_WARN: FSO_WARN,
  FSO_ALLOW: FSO_ALLOW,
  FSOClassify: FSOClassify
})
