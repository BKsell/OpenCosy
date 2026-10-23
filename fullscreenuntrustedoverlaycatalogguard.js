'use strict'

// fullscreenuntrustedoverlaycatalogguard.js —— 全屏覆盖风险目录。
//
// 威胁模型：
//   对不可信元素 requestFullscreen 可叠加全屏覆盖层做钓鱼，webkit 前缀同样受控，
//   需用户手势并限制元素。纯字符查表，不用正则。

const FSE_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const FSE_BLOCK = Object.freeze([
  'requestfullscreen-untrusted',
  'webkitrequestfullscreen',
  'fullscreen-div-overlay',
])

const FSE_WARN = Object.freeze([
  'keyboard-lock-in-fullscreen',
])

const FSE_ALLOW = Object.freeze([
  'user-gesture',
  'fullscreenelement-checked',
])

function FSELower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function FSEIn (list, v) {
  for (const x of list) { if (FSELower(x) === v) return true }
  return false
}

function FSEClassify (tok) {
  const v = FSELower(String(tok == null ? '' : tok).trim())
  if (FSEIn(FSE_BLOCK, v)) return FSE_CLASS.BLOCK
  if (FSEIn(FSE_WARN, v)) return FSE_CLASS.WARN
  if (FSEIn(FSE_ALLOW, v)) return FSE_CLASS.ALLOW
  return FSE_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  FSE_CLASS: FSE_CLASS,
  FSE_BLOCK: FSE_BLOCK,
  FSE_WARN: FSE_WARN,
  FSE_ALLOW: FSE_ALLOW,
  FSEClassify: FSEClassify
})
