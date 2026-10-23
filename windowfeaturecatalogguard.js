'use strict'

// windowfeaturecatalogguard.js —— window.open 窗口特性目录。
//
// 威胁模型：
//   copyhistory/personalbar/menubar 等特性把历史记录或浏览器 chrome 暴露给弹窗，location/toolbar 可被隐藏钓鱼，noopener 安全。纯字符查表，不用正则。

const WNT_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const WNT_BLOCK = Object.freeze([
  'copyhistory',
  'personalbar',
  'menubar',
])

const WNT_WARN = Object.freeze([
  'toolbar',
  'location',
  'status',
  'scrollbars',
  'resizable',
])

const WNT_ALLOW = Object.freeze([
  'noopener',
  'noreferrer',
  'popup',
])

function WNTLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function WNTIn (list, v) {
  for (const x of list) { if (WNTLower(x) === v) return true }
  return false
}

function WNTClassify (tok) {
  const v = WNTLower(String(tok == null ? '' : tok).trim())
  if (WNTIn(WNT_BLOCK, v)) return WNT_CLASS.BLOCK
  if (WNTIn(WNT_WARN, v)) return WNT_CLASS.WARN
  if (WNTIn(WNT_ALLOW, v)) return WNT_CLASS.ALLOW
  return WNT_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  WNT_CLASS: WNT_CLASS,
  WNT_BLOCK: WNT_BLOCK,
  WNT_WARN: WNT_WARN,
  WNT_ALLOW: WNT_ALLOW,
  WNTClassify: WNTClassify
})
