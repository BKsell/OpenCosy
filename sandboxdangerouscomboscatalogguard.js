'use strict'

// sandboxdangerouscomboscatalogguard.js —— iframe sandbox 危险组合目录。
//
// 威胁模型：
//   allow-scripts + allow-same-origin 同时存在时沙箱内容可移除自身沙箱，
//   叠加 allow-modals/top-navigation 风险更高。纯字符查表，不用正则。

const SFF_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const SFF_BLOCK = Object.freeze([
  'scripts+samesite',
  'popups-to-escape',
  'allow-modals-spoof',
  'top-navigation-untrusted',
])

const SFF_WARN = Object.freeze([
  'allow-forms',
])

const SFF_ALLOW = Object.freeze([
  'minimal-flags',
])

function SFFLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function SFFIn (list, v) {
  for (const x of list) { if (SFFLower(x) === v) return true }
  return false
}

function SFFClassify (tok) {
  const v = SFFLower(String(tok == null ? '' : tok).trim())
  if (SFFIn(SFF_BLOCK, v)) return SFF_CLASS.BLOCK
  if (SFFIn(SFF_WARN, v)) return SFF_CLASS.WARN
  if (SFFIn(SFF_ALLOW, v)) return SFF_CLASS.ALLOW
  return SFF_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  SFF_CLASS: SFF_CLASS,
  SFF_BLOCK: SFF_BLOCK,
  SFF_WARN: SFF_WARN,
  SFF_ALLOW: SFF_ALLOW,
  SFFClassify: SFFClassify
})
