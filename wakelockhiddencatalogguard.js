'use strict'

// wakelockhiddencatalogguard.js —— 后台唤醒锁目录。
//
// 威胁模型：
//   visible 之外仍持有 screen Wake Lock 可让设备常亮耗电/掩盖后台行为，
//   页面隐藏应 release。纯字符查表，不用正则。

const WKL_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const WKL_BLOCK = Object.freeze([
  'request-hidden',
  'no-release-on-hidden',
  'keepalive-background',
])

const WKL_WARN = Object.freeze([
  'reacquire',
])

const WKL_ALLOW = Object.freeze([
  'release-on-hidden',
])

function WKLLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function WKLIn (list, v) {
  for (const x of list) { if (WKLLower(x) === v) return true }
  return false
}

function WKLClassify (tok) {
  const v = WKLLower(String(tok == null ? '' : tok).trim())
  if (WKLIn(WKL_BLOCK, v)) return WKL_CLASS.BLOCK
  if (WKLIn(WKL_WARN, v)) return WKL_CLASS.WARN
  if (WKLIn(WKL_ALLOW, v)) return WKL_CLASS.ALLOW
  return WKL_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  WKL_CLASS: WKL_CLASS,
  WKL_BLOCK: WKL_BLOCK,
  WKL_WARN: WKL_WARN,
  WKL_ALLOW: WKL_ALLOW,
  WKLClassify: WKLClassify
})
