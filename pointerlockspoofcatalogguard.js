'use strict'

// pointerlockspoofcatalogguard.js —— 指针锁定伪装目录。
//
// 威胁模型：
//   requestPointerLock 可隐藏/替换真实光标实施点击劫持，unadjustedMovement 下更难分辨，
//   应可随时 ESC 退出并提示。纯字符查表，不用正则。

const PTL_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const PTL_BLOCK = Object.freeze([
  'requestpointerlock-untrusted',
  'unadjustedmovement',
  'cursor-hidden-spoof',
])

const PTL_WARN = Object.freeze([
  'pointerlock-element',
])

const PTL_ALLOW = Object.freeze([
  'exitpointerlock',
  'user-gesture',
])

function PTLLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function PTLIn (list, v) {
  for (const x of list) { if (PTLLower(x) === v) return true }
  return false
}

function PTLClassify (tok) {
  const v = PTLLower(String(tok == null ? '' : tok).trim())
  if (PTLIn(PTL_BLOCK, v)) return PTL_CLASS.BLOCK
  if (PTLIn(PTL_WARN, v)) return PTL_CLASS.WARN
  if (PTLIn(PTL_ALLOW, v)) return PTL_CLASS.ALLOW
  return PTL_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  PTL_CLASS: PTL_CLASS,
  PTL_BLOCK: PTL_BLOCK,
  PTL_WARN: PTL_WARN,
  PTL_ALLOW: PTL_ALLOW,
  PTLClassify: PTLClassify
})
