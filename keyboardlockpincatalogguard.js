'use strict'

// keyboardlockpincatalogguard.js —— 键盘锁定捕获目录。
//
// 威胁模型：
//   requestKeyboardLock 锁定退出键序列可在全屏钓鱼中拦截 ESC/PIN 输入，
//   应只请求必要键并可退出。纯字符查表，不用正则。

const KBD_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const KBD_BLOCK = Object.freeze([
  'lock-all-keys',
  'pin-capture',
  'esc-locked',
  'requestkeyboardlock-untrusted',
])

const KBD_WARN = Object.freeze([
  'specific-keys',
])

const KBD_ALLOW = Object.freeze([
  'escape-enabled',
])

function KBDLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function KBDIn (list, v) {
  for (const x of list) { if (KBDLower(x) === v) return true }
  return false
}

function KBDClassify (tok) {
  const v = KBDLower(String(tok == null ? '' : tok).trim())
  if (KBDIn(KBD_BLOCK, v)) return KBD_CLASS.BLOCK
  if (KBDIn(KBD_WARN, v)) return KBD_CLASS.WARN
  if (KBDIn(KBD_ALLOW, v)) return KBD_CLASS.ALLOW
  return KBD_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  KBD_CLASS: KBD_CLASS,
  KBD_BLOCK: KBD_BLOCK,
  KBD_WARN: KBD_WARN,
  KBD_ALLOW: KBD_ALLOW,
  KBDClassify: KBDClassify
})
