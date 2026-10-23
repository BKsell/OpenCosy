'use strict'

// deprecateddialogmethodcatalogguard.js —— 废弃/模态对话框目录。
//
// 威胁模型：
//   showModalDialog 已废弃且同步跨文档，window.open 传 dialogArguments 会泄露调用上下文，
//   应使用无 opener 的受控弹窗。纯字符查表，不用正则。

const ODG_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const ODG_BLOCK = Object.freeze([
  'showmodaldialog',
  'dialogarguments',
  'window.open-modal',
])

const ODG_WARN = Object.freeze([
  'popup',
  'alert-modal',
])

const ODG_ALLOW = Object.freeze([
  'noopener-window',
])

function ODGLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function ODGIn (list, v) {
  for (const x of list) { if (ODGLower(x) === v) return true }
  return false
}

function ODGClassify (tok) {
  const v = ODGLower(String(tok == null ? '' : tok).trim())
  if (ODGIn(ODG_BLOCK, v)) return ODG_CLASS.BLOCK
  if (ODGIn(ODG_WARN, v)) return ODG_CLASS.WARN
  if (ODGIn(ODG_ALLOW, v)) return ODG_CLASS.ALLOW
  return ODG_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  ODG_CLASS: ODG_CLASS,
  ODG_BLOCK: ODG_BLOCK,
  ODG_WARN: ODG_WARN,
  ODG_ALLOW: ODG_ALLOW,
  ODGClassify: ODGClassify
})
