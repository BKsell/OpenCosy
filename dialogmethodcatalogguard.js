'use strict'

// dialogmethodcatalogguard.js —— 同步/干扰式弹窗方法目录。
//
// 威胁模型：
//   alert/confirm/prompt 同步阻塞、beforeunload 滥用、onbeforeunload 文案可用于钓鱼，需受控。纯字符查表，不用正则。

const DLG_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const DLG_BLOCK = Object.freeze([
  'alert',
  'confirm',
  'prompt',
  'showModalDialog',
  'print',
])

const DLG_WARN = Object.freeze([
  'beforeunload',
  'onbeforeunload',
  'returnValue',
  'unload',
  'onunload',
  'pagehide',
  'pageshow',
  'freeze',
  'resume',
])

const DLG_ALLOW = Object.freeze([
  'none',
])

function DLGLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function DLGIn (list, v) {
  for (const x of list) { if (DLGLower(x) === v) return true }
  return false
}

function DLGClassify (tok) {
  const v = DLGLower(String(tok == null ? '' : tok).trim())
  if (DLGIn(DLG_BLOCK, v)) return DLG_CLASS.BLOCK
  if (DLGIn(DLG_WARN, v)) return DLG_CLASS.WARN
  if (DLGIn(DLG_ALLOW, v)) return DLG_CLASS.ALLOW
  return DLG_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  DLG_CLASS: DLG_CLASS,
  DLG_BLOCK: DLG_BLOCK,
  DLG_WARN: DLG_WARN,
  DLG_ALLOW: DLG_ALLOW,
  DLGClassify: DLGClassify
})
