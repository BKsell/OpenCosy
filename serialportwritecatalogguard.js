'use strict'

// serialportwritecatalogguard.js —— 串口读写目录。
//
// 威胁模型：
//   requestPort/open 后写任意波特率数据可驱动工业/外设执行动作，
//   应让用户显式选择端口。纯字符查表，不用正则。

const SPW_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const SPW_BLOCK = Object.freeze([
  'requestport-any',
  'baud-write',
  'setsignals',
  'serial-write-untrusted',
])

const SPW_WARN = Object.freeze([
  'serial-read',
])

const SPW_ALLOW = Object.freeze([
  'user-picked-port',
])

function SPWLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function SPWIn (list, v) {
  for (const x of list) { if (SPWLower(x) === v) return true }
  return false
}

function SPWClassify (tok) {
  const v = SPWLower(String(tok == null ? '' : tok).trim())
  if (SPWIn(SPW_BLOCK, v)) return SPW_CLASS.BLOCK
  if (SPWIn(SPW_WARN, v)) return SPW_CLASS.WARN
  if (SPWIn(SPW_ALLOW, v)) return SPW_CLASS.ALLOW
  return SPW_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  SPW_CLASS: SPW_CLASS,
  SPW_BLOCK: SPW_BLOCK,
  SPW_WARN: SPW_WARN,
  SPW_ALLOW: SPW_ALLOW,
  SPWClassify: SPWClassify
})
