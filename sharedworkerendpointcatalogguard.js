'use strict'

// sharedworkerendpointcatalogguard.js —— SharedWorker 端点目录。
//
// 威胁模型：
//   SharedWorker 连接任意源或端口消息无来源校验会在上下文间泄露数据，
//   应同源并校验端口来源。纯字符查表，不用正则。

const SHW_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const SHW_BLOCK = Object.freeze([
  'sharedworker-*',
  'port-no-origin',
  'sharedworker-cross',
])

const SHW_WARN = Object.freeze([
  'sharedworker-default',
])

const SHW_ALLOW = Object.freeze([
  'same-origin-port',
])

function SHWLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function SHWIn (list, v) {
  for (const x of list) { if (SHWLower(x) === v) return true }
  return false
}

function SHWClassify (tok) {
  const v = SHWLower(String(tok == null ? '' : tok).trim())
  if (SHWIn(SHW_BLOCK, v)) return SHW_CLASS.BLOCK
  if (SHWIn(SHW_WARN, v)) return SHW_CLASS.WARN
  if (SHWIn(SHW_ALLOW, v)) return SHW_CLASS.ALLOW
  return SHW_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  SHW_CLASS: SHW_CLASS,
  SHW_BLOCK: SHW_BLOCK,
  SHW_WARN: SHW_WARN,
  SHW_ALLOW: SHW_ALLOW,
  SHWClassify: SHWClassify
})
