'use strict'

// eventsourceendpointcatalogguard.js —— EventSource 跨源目录。
//
// 威胁模型：
//   new EventSource 连接跨源且 withCredentials 会持续带 Cookie 接收推送，
//   应同源。纯字符查表，不用正则。

const ESJ_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const ESJ_BLOCK = Object.freeze([
  'eventsource-cross',
  'withcredentials',
  'eventsource-input',
])

const ESJ_WARN = Object.freeze([
  'reconnect-infinite',
])

const ESJ_ALLOW = Object.freeze([
  'same-origin',
])

function ESJLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function ESJIn (list, v) {
  for (const x of list) { if (ESJLower(x) === v) return true }
  return false
}

function ESJClassify (tok) {
  const v = ESJLower(String(tok == null ? '' : tok).trim())
  if (ESJIn(ESJ_BLOCK, v)) return ESJ_CLASS.BLOCK
  if (ESJIn(ESJ_WARN, v)) return ESJ_CLASS.WARN
  if (ESJIn(ESJ_ALLOW, v)) return ESJ_CLASS.ALLOW
  return ESJ_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  ESJ_CLASS: ESJ_CLASS,
  ESJ_BLOCK: ESJ_BLOCK,
  ESJ_WARN: ESJ_WARN,
  ESJ_ALLOW: ESJ_ALLOW,
  ESJClassify: ESJClassify
})
