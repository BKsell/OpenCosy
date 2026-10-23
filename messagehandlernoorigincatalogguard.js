'use strict'

// messagehandlernoorigincatalogguard.js —— message 监听缺源校验目录。
//
// 威胁模型：
//   message 事件不校验 event.origin/source 即处理 data 可被任意页面调用，
//   应显式比较受信源。纯字符查表，不用正则。

const PMH_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const PMH_BLOCK = Object.freeze([
  'onmessage-no-origin',
  'addeventlistener-message',
  'ev.data-unchecked',
])

const PMH_WARN = Object.freeze([
  'origin-wildcard-check',
])

const PMH_ALLOW = Object.freeze([
  'explicit-origin',
])

function PMHLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function PMHIn (list, v) {
  for (const x of list) { if (PMHLower(x) === v) return true }
  return false
}

function PMHClassify (tok) {
  const v = PMHLower(String(tok == null ? '' : tok).trim())
  if (PMHIn(PMH_BLOCK, v)) return PMH_CLASS.BLOCK
  if (PMHIn(PMH_WARN, v)) return PMH_CLASS.WARN
  if (PMHIn(PMH_ALLOW, v)) return PMH_CLASS.ALLOW
  return PMH_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  PMH_CLASS: PMH_CLASS,
  PMH_BLOCK: PMH_BLOCK,
  PMH_WARN: PMH_WARN,
  PMH_ALLOW: PMH_ALLOW,
  PMHClassify: PMHClassify
})
