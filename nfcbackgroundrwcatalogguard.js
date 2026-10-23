'use strict'

// nfcbackgroundrwcatalogguard.js —— NFC 后台读写目录。
//
// 威胁模型：
//   NDEFReader 后台持续 scan 或 write 标签可静默改写贴靠 NFC 设备/卡片，
//   应仅前台并需用户手势。纯字符查表，不用正则。

const NFB_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const NFB_BLOCK = Object.freeze([
  'background-scan',
  'write-tag',
  'ndef-write',
  'scan-forever',
])

const NFB_WARN = Object.freeze([
  'ndef-read',
])

const NFB_ALLOW = Object.freeze([
  'foreground-gesture',
])

function NFBLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function NFBIn (list, v) {
  for (const x of list) { if (NFBLower(x) === v) return true }
  return false
}

function NFBClassify (tok) {
  const v = NFBLower(String(tok == null ? '' : tok).trim())
  if (NFBIn(NFB_BLOCK, v)) return NFB_CLASS.BLOCK
  if (NFBIn(NFB_WARN, v)) return NFB_CLASS.WARN
  if (NFBIn(NFB_ALLOW, v)) return NFB_CLASS.ALLOW
  return NFB_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  NFB_CLASS: NFB_CLASS,
  NFB_BLOCK: NFB_BLOCK,
  NFB_WARN: NFB_WARN,
  NFB_ALLOW: NFB_ALLOW,
  NFBClassify: NFBClassify
})
