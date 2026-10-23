'use strict'

// sendbeaconthirdpartycatalogguard.js —— sendBeacon 外发目录。
//
// 威胁模型：
//   navigator.sendBeacon 把数据 POST 到第三方会在卸载时静默外发敏感信息，
//   应限受控遥测端点。纯字符查表，不用正则。

const BCN_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const BCN_BLOCK = Object.freeze([
  'sendbeacon-third-party',
  'sendbeacon-pii',
  'beacon-input-url',
])

const BCN_WARN = Object.freeze([
  'beacon-cross',
])

const BCN_ALLOW = Object.freeze([
  'telemetry-allowlist',
])

function BCNLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function BCNIn (list, v) {
  for (const x of list) { if (BCNLower(x) === v) return true }
  return false
}

function BCNClassify (tok) {
  const v = BCNLower(String(tok == null ? '' : tok).trim())
  if (BCNIn(BCN_BLOCK, v)) return BCN_CLASS.BLOCK
  if (BCNIn(BCN_WARN, v)) return BCN_CLASS.WARN
  if (BCNIn(BCN_ALLOW, v)) return BCN_CLASS.ALLOW
  return BCN_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  BCN_CLASS: BCN_CLASS,
  BCN_BLOCK: BCN_BLOCK,
  BCN_WARN: BCN_WARN,
  BCN_ALLOW: BCN_ALLOW,
  BCNClassify: BCNClassify
})
