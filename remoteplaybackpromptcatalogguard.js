'use strict'

// remoteplaybackpromptcatalogguard.js —— Remote Playback 目录。
//
// 威胁模型：
//   watchAvailability 常驻 + remote.prompt() 可在未充分提示下把媒体投到远端，
//   应默认禁用可用性监听。纯字符查表，不用正则。

const RPB_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const RPB_BLOCK = Object.freeze([
  'watchavailability',
  'remote.prompt',
  'state-connecting',
])

const RPB_WARN = Object.freeze([
  'remoteplayback-untrusted',
])

const RPB_ALLOW = Object.freeze([
  'availability-off',
])

function RPBLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function RPBIn (list, v) {
  for (const x of list) { if (RPBLower(x) === v) return true }
  return false
}

function RPBClassify (tok) {
  const v = RPBLower(String(tok == null ? '' : tok).trim())
  if (RPBIn(RPB_BLOCK, v)) return RPB_CLASS.BLOCK
  if (RPBIn(RPB_WARN, v)) return RPB_CLASS.WARN
  if (RPBIn(RPB_ALLOW, v)) return RPB_CLASS.ALLOW
  return RPB_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  RPB_CLASS: RPB_CLASS,
  RPB_BLOCK: RPB_BLOCK,
  RPB_WARN: RPB_WARN,
  RPB_ALLOW: RPB_ALLOW,
  RPBClassify: RPBClassify
})
