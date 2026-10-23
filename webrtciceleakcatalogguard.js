'use strict'

// webrtciceleakcatalogguard.js —— WebRTC ICE 泄露目录。
//
// 威胁模型：
//   STUN/TURN 凭据外发、host candidate/mDNS 关闭会暴露内网 IP，
//   应 iceTransportPolicy=relay 并开 mDNS 混淆。纯字符查表，不用正则。

const WIC_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const WIC_BLOCK = Object.freeze([
  'host-candidate',
  'mdns-off',
  'ice-credentials-url',
  'srflx-leak',
])

const WIC_WARN = Object.freeze([
  'turn-credentials-static',
])

const WIC_ALLOW = Object.freeze([
  'relay-only',
  'mdns-anonymize',
])

function WICLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function WICIn (list, v) {
  for (const x of list) { if (WICLower(x) === v) return true }
  return false
}

function WICClassify (tok) {
  const v = WICLower(String(tok == null ? '' : tok).trim())
  if (WICIn(WIC_BLOCK, v)) return WIC_CLASS.BLOCK
  if (WICIn(WIC_WARN, v)) return WIC_CLASS.WARN
  if (WICIn(WIC_ALLOW, v)) return WIC_CLASS.ALLOW
  return WIC_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  WIC_CLASS: WIC_CLASS,
  WIC_BLOCK: WIC_BLOCK,
  WIC_WARN: WIC_WARN,
  WIC_ALLOW: WIC_ALLOW,
  WICClassify: WICClassify
})
