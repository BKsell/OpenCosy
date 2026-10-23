'use strict'

// usbarbitrarytransfercatalogguard.js —— USB 任意设备传输目录。
//
// 威胁模型：
//   requestDevice 用任意 VID/PID 并 transferOut/controlTransfer 可重写固件或拦截设备，
//   应按已知厂商白名单。纯字符查表，不用正则。

const UBT_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const UBT_BLOCK = Object.freeze([
  'acceptalldevices',
  'transferout',
  'controltransfer',
  'claiminterface-untrusted',
])

const UBT_WARN = Object.freeze([
  'interrupt-transfer',
])

const UBT_ALLOW = Object.freeze([
  'vendor-allowlist',
])

function UBTLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function UBTIn (list, v) {
  for (const x of list) { if (UBTLower(x) === v) return true }
  return false
}

function UBTClassify (tok) {
  const v = UBTLower(String(tok == null ? '' : tok).trim())
  if (UBTIn(UBT_BLOCK, v)) return UBT_CLASS.BLOCK
  if (UBTIn(UBT_WARN, v)) return UBT_CLASS.WARN
  if (UBTIn(UBT_ALLOW, v)) return UBT_CLASS.ALLOW
  return UBT_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  UBT_CLASS: UBT_CLASS,
  UBT_BLOCK: UBT_BLOCK,
  UBT_WARN: UBT_WARN,
  UBT_ALLOW: UBT_ALLOW,
  UBTClassify: UBTClassify
})
