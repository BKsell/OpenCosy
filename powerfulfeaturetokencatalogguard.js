'use strict'

// powerfulfeaturetokencatalogguard.js —— Permissions-Policy 强大特性令牌目录。
//
// 威胁模型：
//   Permissions-Policy 若把 camera/microphone/geolocation 等设为 * 即对所有跨源放开。本模块按策略令牌集合
//   分级，纯字符，不用正则。

const PFT_REASON = Object.freeze({
  BLOCK: 'powerfulfeaturetokencatalog-input-hits-blocked-catalog',
  WARN: 'powerfulfeaturetokencatalog-input-hits-review-catalog',
  PREFIX: 'powerfulfeaturetokencatalog-input-hits-dangerous-prefix',
  EMPTY: 'powerfulfeaturetokencatalog-input-is-empty'
})

const PFT_BLOCK = Object.freeze([
  'camera=*',
  'microphone=*',
  'geolocation=*',
  'display-capture=*',
  'payment=*',
  'usb=*',
  'serial=*',
  'hid=*',
  'bluetooth=*',
  'midi=*',
  'clipboard-write=*',
  'window-management=*',
  'fullscreen=*',
])

const PFT_WARN = Object.freeze([
  'camera=(self)',
  'microphone=(self)',
  'geolocation=(self)',
  'autoplay=(self)',
  'fullscreen=(self)',
  'payment=(self)',
  'notifications=(self)',
])

const PFT_ALLOW = Object.freeze([
  'camera=()',
  'microphone=()',
  'geolocation=()',
  'usb=()',
  'serial=()',
  'hid=()',
  'bluetooth=()',
  'midi=()',
  'payment=()',
  'display-capture=()',
])

const PFT_PREFIX_LIT = Object.freeze([
])
const PFT_PREFIX_REASON = Object.freeze([
])

function PFTLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function PFTIn (list, v) {
  for (const x of list) { if (PFTLower(x) === v) return true }
  return false
}

function PFTSplit (inStr) {
  return inStr.split(',')
}

class PFTGuard {
  static get blockList () { return PFT_BLOCK }
  static get warnList () { return PFT_WARN }
  static get allowList () { return PFT_ALLOW }
  static get prefixLit () { return PFT_PREFIX_LIT }
  audit (inStr) {
    const findings = []
    if (typeof inStr !== 'string' || inStr.length === 0) return { safe: false, findings: [{ reason: PFT_REASON.EMPTY }] }
    for (const tok of PFTSplit(inStr)) {
      const cmp = PFTLower(String(tok).trim())
      if (PFTIn(PFT_BLOCK, cmp)) findings.push({ reason: PFT_REASON.BLOCK, detail: cmp })
      else if (PFTIn(PFT_WARN, cmp)) findings.push({ reason: PFT_REASON.WARN, detail: cmp })
      for (let i = 0; i < PFT_PREFIX_LIT.length; i++) {
        const lit = PFT_PREFIX_LIT[i]
        if (cmp.length >= lit.length && cmp.slice(0, lit.length) === lit) findings.push({ reason: PFT_REASON.PREFIX, detail: PFT_PREFIX_REASON[i] })
      }
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  PFT_REASON: PFT_REASON,
  PFT_BLOCK: PFT_BLOCK,
  PFT_WARN: PFT_WARN,
  PFT_ALLOW: PFT_ALLOW,
  PFTGuard: PFTGuard
})
