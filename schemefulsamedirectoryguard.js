'use strict'

// schemefulsamedirectoryguard.js —— SameSite/Schemeful 站点判定词目录。
//
// 威胁模型：
//   same-site/same-origin/schemefully-same-site/cross-site 等概念词用于隔离判定与 Cookie 策略。纯字符查表，不用正则。

const SSC_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const SSC_BLOCK = Object.freeze([
  'cross-site',
  'none',
  'unset',
  'no-restriction',
])

const SSC_WARN = Object.freeze([
  'same-site',
  'lax',
  'schemeful-same-site',
  'schemefully-same-site',
  'schemeful',
  'samesite=lax',
  'samesite=none',
  'lax+post',
  'top-level',
  'cross-origin',
  'site',
  'eTLD',
  'eTLD+1',
  'registrable',
])

const SSC_ALLOW = Object.freeze([
  'same-origin',
  'strict',
  'samesite=strict',
  'same-origin-policy',
  'origin',
  'scheme',
  'host',
  'port',
  'schemefully',
  'schemeful-same-origin',
])

function SSCLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function SSCIn (list, v) {
  for (const x of list) { if (SSCLower(x) === v) return true }
  return false
}

function SSCClassify (tok) {
  const v = SSCLower(String(tok == null ? '' : tok).trim())
  if (SSCIn(SSC_BLOCK, v)) return SSC_CLASS.BLOCK
  if (SSCIn(SSC_WARN, v)) return SSC_CLASS.WARN
  if (SSCIn(SSC_ALLOW, v)) return SSC_CLASS.ALLOW
  return SSC_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  SSC_CLASS: SSC_CLASS,
  SSC_BLOCK: SSC_BLOCK,
  SSC_WARN: SSC_WARN,
  SSC_ALLOW: SSC_ALLOW,
  SSCClassify: SSCClassify
})
