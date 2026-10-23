'use strict'

// cookieattributedirectoryguard.js —— Cookie 属性目录。
//
// 威胁模型：
//   Set-Cookie 属性中 HttpOnly/Secure/SameSite/Prefix 关系安全，Domain/Path/Expires 过宽需复核。纯字符查表，不用正则。

const CCD_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const CCD_BLOCK = Object.freeze([
  'SameSite=None',
])

const CCD_WARN = Object.freeze([
  'Domain',
  'Expires',
  'Max-Age',
  'Path',
  'SameSite=Lax',
  'SameSite',
  'Priority',
  'SameParty',
  'Partitioned',
  'Persistent',
])

const CCD_ALLOW = Object.freeze([
  'HttpOnly',
  'Secure',
  'SameSite=Strict',
  'Lax',
  'Strict',
  'None',
  'name',
  'value',
  'HostOnly',
  'HostOnly-true',
  'session-cookie',
  '__Host-',
  '__Secure-',
])

function CCDLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function CCDIn (list, v) {
  for (const x of list) { if (CCDLower(x) === v) return true }
  return false
}

function CCDClassify (tok) {
  const v = CCDLower(String(tok == null ? '' : tok).trim())
  if (CCDIn(CCD_BLOCK, v)) return CCD_CLASS.BLOCK
  if (CCDIn(CCD_WARN, v)) return CCD_CLASS.WARN
  if (CCDIn(CCD_ALLOW, v)) return CCD_CLASS.ALLOW
  return CCD_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  CCD_CLASS: CCD_CLASS,
  CCD_BLOCK: CCD_BLOCK,
  CCD_WARN: CCD_WARN,
  CCD_ALLOW: CCD_ALLOW,
  CCDClassify: CCDClassify
})
