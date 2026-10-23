'use strict'

// cookieprefixvaluecatalogguard.js —— Cookie 名安全前缀目录。
//
// 威胁模型：
//   __Secure- 要求 Secure，__Host- 还要求 path=/ 且无 Domain；缺约束的伪前缀 cookie 应拒。本模块按 cookie 名
//   前缀分级，纯字符，不用正则。

const CPV_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const CPV_BLOCK = Object.freeze([
  '__host-with-domain',
  '__secure-without-secure',
  '__host-without-path-root',
])

const CPV_WARN = Object.freeze([
  'sessionid',
  'sid',
  'phpsessid',
  'jsessionid',
  'asp.net_sessionid',
  'remember-me',
])

const CPV_ALLOW = Object.freeze([
  '__Host-id',
  '__Secure-id',
  'csrf_token',
  'prefs_theme',
])

function CPVLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function CPVIn (list, v) {
  for (const x of list) { if (CPVLower(x) === v) return true }
  return false
}

function CPVClassify (tok) {
  const v = CPVLower(String(tok == null ? '' : tok).trim())
  if (CPVIn(CPV_BLOCK, v)) return CPV_CLASS.BLOCK
  if (CPVIn(CPV_WARN, v)) return CPV_CLASS.WARN
  if (CPVIn(CPV_ALLOW, v)) return CPV_CLASS.ALLOW
  return CPV_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  CPV_CLASS: CPV_CLASS,
  CPV_BLOCK: CPV_BLOCK,
  CPV_WARN: CPV_WARN,
  CPV_ALLOW: CPV_ALLOW,
  CPVClassify: CPVClassify
})
