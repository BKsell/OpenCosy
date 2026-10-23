'use strict'

// cachecontroltokendirectoryguard.js —— Cache-Control 指令目录。
//
// 威胁模型：
//   no-store/no-cache/private 保护敏感响应，public/max-age 长缓存敏感数据需复核，stale 指令常规。纯字符查表，不用正则。

const CCT_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const CCT_BLOCK = Object.freeze([
  'public',
])

const CCT_WARN = Object.freeze([
  'max-age',
  's-maxage',
  'no-cache',
  'must-revalidate',
  'proxy-revalidate',
  'stale-while-revalidate',
  'stale-if-error',
  'no-transform',
  'only-if-cached',
  'immutable',
])

const CCT_ALLOW = Object.freeze([
  'no-store',
  'private',
  'must-understand',
])

function CCTLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function CCTIn (list, v) {
  for (const x of list) { if (CCTLower(x) === v) return true }
  return false
}

function CCTClassify (tok) {
  const v = CCTLower(String(tok == null ? '' : tok).trim())
  if (CCTIn(CCT_BLOCK, v)) return CCT_CLASS.BLOCK
  if (CCTIn(CCT_WARN, v)) return CCT_CLASS.WARN
  if (CCTIn(CCT_ALLOW, v)) return CCT_CLASS.ALLOW
  return CCT_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  CCT_CLASS: CCT_CLASS,
  CCT_BLOCK: CCT_BLOCK,
  CCT_WARN: CCT_WARN,
  CCT_ALLOW: CCT_ALLOW,
  CCTClassify: CCTClassify
})
