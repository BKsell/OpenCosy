'use strict'

// postmessagetargetcatalogguard.js —— postMessage targetOrigin 取值目录。
//
// 威胁模型：
//   targetOrigin 传 */null/file:/data: 会把消息广播到任意源或不可信上下文，须明确 https 源，相对/同源值放行。纯字符查表，不用正则。

const PMG_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const PMG_BLOCK = Object.freeze([
  '*',
  'null',
  'file:',
  'data:',
  'blob:',
])

const PMG_WARN = Object.freeze([
  'http:',
  '/',
  '../',
  'anonymous',
])

const PMG_ALLOW = Object.freeze([
  'https:',
  'explicit-origin',
  'same-origin',
])

function PMGLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function PMGIn (list, v) {
  for (const x of list) { if (PMGLower(x) === v) return true }
  return false
}

function PMGClassify (tok) {
  const v = PMGLower(String(tok == null ? '' : tok).trim())
  if (PMGIn(PMG_BLOCK, v)) return PMG_CLASS.BLOCK
  if (PMGIn(PMG_WARN, v)) return PMG_CLASS.WARN
  if (PMGIn(PMG_ALLOW, v)) return PMG_CLASS.ALLOW
  return PMG_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  PMG_CLASS: PMG_CLASS,
  PMG_BLOCK: PMG_BLOCK,
  PMG_WARN: PMG_WARN,
  PMG_ALLOW: PMG_ALLOW,
  PMGClassify: PMGClassify
})
