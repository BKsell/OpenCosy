'use strict'

// debugqueryenabledcatalogguard.js —— 调试开关残留目录。
//
// 威胁模型：
//   ?debug=1、localStorage debug=true 或暴露 stack 的开关残留到生产会打开详细错误/测试面，
//   应在发布构建关闭。纯字符查表，不用正则。

const DBG_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const DBG_BLOCK = Object.freeze([
  '?debug=',
  'localstorage-debug',
  'debug=true',
  'stack-enabled',
  'verbose-flag',
])

const DBG_WARN = Object.freeze([
  'devtools-open',
])

const DBG_ALLOW = Object.freeze([
  'prod-off',
])

function DBGLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function DBGIn (list, v) {
  for (const x of list) { if (DBGLower(x) === v) return true }
  return false
}

function DBGClassify (tok) {
  const v = DBGLower(String(tok == null ? '' : tok).trim())
  if (DBGIn(DBG_BLOCK, v)) return DBG_CLASS.BLOCK
  if (DBGIn(DBG_WARN, v)) return DBG_CLASS.WARN
  if (DBGIn(DBG_ALLOW, v)) return DBG_CLASS.ALLOW
  return DBG_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  DBG_CLASS: DBG_CLASS,
  DBG_BLOCK: DBG_BLOCK,
  DBG_WARN: DBG_WARN,
  DBG_ALLOW: DBG_ALLOW,
  DBGClassify: DBGClassify
})
