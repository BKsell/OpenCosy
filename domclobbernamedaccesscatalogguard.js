'use strict'

// domclobbernamedaccesscatalogguard.js —— DOM Clobber 命名访问目录。
//
// 威胁模型：
//   利用表单 id/name 覆盖 window 属性或 getElementById 结果可篡改后续安全检查，
//   应直接引用并校验节点类型。纯字符查表，不用正则。

const DBC_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const DBC_BLOCK = Object.freeze([
  'window.named-form',
  'getelementbyid-clobbered',
  'form-id-window',
  'name-access-override',
])

const DBC_WARN = Object.freeze([
  'named-access',
])

const DBC_ALLOW = Object.freeze([
  'strict-getelementbyid',
])

function DBCLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function DBCIn (list, v) {
  for (const x of list) { if (DBCLower(x) === v) return true }
  return false
}

function DBCClassify (tok) {
  const v = DBCLower(String(tok == null ? '' : tok).trim())
  if (DBCIn(DBC_BLOCK, v)) return DBC_CLASS.BLOCK
  if (DBCIn(DBC_WARN, v)) return DBC_CLASS.WARN
  if (DBCIn(DBC_ALLOW, v)) return DBC_CLASS.ALLOW
  return DBC_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  DBC_CLASS: DBC_CLASS,
  DBC_BLOCK: DBC_BLOCK,
  DBC_WARN: DBC_WARN,
  DBC_ALLOW: DBC_ALLOW,
  DBCClassify: DBCClassify
})
