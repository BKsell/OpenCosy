'use strict'

// blobobjecturlriskcatalogguard.js —— Blob/Object URL 风险目录。
//
// 威胁模型：
//   为含 HTML 的 blob/createObjectURL 并导航、使用后不 revoke 会长期可访问，
//   应限定用途并及时释放。纯字符查表，不用正则。

const BLU_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const BLU_BLOCK = Object.freeze([
  'blob-html',
  'objecturl-navigation',
  'no-revoke',
  'createobjecturl-script',
])

const BLU_WARN = Object.freeze([
  'objecturl-media',
])

const BLU_ALLOW = Object.freeze([
  'revoked-after-use',
])

function BLULower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function BLUIn (list, v) {
  for (const x of list) { if (BLULower(x) === v) return true }
  return false
}

function BLUClassify (tok) {
  const v = BLULower(String(tok == null ? '' : tok).trim())
  if (BLUIn(BLU_BLOCK, v)) return BLU_CLASS.BLOCK
  if (BLUIn(BLU_WARN, v)) return BLU_CLASS.WARN
  if (BLUIn(BLU_ALLOW, v)) return BLU_CLASS.ALLOW
  return BLU_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  BLU_CLASS: BLU_CLASS,
  BLU_BLOCK: BLU_BLOCK,
  BLU_WARN: BLU_WARN,
  BLU_ALLOW: BLU_ALLOW,
  BLUClassify: BLUClassify
})
