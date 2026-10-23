'use strict'

// setattributereflectcatalogguard.js —— setAttribute 危险属性目录。
//
// 威胁模型：
//   setAttribute 设置 href/src/action/formaction/srcdoc 或 on* 处理器可反射 XSS，
//   应改设 dataset/textContent。纯字符查表，不用正则。

const SAS_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const SAS_BLOCK = Object.freeze([
  'href',
  'src',
  'action',
  'formaction',
  'srcdoc',
  'onclick',
  'onerror',
  'onload',
])

const SAS_WARN = Object.freeze([
  'style',
  'poster',
  'background',
])

const SAS_ALLOW = Object.freeze([
  'dataset',
  'class',
  'aria-label',
])

function SASLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function SASIn (list, v) {
  for (const x of list) { if (SASLower(x) === v) return true }
  return false
}

function SASClassify (tok) {
  const v = SASLower(String(tok == null ? '' : tok).trim())
  if (SASIn(SAS_BLOCK, v)) return SAS_CLASS.BLOCK
  if (SASIn(SAS_WARN, v)) return SAS_CLASS.WARN
  if (SASIn(SAS_ALLOW, v)) return SAS_CLASS.ALLOW
  return SAS_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  SAS_CLASS: SAS_CLASS,
  SAS_BLOCK: SAS_BLOCK,
  SAS_WARN: SAS_WARN,
  SAS_ALLOW: SAS_ALLOW,
  SASClassify: SASClassify
})
