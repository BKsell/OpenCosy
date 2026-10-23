'use strict'

// innerhtmlsinkcatalogguard.js —— HTML 注入 DOM Sink 目录。
//
// 威胁模型：
//   innerHTML/outerHTML/document.write/insertAdjacentHTML 写入不可信字符串即 XSS，
//   应改用 textContent 或经净化。纯字符查表，不用正则。

const IHS_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const IHS_BLOCK = Object.freeze([
  'innerhtml',
  'outerhtml',
  'document.write',
  'document.writeln',
  'insertadjacenthtml',
])

const IHS_WARN = Object.freeze([
  'srcdoc',
])

const IHS_ALLOW = Object.freeze([
  'textcontent',
  'innertext',
])

function IHSLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function IHSIn (list, v) {
  for (const x of list) { if (IHSLower(x) === v) return true }
  return false
}

function IHSClassify (tok) {
  const v = IHSLower(String(tok == null ? '' : tok).trim())
  if (IHSIn(IHS_BLOCK, v)) return IHS_CLASS.BLOCK
  if (IHSIn(IHS_WARN, v)) return IHS_CLASS.WARN
  if (IHSIn(IHS_ALLOW, v)) return IHS_CLASS.ALLOW
  return IHS_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  IHS_CLASS: IHS_CLASS,
  IHS_BLOCK: IHS_BLOCK,
  IHS_WARN: IHS_WARN,
  IHS_ALLOW: IHS_ALLOW,
  IHSClassify: IHSClassify
})
