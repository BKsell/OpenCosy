'use strict'

// basehrefinjectioncatalogguard.js —— base 标签注入目录。
//
// 威胁模型：
//   注入 <base href> 会重写页面所有相对 URL/表单目标到攻击者站点，
//   应固定 base 或不信任其输入。纯字符查表，不用正则。

const BSH_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const BSH_BLOCK = Object.freeze([
  '<base href-input',
  'base-href-untrusted',
  'document.baseuri-override',
])

const BSH_WARN = Object.freeze([
  'base-relative',
])

const BSH_ALLOW = Object.freeze([
  'base-fixed',
])

function BSHLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function BSHIn (list, v) {
  for (const x of list) { if (BSHLower(x) === v) return true }
  return false
}

function BSHClassify (tok) {
  const v = BSHLower(String(tok == null ? '' : tok).trim())
  if (BSHIn(BSH_BLOCK, v)) return BSH_CLASS.BLOCK
  if (BSHIn(BSH_WARN, v)) return BSH_CLASS.WARN
  if (BSHIn(BSH_ALLOW, v)) return BSH_CLASS.ALLOW
  return BSH_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  BSH_CLASS: BSH_CLASS,
  BSH_BLOCK: BSH_BLOCK,
  BSH_WARN: BSH_WARN,
  BSH_ALLOW: BSH_ALLOW,
  BSHClassify: BSHClassify
})
