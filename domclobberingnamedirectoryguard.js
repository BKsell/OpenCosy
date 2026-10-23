'use strict'

// domclobberingnamedirectoryguard.js —— DOM Clobbering 属性名目录。
//
// 威胁模型：
//   id/name 可覆盖 window/forms 等具名属性（src/href/value/children 等），配合 HTML 注入改写脚本读取的配置。
//   纯字符查表，不用正则。

const DCN_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const DCN_BLOCK = Object.freeze([
  'src',
  'href',
  'data',
  'value',
  'action',
  'formAction',
  'formaction',
  'srcdoc',
  'codebase',
  'object',
  'embed',
  'form',
])

const DCN_WARN = Object.freeze([
  'name',
  'id',
  'children',
  'childElementCount',
  'firstElementChild',
  'lastElementChild',
  'nextElementSibling',
  'previousElementSibling',
  'parentElement',
  'innerHTML',
  'outerHTML',
  'innerText',
  'textContent',
  'dataset',
  'classList',
  'className',
  'attributes',
  'shadowRoot',
  'contentDocument',
  'contentWindow',
  'window',
  'document',
  'forms',
  'images',
  'links',
  'anchors',
  'scripts',
  'stylesheets',
  'applets',
  'embeds',
  'plugins',
  'frames',
  'elements',
  'length',
  'item',
  'namedItem',
])

const DCN_ALLOW = Object.freeze([
  'tag',
  'tagName',
  'localName',
  'namespaceURI',
  'nodeType',
  'nodeName',
  'getElementById',
  'querySelector',
  'getElementsByName',
  'closest',
  'matches',
  'nonce',
])

function DCNLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function DCNIn (list, v) {
  for (const x of list) { if (DCNLower(x) === v) return true }
  return false
}

function DCNClassify (tok) {
  const v = DCNLower(String(tok == null ? '' : tok).trim())
  if (DCNIn(DCN_BLOCK, v)) return DCN_CLASS.BLOCK
  if (DCNIn(DCN_WARN, v)) return DCN_CLASS.WARN
  if (DCNIn(DCN_ALLOW, v)) return DCN_CLASS.ALLOW
  return DCN_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  DCN_CLASS: DCN_CLASS,
  DCN_BLOCK: DCN_BLOCK,
  DCN_WARN: DCN_WARN,
  DCN_ALLOW: DCN_ALLOW,
  DCNClassify: DCNClassify
})
