'use strict'

// speakercaptchadomcatalogguard.js —— 可注入 DOM 元素属性面目录。
//
// 威胁模型：
//   富文本/Markdown 渲染中 srcdoc/data/href/on* 与 formaction/xlink:href 等属性面需白名单。纯字符查表，不用正则。

const SCD_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const SCD_BLOCK = Object.freeze([
  'onclick',
  'onload',
  'onerror',
  'onmouseover',
  'onfocus',
  'onblur',
  'onsubmit',
  'onkeydown',
  'onkeyup',
  'onkeypress',
  'onchange',
  'oninput',
  'onanimationstart',
  'onanimationend',
  'ontransitionend',
  'onbeforetoggle',
  'ontoggle',
  'onpointerdown',
  'onpointerover',
  'onbeforeinput',
  'onbeforeprint',
  'onafterprint',
  'onmessage',
  'onbeforeunload',
  'onunload',
  'srcdoc',
  'data',
  'formaction',
  'xlink:href',
  'xmlns:xlink',
  'href',
  'src',
  'action',
  'background',
  'poster',
  'code',
  'codebase',
  'classid',
  'manifest',
  'archive',
  'longdesc',
  'usemap',
  'lowsrc',
  'dynsrc',
  'ping',
  'csp',
  'integrity',
  'nonce',
])

const SCD_WARN = Object.freeze([
  'style',
  'class',
  'id',
  'name',
  'rel',
  'target',
  'download',
  'crossorigin',
  'referrerpolicy',
  'loading',
  'decoding',
  'fetchpriority',
  'content',
  'http-equiv',
  'charset',
  'sandbox',
  'allow',
  'allowfullscreen',
  'allowpaymentrequest',
  'is',
  'slot',
  'part',
  'exportparts',
  'contenteditable',
  'draggable',
  'spellcheck',
  'autofocus',
  'tabindex',
  'accesskey',
  'autocapitalize',
  'autocorrect',
  'enterkeyhint',
  'inputmode',
  'wrap',
  'dirname',
])

const SCD_ALLOW = Object.freeze([
  'role',
  'aria-label',
  'aria-hidden',
  'aria-describedby',
  'title',
  'alt',
  'lang',
  'translate',
  'hidden',
  'dir',
  'data-id',
  'data-index',
  'width',
  'height',
  'cols',
  'rows',
  'colspan',
  'rowspan',
  'nowrap',
  'disabled',
  'readonly',
  'required',
  'multiple',
  'checked',
  'selected',
  'open',
  'reversed',
  'start',
  'value',
  'min',
  'max',
  'step',
  'placeholder',
  'pattern',
  'accept',
  'capture',
  'for',
  'label',
  'optgroup',
  'fieldset',
  'legend',
  'datalist',
  'output',
  'progress',
  'meter',
  'details',
  'summary',
  'dialog',
  'canvas',
  'svg',
  'math',
])

function SCDLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function SCDIn (list, v) {
  for (const x of list) { if (SCDLower(x) === v) return true }
  return false
}

function SCDClassify (tok) {
  const v = SCDLower(String(tok == null ? '' : tok).trim())
  if (SCDIn(SCD_BLOCK, v)) return SCD_CLASS.BLOCK
  if (SCDIn(SCD_WARN, v)) return SCD_CLASS.WARN
  if (SCDIn(SCD_ALLOW, v)) return SCD_CLASS.ALLOW
  return SCD_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  SCD_CLASS: SCD_CLASS,
  SCD_BLOCK: SCD_BLOCK,
  SCD_WARN: SCD_WARN,
  SCD_ALLOW: SCD_ALLOW,
  SCDClassify: SCDClassify
})
