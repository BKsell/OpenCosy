'use strict'

// domnodeapidirectoryguard.js —— DOM 节点方法/属性风险分级目录。
//
// 威胁模型：
//   appendChild/setAttribute 中性，但 insertAdjacentHTML/innerHTML/document.write/navigation 类方法可注入或跳转，
//   只读/结构方法低风险。纯字符查表，不用正则。

const DNA_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const DNA_BLOCK = Object.freeze([
  'innerHTML',
  'outerHTML',
  'insertAdjacentHTML',
  'eval',
  'setExpression',
  'getExpression',
  'recalc',
  'createContextualFragment',
  'execCommand',
  'insertAdjacentText',
  'outerText',
  'setHTMLUnsafe',
  'parseHTMLUnsafe',
])

const DNA_WARN = Object.freeze([
  'setAttribute',
  'setAttributeNS',
  'setAttributeNode',
  'setAttributeNodeNS',
  'createAttribute',
  'createAttributeNS',
  'removeAttribute',
  'removeAttributeNode',
  'href',
  'src',
  'action',
  'formAction',
  'location',
  'assign',
  'replace',
  'reload',
  'showModal',
  'show',
  'showPopover',
  'requestFullscreen',
  'requestPointerLock',
  'append',
  'prepend',
  'before',
  'after',
  'replaceWith',
  'replaceChildren',
  'insertBefore',
  'appendChild',
  'insertAdjacentElement',
  'addEventListener',
  'removeEventListener',
  'dispatchEvent',
  'click',
  'focus',
  'blur',
  'scrollIntoView',
  'scrollTo',
  'scrollBy',
  'submit',
  'reset',
  'select',
  'showPicker',
  'checkValidity',
  'reportValidity',
  'setRangeText',
  'setSelectionRange',
  'setCustomValidity',
  'open',
  'close',
  'postMessage',
  'drawImage',
  'fetch',
  'sendBeacon',
  'importNode',
  'adoptNode',
])

const DNA_ALLOW = Object.freeze([
  'getAttribute',
  'getAttributeNS',
  'getAttributeNode',
  'getAttributeNames',
  'hasAttribute',
  'hasAttributes',
  'getElementsByTagName',
  'getElementsByTagNameNS',
  'getElementsByClassName',
  'getElementById',
  'querySelector',
  'querySelectorAll',
  'closest',
  'matches',
  'cloneNode',
  'contains',
  'hasChildNodes',
  'isEqualNode',
  'isSameNode',
  'compareDocumentPosition',
  'getBoundingClientRect',
  'getClientRects',
  'removeChild',
  'replaceChild',
  'firstChild',
  'lastChild',
  'childNodes',
  'children',
  'parentNode',
  'parentElement',
  'nextSibling',
  'previousSibling',
  'nextElementSibling',
  'previousElementSibling',
  'firstElementChild',
  'lastElementChild',
  'nodeName',
  'nodeType',
  'nodeValue',
  'textContent',
  'localName',
  'namespaceURI',
  'prefix',
  'ownerDocument',
  'classList',
  'className',
  'id',
  'dataset',
  'attributes',
  'childElementCount',
  'getRootNode',
  'isConnected',
  'normalize',
  'lookupPrefix',
  'lookupNamespaceURI',
  'isDefaultNamespace',
  'getComputedTextLength',
  'getBBox',
  'getCTM',
  'getScreenCTM',
  'getTotalLength',
  'hasPointerCapture',
  'releasePointerCapture',
  'checkVisibility',
  'scrollWidth',
  'scrollHeight',
  'clientWidth',
  'clientHeight',
  'offsetWidth',
  'offsetHeight',
  'offsetTop',
  'offsetLeft',
  'offsetParent',
])

function DNALower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function DNAIn (list, v) {
  for (const x of list) { if (DNALower(x) === v) return true }
  return false
}

function DNAClassify (tok) {
  const v = DNALower(String(tok == null ? '' : tok).trim())
  if (DNAIn(DNA_BLOCK, v)) return DNA_CLASS.BLOCK
  if (DNAIn(DNA_WARN, v)) return DNA_CLASS.WARN
  if (DNAIn(DNA_ALLOW, v)) return DNA_CLASS.ALLOW
  return DNA_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  DNA_CLASS: DNA_CLASS,
  DNA_BLOCK: DNA_BLOCK,
  DNA_WARN: DNA_WARN,
  DNA_ALLOW: DNA_ALLOW,
  DNAClassify: DNAClassify
})
