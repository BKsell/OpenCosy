'use strict'

// eventhandlercatalogguard.js —— 内联事件处理器属性目录。
//
// 威胁模型：
//   HTML 内联 on* 处理器在 CSP unsafe-inline 下直接执行脚本，应改 addEventListener。本模块按属性名分级，
//   纯字符，不用正则。

const EHC_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const EHC_BLOCK = Object.freeze([
  'onerror',
  'onload',
  'onclick-uri',
  'onmouseover-uri',
  'onfocus-uri',
  'onsubmit-uri',
  'onanimationstart-uri',
  'ontransitionend-uri',
  'onmessage-uri',
])

const EHC_WARN = Object.freeze([
  'onclick',
  'onmousedown',
  'onmouseup',
  'onkeydown',
  'onkeyup',
  'onchange',
  'onsubmit',
  'onfocus',
  'onblur',
  'oninput',
  'ontoggle',
  'oncopy',
  'onpaste',
  'onbeforeunload',
  'onmessage',
])

const EHC_ALLOW = Object.freeze([
  'addEventListener:click',
  'addEventListener:error',
  'addEventListener:load',
])

function EHCLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function EHCIn (list, v) {
  for (const x of list) { if (EHCLower(x) === v) return true }
  return false
}

function EHCClassify (tok) {
  const v = EHCLower(String(tok == null ? '' : tok).trim())
  if (EHCIn(EHC_BLOCK, v)) return EHC_CLASS.BLOCK
  if (EHCIn(EHC_WARN, v)) return EHC_CLASS.WARN
  if (EHCIn(EHC_ALLOW, v)) return EHC_CLASS.ALLOW
  return EHC_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  EHC_CLASS: EHC_CLASS,
  EHC_BLOCK: EHC_BLOCK,
  EHC_WARN: EHC_WARN,
  EHC_ALLOW: EHC_ALLOW,
  EHCClassify: EHCClassify
})
