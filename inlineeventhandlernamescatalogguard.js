'use strict'

// inlineeventhandlernamescatalogguard.js —— 内联事件处理器名目录。
//
// 威胁模型：
//   把不可信字符串赋给 on* 属性等于内联执行，
//   应使用 addEventListener 传函数并配 CSP 禁内联。纯字符查表，不用正则。

const IEH_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const IEH_BLOCK = Object.freeze([
  'onclick',
  'onload',
  'onerror',
  'onmouseover',
  'onfocus',
  'onmessage',
  'onanimationstart',
])

const IEH_WARN = Object.freeze([
  'addeventlistener-string',
])

const IEH_ALLOW = Object.freeze([
  'addeventlistener-fn',
])

function IEHLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function IEHIn (list, v) {
  for (const x of list) { if (IEHLower(x) === v) return true }
  return false
}

function IEHClassify (tok) {
  const v = IEHLower(String(tok == null ? '' : tok).trim())
  if (IEHIn(IEH_BLOCK, v)) return IEH_CLASS.BLOCK
  if (IEHIn(IEH_WARN, v)) return IEH_CLASS.WARN
  if (IEHIn(IEH_ALLOW, v)) return IEH_CLASS.ALLOW
  return IEH_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  IEH_CLASS: IEH_CLASS,
  IEH_BLOCK: IEH_BLOCK,
  IEH_WARN: IEH_WARN,
  IEH_ALLOW: IEH_ALLOW,
  IEHClassify: IEHClassify
})
