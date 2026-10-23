'use strict'

// isolationheadervaluedirectoryguard.js —— 跨域隔离头取值目录。
//
// 威胁模型：
//   COOP same-origin/allow-popups、CORP same-origin/cross-origin、COEP require-corp/credentialless 取值强度分级。
//   纯字符查表，不用正则。

const IHV_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const IHV_BLOCK = Object.freeze([
  'unsafe-none',
  'cross-origin',
])

const IHV_WARN = Object.freeze([
  'same-origin-allow-popups',
  'same-origin-allow-popups-to-escape',
  'allow-popups',
  'allow-popups-to-escape-sandbox',
  'cross-origin-allow-popups',
])

const IHV_ALLOW = Object.freeze([
  'same-origin',
  'same-origin-isolated',
  'require-corp',
  'credentialless',
  'unsafe-none-coop',
  'noopener',
  'opener',
  'embedder',
  'resource-policy',
  'coop',
  'coep',
  'corp',
  'isolation',
  'isolated',
  'agent-cluster',
])

function IHVLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function IHVIn (list, v) {
  for (const x of list) { if (IHVLower(x) === v) return true }
  return false
}

function IHVClassify (tok) {
  const v = IHVLower(String(tok == null ? '' : tok).trim())
  if (IHVIn(IHV_BLOCK, v)) return IHV_CLASS.BLOCK
  if (IHVIn(IHV_WARN, v)) return IHV_CLASS.WARN
  if (IHVIn(IHV_ALLOW, v)) return IHV_CLASS.ALLOW
  return IHV_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  IHV_CLASS: IHV_CLASS,
  IHV_BLOCK: IHV_BLOCK,
  IHV_WARN: IHV_WARN,
  IHV_ALLOW: IHV_ALLOW,
  IHVClassify: IHVClassify
})
