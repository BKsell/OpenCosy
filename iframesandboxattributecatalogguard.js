'use strict'

// iframesandboxattributecatalogguard.js —— iframe sandbox 标志目录。
//
// 威胁模型：
//   allow-popups-to-escape-sandbox 直接突破沙箱，allow-top-navigation/downloads/modals 等放宽隔离需复核，基础安全标志放行。纯字符查表，不用正则。

const IFA_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const IFA_BLOCK = Object.freeze([
  'allow-popups-to-escape-sandbox',
])

const IFA_WARN = Object.freeze([
  'allow-top-navigation',
  'allow-top-navigation-to-custom-protocols',
  'allow-downloads',
  'allow-modals',
  'allow-pointer-lock',
  'allow-orientation-lock',
  'allow-presentation',
  'allow-storage-access-by-user-activation',
])

const IFA_ALLOW = Object.freeze([
  'allow-scripts',
  'allow-same-origin',
  'allow-forms',
  'allow-popups',
  'allow-top-navigation-by-user-activation',
  'allow-clipboard',
])

function IFALower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function IFAIn (list, v) {
  for (const x of list) { if (IFALower(x) === v) return true }
  return false
}

function IFAClassify (tok) {
  const v = IFALower(String(tok == null ? '' : tok).trim())
  if (IFAIn(IFA_BLOCK, v)) return IFA_CLASS.BLOCK
  if (IFAIn(IFA_WARN, v)) return IFA_CLASS.WARN
  if (IFAIn(IFA_ALLOW, v)) return IFA_CLASS.ALLOW
  return IFA_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  IFA_CLASS: IFA_CLASS,
  IFA_BLOCK: IFA_BLOCK,
  IFA_WARN: IFA_WARN,
  IFA_ALLOW: IFA_ALLOW,
  IFAClassify: IFAClassify
})
