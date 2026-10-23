'use strict'

// openerisolationcatalogguard.js —— 窗口 opener/导航隔离取值目录。
//
// 威胁模型：
//   noopener/noreferrer/COOP same-origin 切断 window.opener，缺失允许反向 tabnabbing。纯字符查表，不用正则。

const OPI_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const OPI_BLOCK = Object.freeze([
  'opener',
  'window.opener',
  '_blank',
  'no-referrer',
  'unsafe-url',
])

const OPI_WARN = Object.freeze([
  '_self',
  '_parent',
  '_top',
  'window.open',
  'navigate',
  'target',
  'back',
  'forward',
  'history',
  'referrer',
  'origin',
  'origin-when-cross-origin',
  'strict-origin',
])

const OPI_ALLOW = Object.freeze([
  'noopener',
  'noreferrer',
  'noopener-noreferrer',
  'same-origin',
  'same-origin-allow-popups',
  'no-referrer-when-downgrade',
  'strict-origin-when-cross-origin',
])

function OPILower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function OPIIn (list, v) {
  for (const x of list) { if (OPILower(x) === v) return true }
  return false
}

function OPIClassify (tok) {
  const v = OPILower(String(tok == null ? '' : tok).trim())
  if (OPIIn(OPI_BLOCK, v)) return OPI_CLASS.BLOCK
  if (OPIIn(OPI_WARN, v)) return OPI_CLASS.WARN
  if (OPIIn(OPI_ALLOW, v)) return OPI_CLASS.ALLOW
  return OPI_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  OPI_CLASS: OPI_CLASS,
  OPI_BLOCK: OPI_BLOCK,
  OPI_WARN: OPI_WARN,
  OPI_ALLOW: OPI_ALLOW,
  OPIClassify: OPIClassify
})
