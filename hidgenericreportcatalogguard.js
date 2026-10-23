'use strict'

// hidgenericreportcatalogguard.js —— HID 通用报告目录。
//
// 威胁模型：
//   requestDevice 接收通用 HID（键盘/扫码枪）并 sendReport 可注入按键/凭据，
//   应限具体 usagePage。纯字符查表，不用正则。

const HDR_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const HDR_BLOCK = Object.freeze([
  'generic-hid',
  'sendreport',
  'feature-report',
  'keystroke-injection',
])

const HDR_WARN = Object.freeze([
  'inputreport-listen',
])

const HDR_ALLOW = Object.freeze([
  'usagepage-allowlist',
])

function HDRLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function HDRIn (list, v) {
  for (const x of list) { if (HDRLower(x) === v) return true }
  return false
}

function HDRClassify (tok) {
  const v = HDRLower(String(tok == null ? '' : tok).trim())
  if (HDRIn(HDR_BLOCK, v)) return HDR_CLASS.BLOCK
  if (HDRIn(HDR_WARN, v)) return HDR_CLASS.WARN
  if (HDRIn(HDR_ALLOW, v)) return HDR_CLASS.ALLOW
  return HDR_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  HDR_CLASS: HDR_CLASS,
  HDR_BLOCK: HDR_BLOCK,
  HDR_WARN: HDR_WARN,
  HDR_ALLOW: HDR_ALLOW,
  HDRClassify: HDRClassify
})
