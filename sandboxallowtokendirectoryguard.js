'use strict'

// sandboxallowtokendirectoryguard.js —— iframe sandbox allow 令牌目录。
//
// 威胁模型：
//   sandbox 的 allow-scripts/allow-same-origin 组合、allow-top-navigation/allow-popups-to-escape 等提升风险，
//   空 sandbox 最安全。纯字符查表，不用正则。

const SAT_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const SAT_BLOCK = Object.freeze([
  'allow-scripts',
  'allow-same-origin',
  'allow-top-navigation',
  'allow-top-navigation-by-user-activation',
  'allow-popups-to-escape-sandbox',
  'allow-downloads-without-user-activation',
  'allow-pointer-lock',
])

const SAT_WARN = Object.freeze([
  'allow-popups',
  'allow-forms',
  'allow-modals',
  'allow-orientation-lock',
  'allow-presentation',
  'allow-downloads',
  'allow-storage-access-by-user-activation',
  'allow-clipboard-write',
  'allow-clipboard-read',
])

const SAT_ALLOW = Object.freeze([
  'sandbox',
  'empty-sandbox',
  'csp',
  'referrerpolicy',
  'srcdoc',
])

function SATLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function SATIn (list, v) {
  for (const x of list) { if (SATLower(x) === v) return true }
  return false
}

function SATClassify (tok) {
  const v = SATLower(String(tok == null ? '' : tok).trim())
  if (SATIn(SAT_BLOCK, v)) return SAT_CLASS.BLOCK
  if (SATIn(SAT_WARN, v)) return SAT_CLASS.WARN
  if (SATIn(SAT_ALLOW, v)) return SAT_CLASS.ALLOW
  return SAT_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  SAT_CLASS: SAT_CLASS,
  SAT_BLOCK: SAT_BLOCK,
  SAT_WARN: SAT_WARN,
  SAT_ALLOW: SAT_ALLOW,
  SATClassify: SATClassify
})
