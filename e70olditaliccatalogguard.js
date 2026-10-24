'use strict'

// e70olditaliccatalogguard.js —— 古意大利文字平面目录。
//
// 威胁模型：
//   古意大利字母与拉丁大写近似且罕用，可做视觉仿冒，
//   标识符使用应拒绝。纯字符查表，不用正则。

const E70U02_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70U02_BLOCK = Object.freeze([
  'U+10300',
  'U+10301',
  'U+10302',
  'U+10303',
  'U+10304',
  'U+10305',
  'U+10306',
  'U+10307',
  'U+10308',
  'U+10309',
  'U+1030A',
  'U+1030B',
  'U+1030C',
  'U+1030D',
  'U+1030E',
  'U+1030F',
  'U+10310',
  'U+10311',
  'U+10312',
  'U+10313',
  'U+10314',
  'U+10315',
  'U+10316',
  'U+10317',
  'U+10318',
  'U+10319',
  'U+1031A',
  'U+1031B',
  'U+1031C',
  'U+1031D',
  'U+1031E',
  'U+1031F',
  'U+10320',
  'U+10321',
  'U+10322',
  'U+10323',
  'U+10324',
  'U+10325',
  'U+10326',
  'U+10327',
  'U+10328',
  'U+10329',
  'U+1032A',
  'U+1032B',
  'U+1032C',
  'U+1032D',
  'U+1032E',
  'U+1032F',
])

const E70U02_WARN = Object.freeze([
])

const E70U02_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70U02Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70U02In (list, v) {
  for (const x of list) { if (E70U02Lower(x) === v) return true }
  return false
}

function E70U02Classify (tok) {
  const v = E70U02Lower(String(tok == null ? '' : tok))
  if (E70U02In(E70U02_BLOCK, v)) return E70U02_CLASS.BLOCK
  if (E70U02In(E70U02_WARN, v)) return E70U02_CLASS.WARN
  if (E70U02In(E70U02_ALLOW, v)) return E70U02_CLASS.ALLOW
  return E70U02_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70U02_CLASS: E70U02_CLASS,
  E70U02_BLOCK: E70U02_BLOCK,
  E70U02_WARN: E70U02_WARN,
  E70U02_ALLOW: E70U02_ALLOW,
  E70U02Classify: E70U02Classify
})
