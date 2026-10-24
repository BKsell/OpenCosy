'use strict'

// e70deseretcatalogguard.js —— 德塞雷特字母平面目录。
//
// 威胁模型：
//   德塞雷特字母为近代人造文字，与拉丁一一对应但码点不同，可做同形替换，
//   标识符使用应拒绝。纯字符查表，不用正则。

const E70U05_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70U05_BLOCK = Object.freeze([
  'U+10400',
  'U+10401',
  'U+10402',
  'U+10403',
  'U+10404',
  'U+10405',
  'U+10406',
  'U+10407',
  'U+10408',
  'U+10409',
  'U+1040A',
  'U+1040B',
  'U+1040C',
  'U+1040D',
  'U+1040E',
  'U+1040F',
  'U+10410',
  'U+10411',
  'U+10412',
  'U+10413',
  'U+10414',
  'U+10415',
  'U+10416',
  'U+10417',
  'U+10418',
  'U+10419',
  'U+1041A',
  'U+1041B',
  'U+1041C',
  'U+1041D',
  'U+1041E',
  'U+1041F',
  'U+10420',
  'U+10421',
  'U+10422',
  'U+10423',
  'U+10424',
  'U+10425',
  'U+10426',
  'U+10427',
  'U+10428',
  'U+10429',
  'U+1042A',
  'U+1042B',
  'U+1042C',
  'U+1042D',
  'U+1042E',
  'U+1042F',
  'U+10430',
  'U+10431',
  'U+10432',
  'U+10433',
  'U+10434',
  'U+10435',
  'U+10436',
  'U+10437',
  'U+10438',
  'U+10439',
  'U+1043A',
  'U+1043B',
  'U+1043C',
  'U+1043D',
  'U+1043E',
  'U+1043F',
  'U+10440',
  'U+10441',
  'U+10442',
  'U+10443',
  'U+10444',
  'U+10445',
  'U+10446',
  'U+10447',
  'U+10448',
  'U+10449',
  'U+1044A',
  'U+1044B',
  'U+1044C',
  'U+1044D',
  'U+1044E',
  'U+1044F',
])

const E70U05_WARN = Object.freeze([
])

const E70U05_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70U05Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70U05In (list, v) {
  for (const x of list) { if (E70U05Lower(x) === v) return true }
  return false
}

function E70U05Classify (tok) {
  const v = E70U05Lower(String(tok == null ? '' : tok))
  if (E70U05In(E70U05_BLOCK, v)) return E70U05_CLASS.BLOCK
  if (E70U05In(E70U05_WARN, v)) return E70U05_CLASS.WARN
  if (E70U05In(E70U05_ALLOW, v)) return E70U05_CLASS.ALLOW
  return E70U05_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70U05_CLASS: E70U05_CLASS,
  E70U05_BLOCK: E70U05_BLOCK,
  E70U05_WARN: E70U05_WARN,
  E70U05_ALLOW: E70U05_ALLOW,
  E70U05Classify: E70U05Classify
})
