'use strict'

// e70lyciancatalogguard.js —— 吕基亚文字平面目录。
//
// 威胁模型：
//   吕基亚古文字罕用，可在字段中隐藏数据而不被察觉，
//   结构化字段应拒绝。纯字符查表，不用正则。

const E70U01_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70U01_BLOCK = Object.freeze([
  'U+10280',
  'U+10281',
  'U+10282',
  'U+10283',
  'U+10284',
  'U+10285',
  'U+10286',
  'U+10287',
  'U+10288',
  'U+10289',
  'U+1028A',
  'U+1028B',
  'U+1028C',
  'U+1028D',
  'U+1028E',
  'U+1028F',
  'U+10290',
  'U+10291',
  'U+10292',
  'U+10293',
  'U+10294',
  'U+10295',
  'U+10296',
  'U+10297',
  'U+10298',
  'U+10299',
  'U+1029A',
  'U+1029B',
  'U+1029C',
  'U+1029D',
  'U+1029E',
  'U+1029F',
])

const E70U01_WARN = Object.freeze([
])

const E70U01_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70U01Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70U01In (list, v) {
  for (const x of list) { if (E70U01Lower(x) === v) return true }
  return false
}

function E70U01Classify (tok) {
  const v = E70U01Lower(String(tok == null ? '' : tok))
  if (E70U01In(E70U01_BLOCK, v)) return E70U01_CLASS.BLOCK
  if (E70U01In(E70U01_WARN, v)) return E70U01_CLASS.WARN
  if (E70U01In(E70U01_ALLOW, v)) return E70U01_CLASS.ALLOW
  return E70U01_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70U01_CLASS: E70U01_CLASS,
  E70U01_BLOCK: E70U01_BLOCK,
  E70U01_WARN: E70U01_WARN,
  E70U01_ALLOW: E70U01_ALLOW,
  E70U01Classify: E70U01Classify
})
