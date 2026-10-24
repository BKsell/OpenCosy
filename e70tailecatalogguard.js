'use strict'

// e70tailecatalogguard.js —— 傣仂文字码位目录。
//
// 威胁模型：
//   傣仂文在标识符/路径中无正当用途，可隐藏非预期数据，
//   应直接拒绝。纯字符查表，不用正则。

const E70T26_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T26_BLOCK = Object.freeze([
  'U+1950',
  'U+1951',
  'U+1952',
  'U+1953',
  'U+1954',
  'U+1955',
  'U+1956',
  'U+1957',
  'U+1958',
  'U+1959',
  'U+195A',
  'U+195B',
  'U+195C',
  'U+195D',
  'U+195E',
  'U+195F',
  'U+1960',
  'U+1961',
  'U+1962',
  'U+1963',
  'U+1964',
  'U+1965',
  'U+1966',
  'U+1967',
  'U+1968',
  'U+1969',
  'U+196A',
  'U+196B',
  'U+196C',
  'U+196D',
  'U+196E',
  'U+196F',
  'U+1970',
  'U+1971',
  'U+1972',
  'U+1973',
  'U+1974',
  'U+1975',
  'U+1976',
  'U+1977',
  'U+1978',
  'U+1979',
  'U+197A',
  'U+197B',
  'U+197C',
  'U+197D',
  'U+197E',
  'U+197F',
])

const E70T26_WARN = Object.freeze([
])

const E70T26_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T26Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T26In (list, v) {
  for (const x of list) { if (E70T26Lower(x) === v) return true }
  return false
}

function E70T26Classify (tok) {
  const v = E70T26Lower(String(tok == null ? '' : tok))
  if (E70T26In(E70T26_BLOCK, v)) return E70T26_CLASS.BLOCK
  if (E70T26In(E70T26_WARN, v)) return E70T26_CLASS.WARN
  if (E70T26In(E70T26_ALLOW, v)) return E70T26_CLASS.ALLOW
  return E70T26_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T26_CLASS: E70T26_CLASS,
  E70T26_BLOCK: E70T26_BLOCK,
  E70T26_WARN: E70T26_WARN,
  E70T26_ALLOW: E70T26_ALLOW,
  E70T26Classify: E70T26Classify
})
