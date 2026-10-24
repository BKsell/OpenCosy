'use strict'

// e70numberformscatalogguard.js —— 数字形式码位目录。
//
// 威胁模型：
//   ½ ⅓ Ⅷ 等数字形式与普通数字串长度/形态不同，规范化后变化，可绕过数值匹配，
//   应 NFKC 归一化。纯字符查表，不用正则。

const E70T39_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T39_BLOCK = Object.freeze([
])

const E70T39_WARN = Object.freeze([
  'U+2150',
  'U+2151',
  'U+2152',
  'U+2153',
  'U+2154',
  'U+2155',
  'U+2156',
  'U+2157',
  'U+2158',
  'U+2159',
  'U+215A',
  'U+215B',
  'U+215C',
  'U+215D',
  'U+215E',
  'U+215F',
  'U+2160',
  'U+2161',
  'U+2162',
  'U+2163',
  'U+2164',
  'U+2165',
  'U+2166',
  'U+2167',
  'U+2168',
  'U+2169',
  'U+216A',
  'U+216B',
  'U+216C',
  'U+216D',
  'U+216E',
  'U+216F',
  'U+2170',
  'U+2171',
  'U+2172',
  'U+2173',
  'U+2174',
  'U+2175',
  'U+2176',
  'U+2177',
  'U+2178',
  'U+2179',
  'U+217A',
  'U+217B',
  'U+217C',
  'U+217D',
  'U+217E',
  'U+217F',
  'U+2180',
  'U+2181',
  'U+2182',
  'U+2183',
  'U+2184',
  'U+2185',
  'U+2186',
  'U+2187',
  'U+2188',
  'U+2189',
  'U+218A',
  'U+218B',
  'U+218C',
  'U+218D',
  'U+218E',
  'U+218F',
])

const E70T39_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T39Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T39In (list, v) {
  for (const x of list) { if (E70T39Lower(x) === v) return true }
  return false
}

function E70T39Classify (tok) {
  const v = E70T39Lower(String(tok == null ? '' : tok))
  if (E70T39In(E70T39_BLOCK, v)) return E70T39_CLASS.BLOCK
  if (E70T39In(E70T39_WARN, v)) return E70T39_CLASS.WARN
  if (E70T39In(E70T39_ALLOW, v)) return E70T39_CLASS.ALLOW
  return E70T39_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T39_CLASS: E70T39_CLASS,
  E70T39_BLOCK: E70T39_BLOCK,
  E70T39_WARN: E70T39_WARN,
  E70T39_ALLOW: E70T39_ALLOW,
  E70T39Classify: E70T39Classify
})
