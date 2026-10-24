'use strict'

// e69cjksymbolspunctcatalogguard.js —— CJK 符号与标点码位目录。
//
// 威胁模型：
//   全角空格 U+3000、全角斜杠 U+FF0F 邻近区域的全角标点可仿冒路径分隔与空白，
//   应 NFKC 归一化。纯字符查表，不用正则。

const E69T24_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T24_BLOCK = Object.freeze([
])

const E69T24_WARN = Object.freeze([
  'U+3000',
  'U+3001',
  'U+3002',
  'U+3003',
  'U+3004',
  'U+3005',
  'U+3006',
  'U+3007',
  'U+3008',
  'U+3009',
  'U+300A',
  'U+300B',
  'U+300C',
  'U+300D',
  'U+300E',
  'U+300F',
  'U+3010',
  'U+3011',
  'U+3012',
  'U+3013',
  'U+3014',
  'U+3015',
  'U+3016',
  'U+3017',
  'U+3018',
  'U+3019',
  'U+301A',
  'U+301B',
  'U+301C',
  'U+301D',
  'U+301E',
  'U+301F',
  'U+3020',
  'U+3021',
  'U+3022',
  'U+3023',
  'U+3024',
  'U+3025',
  'U+3026',
  'U+3027',
  'U+3028',
  'U+3029',
  'U+302A',
  'U+302B',
  'U+302C',
  'U+302D',
  'U+302E',
  'U+302F',
  'U+3030',
  'U+3031',
  'U+3032',
  'U+3033',
  'U+3034',
  'U+3035',
  'U+3036',
  'U+3037',
  'U+3038',
  'U+3039',
  'U+303A',
  'U+303B',
  'U+303C',
  'U+303D',
  'U+303E',
  'U+303F',
])

const E69T24_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T24Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T24In (list, v) {
  for (const x of list) { if (E69T24Lower(x) === v) return true }
  return false
}

function E69T24Classify (tok) {
  const v = E69T24Lower(String(tok == null ? '' : tok))
  if (E69T24In(E69T24_BLOCK, v)) return E69T24_CLASS.BLOCK
  if (E69T24In(E69T24_WARN, v)) return E69T24_CLASS.WARN
  if (E69T24In(E69T24_ALLOW, v)) return E69T24_CLASS.ALLOW
  return E69T24_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T24_CLASS: E69T24_CLASS,
  E69T24_BLOCK: E69T24_BLOCK,
  E69T24_WARN: E69T24_WARN,
  E69T24_ALLOW: E69T24_ALLOW,
  E69T24Classify: E69T24Classify
})
