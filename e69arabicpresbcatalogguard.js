'use strict'

// e69arabicpresbcatalogguard.js —— 阿拉伯表示形式 B 码位目录。
//
// 威胁模型：
//   阿拉伯表示形式 B 含连写变体与 BOM U+FEFF（零宽不换行空格），可隐藏载荷与重排顺序，
//   应剥离 BOM 并规范化。纯字符查表，不用正则。

const E69T35_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T35_BLOCK = Object.freeze([
])

const E69T35_WARN = Object.freeze([
  'U+FE70',
  'U+FE71',
  'U+FE72',
  'U+FE73',
  'U+FE74',
  'U+FE75',
  'U+FE76',
  'U+FE77',
  'U+FE78',
  'U+FE79',
  'U+FE7A',
  'U+FE7B',
  'U+FE7C',
  'U+FE7D',
  'U+FE7E',
  'U+FE7F',
  'U+FE80',
  'U+FE81',
  'U+FE82',
  'U+FE83',
  'U+FE84',
  'U+FE85',
  'U+FE86',
  'U+FE87',
  'U+FE88',
  'U+FE89',
  'U+FE8A',
  'U+FE8B',
  'U+FE8C',
  'U+FE8D',
  'U+FE8E',
  'U+FE8F',
  'U+FE90',
  'U+FE91',
  'U+FE92',
  'U+FE93',
  'U+FE94',
  'U+FE95',
  'U+FE96',
  'U+FE97',
  'U+FE98',
  'U+FE99',
  'U+FE9A',
  'U+FE9B',
  'U+FE9C',
  'U+FE9D',
  'U+FE9E',
  'U+FE9F',
  'U+FEA0',
  'U+FEA1',
  'U+FEA2',
  'U+FEA3',
  'U+FEA4',
  'U+FEA5',
  'U+FEA6',
  'U+FEA7',
  'U+FEA8',
  'U+FEA9',
  'U+FEAA',
  'U+FEAB',
  'U+FEAC',
  'U+FEAD',
  'U+FEAE',
  'U+FEAF',
  'U+FEB0',
  'U+FEB1',
  'U+FEB2',
  'U+FEB3',
  'U+FEB4',
  'U+FEB5',
  'U+FEB6',
  'U+FEB7',
  'U+FEB8',
  'U+FEB9',
  'U+FEBA',
  'U+FEBB',
  'U+FEBC',
  'U+FEBD',
  'U+FEBE',
  'U+FEBF',
  'U+FEC0',
  'U+FEC1',
  'U+FEC2',
  'U+FEC3',
  'U+FEC4',
  'U+FEC5',
  'U+FEC6',
  'U+FEC7',
  'U+FEC8',
  'U+FEC9',
  'U+FECA',
  'U+FECB',
  'U+FECC',
  'U+FECD',
  'U+FECE',
  'U+FECF',
  'U+FED0',
  'U+FED1',
  'U+FED2',
  'U+FED3',
  'U+FED4',
  'U+FED5',
  'U+FED6',
  'U+FED7',
  'U+FED8',
  'U+FED9',
  'U+FEDA',
  'U+FEDB',
  'U+FEDC',
  'U+FEDD',
  'U+FEDE',
  'U+FEDF',
  'U+FEE0',
  'U+FEE1',
  'U+FEE2',
  'U+FEE3',
  'U+FEE4',
  'U+FEE5',
  'U+FEE6',
  'U+FEE7',
  'U+FEE8',
  'U+FEE9',
  'U+FEEA',
  'U+FEEB',
  'U+FEEC',
  'U+FEED',
  'U+FEEE',
  'U+FEEF',
  'U+FEF0',
  'U+FEF1',
  'U+FEF2',
  'U+FEF3',
  'U+FEF4',
  'U+FEF5',
  'U+FEF6',
  'U+FEF7',
  'U+FEF8',
  'U+FEF9',
  'U+FEFA',
  'U+FEFB',
  'U+FEFC',
  'U+FEFD',
  'U+FEFE',
  'U+FEFF',
])

const E69T35_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T35Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T35In (list, v) {
  for (const x of list) { if (E69T35Lower(x) === v) return true }
  return false
}

function E69T35Classify (tok) {
  const v = E69T35Lower(String(tok == null ? '' : tok))
  if (E69T35In(E69T35_BLOCK, v)) return E69T35_CLASS.BLOCK
  if (E69T35In(E69T35_WARN, v)) return E69T35_CLASS.WARN
  if (E69T35In(E69T35_ALLOW, v)) return E69T35_CLASS.ALLOW
  return E69T35_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T35_CLASS: E69T35_CLASS,
  E69T35_BLOCK: E69T35_BLOCK,
  E69T35_WARN: E69T35_WARN,
  E69T35_ALLOW: E69T35_ALLOW,
  E69T35Classify: E69T35Classify
})
