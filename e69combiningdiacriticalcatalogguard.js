'use strict'

// e69combiningdiacriticalcatalogguard.js —— 组合附加符号码位目录。
//
// 威胁模型：
//   组合附加符叠加在基字符上构成同形串，NFC/NFD 序列不同但视觉一致，可隐藏载荷，
//   应 NFKC 归一化并剥离非必要记号。纯字符查表，不用正则。

const E69T05_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T05_BLOCK = Object.freeze([
])

const E69T05_WARN = Object.freeze([
  'U+0300',
  'U+0301',
  'U+0302',
  'U+0303',
  'U+0304',
  'U+0305',
  'U+0306',
  'U+0307',
  'U+0308',
  'U+0309',
  'U+030A',
  'U+030B',
  'U+030C',
  'U+030D',
  'U+030E',
  'U+030F',
  'U+0310',
  'U+0311',
  'U+0312',
  'U+0313',
  'U+0314',
  'U+0315',
  'U+0316',
  'U+0317',
  'U+0318',
  'U+0319',
  'U+031A',
  'U+031B',
  'U+031C',
  'U+031D',
  'U+031E',
  'U+031F',
  'U+0320',
  'U+0321',
  'U+0322',
  'U+0323',
  'U+0324',
  'U+0325',
  'U+0326',
  'U+0327',
  'U+0328',
  'U+0329',
  'U+032A',
  'U+032B',
  'U+032C',
  'U+032D',
  'U+032E',
  'U+032F',
  'U+0330',
  'U+0331',
  'U+0332',
  'U+0333',
  'U+0334',
  'U+0335',
  'U+0336',
  'U+0337',
  'U+0338',
  'U+0339',
  'U+033A',
  'U+033B',
  'U+033C',
  'U+033D',
  'U+033E',
  'U+033F',
  'U+0340',
  'U+0341',
  'U+0342',
  'U+0343',
  'U+0344',
  'U+0345',
  'U+0346',
  'U+0347',
  'U+0348',
  'U+0349',
  'U+034A',
  'U+034B',
  'U+034C',
  'U+034D',
  'U+034E',
  'U+034F',
  'U+0350',
  'U+0351',
  'U+0352',
  'U+0353',
  'U+0354',
  'U+0355',
  'U+0356',
  'U+0357',
  'U+0358',
  'U+0359',
  'U+035A',
  'U+035B',
  'U+035C',
  'U+035D',
  'U+035E',
  'U+035F',
  'U+0360',
  'U+0361',
  'U+0362',
  'U+0363',
  'U+0364',
  'U+0365',
  'U+0366',
  'U+0367',
  'U+0368',
  'U+0369',
  'U+036A',
  'U+036B',
  'U+036C',
  'U+036D',
  'U+036E',
  'U+036F',
])

const E69T05_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T05Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T05In (list, v) {
  for (const x of list) { if (E69T05Lower(x) === v) return true }
  return false
}

function E69T05Classify (tok) {
  const v = E69T05Lower(String(tok == null ? '' : tok))
  if (E69T05In(E69T05_BLOCK, v)) return E69T05_CLASS.BLOCK
  if (E69T05In(E69T05_WARN, v)) return E69T05_CLASS.WARN
  if (E69T05In(E69T05_ALLOW, v)) return E69T05_CLASS.ALLOW
  return E69T05_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T05_CLASS: E69T05_CLASS,
  E69T05_BLOCK: E69T05_BLOCK,
  E69T05_WARN: E69T05_WARN,
  E69T05_ALLOW: E69T05_ALLOW,
  E69T05Classify: E69T05Classify
})
