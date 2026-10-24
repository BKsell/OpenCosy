'use strict'

// e70syriaccatalogguard.js —— 叙利亚文字码位目录。
//
// 威胁模型：
//   叙利亚文在常规字段无正当用途且为从右向左文字，可用于顺序欺骗，
//   应直接拒绝。纯字符查表，不用正则。

const E70T03_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T03_BLOCK = Object.freeze([
  'U+0700',
  'U+0701',
  'U+0702',
  'U+0703',
  'U+0704',
  'U+0705',
  'U+0706',
  'U+0707',
  'U+0708',
  'U+0709',
  'U+070A',
  'U+070B',
  'U+070C',
  'U+070D',
  'U+070E',
  'U+070F',
  'U+0710',
  'U+0711',
  'U+0712',
  'U+0713',
  'U+0714',
  'U+0715',
  'U+0716',
  'U+0717',
  'U+0718',
  'U+0719',
  'U+071A',
  'U+071B',
  'U+071C',
  'U+071D',
  'U+071E',
  'U+071F',
  'U+0720',
  'U+0721',
  'U+0722',
  'U+0723',
  'U+0724',
  'U+0725',
  'U+0726',
  'U+0727',
  'U+0728',
  'U+0729',
  'U+072A',
  'U+072B',
  'U+072C',
  'U+072D',
  'U+072E',
  'U+072F',
  'U+0730',
  'U+0731',
  'U+0732',
  'U+0733',
  'U+0734',
  'U+0735',
  'U+0736',
  'U+0737',
  'U+0738',
  'U+0739',
  'U+073A',
  'U+073B',
  'U+073C',
  'U+073D',
  'U+073E',
  'U+073F',
  'U+0740',
  'U+0741',
  'U+0742',
  'U+0743',
  'U+0744',
  'U+0745',
  'U+0746',
  'U+0747',
  'U+0748',
  'U+0749',
  'U+074A',
  'U+074B',
  'U+074C',
  'U+074D',
  'U+074E',
  'U+074F',
])

const E70T03_WARN = Object.freeze([
])

const E70T03_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T03Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T03In (list, v) {
  for (const x of list) { if (E70T03Lower(x) === v) return true }
  return false
}

function E70T03Classify (tok) {
  const v = E70T03Lower(String(tok == null ? '' : tok))
  if (E70T03In(E70T03_BLOCK, v)) return E70T03_CLASS.BLOCK
  if (E70T03In(E70T03_WARN, v)) return E70T03_CLASS.WARN
  if (E70T03In(E70T03_ALLOW, v)) return E70T03_CLASS.ALLOW
  return E70T03_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T03_CLASS: E70T03_CLASS,
  E70T03_BLOCK: E70T03_BLOCK,
  E70T03_WARN: E70T03_WARN,
  E70T03_ALLOW: E70T03_ALLOW,
  E70T03Classify: E70T03Classify
})
