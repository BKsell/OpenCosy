'use strict'

// e70armeniancatalogguard.js —— 亚美尼亚文字码位目录。
//
// 威胁模型：
//   亚美尼亚字母在常规机器字段无正当用途，部分大写与拉丁近似，可隐藏载荷，
//   标识符/路径应拒绝。纯字符查表，不用正则。

const E70T00_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T00_BLOCK = Object.freeze([
  'U+0530',
  'U+0531',
  'U+0532',
  'U+0533',
  'U+0534',
  'U+0535',
  'U+0536',
  'U+0537',
  'U+0538',
  'U+0539',
  'U+053A',
  'U+053B',
  'U+053C',
  'U+053D',
  'U+053E',
  'U+053F',
  'U+0540',
  'U+0541',
  'U+0542',
  'U+0543',
  'U+0544',
  'U+0545',
  'U+0546',
  'U+0547',
  'U+0548',
  'U+0549',
  'U+054A',
  'U+054B',
  'U+054C',
  'U+054D',
  'U+054E',
  'U+054F',
  'U+0550',
  'U+0551',
  'U+0552',
  'U+0553',
  'U+0554',
  'U+0555',
  'U+0556',
  'U+0557',
  'U+0558',
  'U+0559',
  'U+055A',
  'U+055B',
  'U+055C',
  'U+055D',
  'U+055E',
  'U+055F',
  'U+0560',
  'U+0561',
  'U+0562',
  'U+0563',
  'U+0564',
  'U+0565',
  'U+0566',
  'U+0567',
  'U+0568',
  'U+0569',
  'U+056A',
  'U+056B',
  'U+056C',
  'U+056D',
  'U+056E',
  'U+056F',
  'U+0570',
  'U+0571',
  'U+0572',
  'U+0573',
  'U+0574',
  'U+0575',
  'U+0576',
  'U+0577',
  'U+0578',
  'U+0579',
  'U+057A',
  'U+057B',
  'U+057C',
  'U+057D',
  'U+057E',
  'U+057F',
  'U+0580',
  'U+0581',
  'U+0582',
  'U+0583',
  'U+0584',
  'U+0585',
  'U+0586',
  'U+0587',
  'U+0588',
  'U+0589',
  'U+058A',
  'U+058B',
  'U+058C',
  'U+058D',
  'U+058E',
  'U+058F',
])

const E70T00_WARN = Object.freeze([
])

const E70T00_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T00Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T00In (list, v) {
  for (const x of list) { if (E70T00Lower(x) === v) return true }
  return false
}

function E70T00Classify (tok) {
  const v = E70T00Lower(String(tok == null ? '' : tok))
  if (E70T00In(E70T00_BLOCK, v)) return E70T00_CLASS.BLOCK
  if (E70T00In(E70T00_WARN, v)) return E70T00_CLASS.WARN
  if (E70T00In(E70T00_ALLOW, v)) return E70T00_CLASS.ALLOW
  return E70T00_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T00_CLASS: E70T00_CLASS,
  E70T00_BLOCK: E70T00_BLOCK,
  E70T00_WARN: E70T00_WARN,
  E70T00_ALLOW: E70T00_ALLOW,
  E70T00Classify: E70T00Classify
})
