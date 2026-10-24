'use strict'

// e68gujaraticatalogguard.js —— 古吉拉特文字码位目录。
//
// 威胁模型：
//   古吉拉特文组合附加符造成视觉与码位差异，
//   应规范化后比较。纯字符查表，不用正则。

const E68R08_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E68R08_BLOCK = Object.freeze([
])

const E68R08_WARN = Object.freeze([
  'U+0A80',
  'U+0A81',
  'U+0A82',
  'U+0A83',
  'U+0A84',
  'U+0A85',
  'U+0A86',
  'U+0A87',
  'U+0A88',
  'U+0A89',
  'U+0A8A',
  'U+0A8B',
  'U+0A8C',
  'U+0A8D',
  'U+0A8E',
  'U+0A8F',
  'U+0A90',
  'U+0A91',
  'U+0A92',
  'U+0A93',
  'U+0A94',
  'U+0A95',
  'U+0A96',
  'U+0A97',
  'U+0A98',
  'U+0A99',
  'U+0A9A',
  'U+0A9B',
  'U+0A9C',
  'U+0A9D',
  'U+0A9E',
  'U+0A9F',
  'U+0AA0',
  'U+0AA1',
  'U+0AA2',
  'U+0AA3',
  'U+0AA4',
  'U+0AA5',
  'U+0AA6',
  'U+0AA7',
  'U+0AA8',
  'U+0AA9',
  'U+0AAA',
  'U+0AAB',
  'U+0AAC',
  'U+0AAD',
  'U+0AAE',
  'U+0AAF',
  'U+0AB0',
  'U+0AB1',
  'U+0AB2',
  'U+0AB3',
  'U+0AB4',
  'U+0AB5',
  'U+0AB6',
  'U+0AB7',
  'U+0AB8',
  'U+0AB9',
  'U+0ABA',
  'U+0ABB',
  'U+0ABC',
  'U+0ABD',
  'U+0ABE',
  'U+0ABF',
  'U+0AC0',
  'U+0AC1',
  'U+0AC2',
  'U+0AC3',
  'U+0AC4',
  'U+0AC5',
  'U+0AC6',
  'U+0AC7',
  'U+0AC8',
  'U+0AC9',
  'U+0ACA',
  'U+0ACB',
  'U+0ACC',
  'U+0ACD',
  'U+0ACE',
  'U+0ACF',
  'U+0AD0',
  'U+0AD1',
  'U+0AD2',
  'U+0AD3',
  'U+0AD4',
  'U+0AD5',
  'U+0AD6',
  'U+0AD7',
  'U+0AD8',
  'U+0AD9',
  'U+0ADA',
  'U+0ADB',
  'U+0ADC',
  'U+0ADD',
  'U+0ADE',
  'U+0ADF',
  'U+0AE0',
  'U+0AE1',
  'U+0AE2',
  'U+0AE3',
  'U+0AE4',
  'U+0AE5',
  'U+0AE6',
  'U+0AE7',
  'U+0AE8',
  'U+0AE9',
  'U+0AEA',
  'U+0AEB',
  'U+0AEC',
  'U+0AED',
  'U+0AEE',
  'U+0AEF',
  'U+0AF0',
  'U+0AF1',
  'U+0AF2',
  'U+0AF3',
  'U+0AF4',
  'U+0AF5',
  'U+0AF6',
  'U+0AF7',
  'U+0AF8',
  'U+0AF9',
  'U+0AFA',
  'U+0AFB',
  'U+0AFC',
  'U+0AFD',
  'U+0AFE',
  'U+0AFF',
])

const E68R08_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E68R08Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E68R08In (list, v) {
  for (const x of list) { if (E68R08Lower(x) === v) return true }
  return false
}

function E68R08Classify (tok) {
  const v = E68R08Lower(String(tok == null ? '' : tok).trim())
  if (E68R08In(E68R08_BLOCK, v)) return E68R08_CLASS.BLOCK
  if (E68R08In(E68R08_WARN, v)) return E68R08_CLASS.WARN
  if (E68R08In(E68R08_ALLOW, v)) return E68R08_CLASS.ALLOW
  return E68R08_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E68R08_CLASS: E68R08_CLASS,
  E68R08_BLOCK: E68R08_BLOCK,
  E68R08_WARN: E68R08_WARN,
  E68R08_ALLOW: E68R08_ALLOW,
  E68R08Classify: E68R08Classify
})
