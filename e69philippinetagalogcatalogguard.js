'use strict'

// e69philippinetagalogcatalogguard.js —— 菲律宾他加禄文字码位目录。
//
// 威胁模型：
//   他加禄等菲律宾文字组合规则复杂、渲染依赖字体，可隐藏注入序列，
//   标识符使用应拒绝。纯字符查表，不用正则。

const E69T13_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T13_BLOCK = Object.freeze([
  'U+1780',
  'U+1781',
  'U+1782',
  'U+1783',
  'U+1784',
  'U+1785',
  'U+1786',
  'U+1787',
  'U+1788',
  'U+1789',
  'U+178A',
  'U+178B',
  'U+178C',
  'U+178D',
  'U+178E',
  'U+178F',
  'U+1790',
  'U+1791',
  'U+1792',
  'U+1793',
  'U+1794',
  'U+1795',
  'U+1796',
  'U+1797',
  'U+1798',
  'U+1799',
  'U+179A',
  'U+179B',
  'U+179C',
  'U+179D',
  'U+179E',
  'U+179F',
  'U+17A0',
  'U+17A1',
  'U+17A2',
  'U+17A3',
  'U+17A4',
  'U+17A5',
  'U+17A6',
  'U+17A7',
  'U+17A8',
  'U+17A9',
  'U+17AA',
  'U+17AB',
  'U+17AC',
  'U+17AD',
  'U+17AE',
  'U+17AF',
  'U+17B0',
  'U+17B1',
  'U+17B2',
  'U+17B3',
  'U+17B4',
  'U+17B5',
  'U+17B6',
  'U+17B7',
  'U+17B8',
  'U+17B9',
  'U+17BA',
  'U+17BB',
  'U+17BC',
  'U+17BD',
  'U+17BE',
  'U+17BF',
  'U+17C0',
  'U+17C1',
  'U+17C2',
  'U+17C3',
  'U+17C4',
  'U+17C5',
  'U+17C6',
  'U+17C7',
  'U+17C8',
  'U+17C9',
  'U+17CA',
  'U+17CB',
  'U+17CC',
  'U+17CD',
  'U+17CE',
  'U+17CF',
  'U+17D0',
  'U+17D1',
  'U+17D2',
  'U+17D3',
  'U+17D4',
  'U+17D5',
  'U+17D6',
  'U+17D7',
  'U+17D8',
  'U+17D9',
  'U+17DA',
  'U+17DB',
  'U+17DC',
  'U+17DD',
  'U+17DE',
  'U+17DF',
  'U+17E0',
  'U+17E1',
  'U+17E2',
  'U+17E3',
  'U+17E4',
  'U+17E5',
  'U+17E6',
  'U+17E7',
  'U+17E8',
  'U+17E9',
  'U+17EA',
  'U+17EB',
  'U+17EC',
  'U+17ED',
  'U+17EE',
  'U+17EF',
  'U+17F0',
  'U+17F1',
  'U+17F2',
  'U+17F3',
  'U+17F4',
  'U+17F5',
  'U+17F6',
  'U+17F7',
  'U+17F8',
  'U+17F9',
  'U+17FA',
  'U+17FB',
  'U+17FC',
  'U+17FD',
  'U+17FE',
  'U+17FF',
])

const E69T13_WARN = Object.freeze([
])

const E69T13_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T13Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T13In (list, v) {
  for (const x of list) { if (E69T13Lower(x) === v) return true }
  return false
}

function E69T13Classify (tok) {
  const v = E69T13Lower(String(tok == null ? '' : tok))
  if (E69T13In(E69T13_BLOCK, v)) return E69T13_CLASS.BLOCK
  if (E69T13In(E69T13_WARN, v)) return E69T13_CLASS.WARN
  if (E69T13In(E69T13_ALLOW, v)) return E69T13_CLASS.ALLOW
  return E69T13_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T13_CLASS: E69T13_CLASS,
  E69T13_BLOCK: E69T13_BLOCK,
  E69T13_WARN: E69T13_WARN,
  E69T13_ALLOW: E69T13_ALLOW,
  E69T13Classify: E69T13Classify
})
