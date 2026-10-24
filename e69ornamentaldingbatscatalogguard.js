'use strict'

// e69ornamentaldingbatscatalogguard.js —— 装饰性丁贝补充平面目录。
//
// 威胁模型：
//   装饰性丁贝符号在标识符/路径/命令中无正当用途，双宽且渲染不一致，
//   结构化字段应拒绝。纯字符查表，不用正则。

const E69U00_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69U00_BLOCK = Object.freeze([
  'U+1F650',
  'U+1F651',
  'U+1F652',
  'U+1F653',
  'U+1F654',
  'U+1F655',
  'U+1F656',
  'U+1F657',
  'U+1F658',
  'U+1F659',
  'U+1F65A',
  'U+1F65B',
  'U+1F65C',
  'U+1F65D',
  'U+1F65E',
  'U+1F65F',
  'U+1F660',
  'U+1F661',
  'U+1F662',
  'U+1F663',
  'U+1F664',
  'U+1F665',
  'U+1F666',
  'U+1F667',
  'U+1F668',
  'U+1F669',
  'U+1F66A',
  'U+1F66B',
  'U+1F66C',
  'U+1F66D',
  'U+1F66E',
  'U+1F66F',
  'U+1F670',
  'U+1F671',
  'U+1F672',
  'U+1F673',
  'U+1F674',
  'U+1F675',
  'U+1F676',
  'U+1F677',
  'U+1F678',
  'U+1F679',
  'U+1F67A',
  'U+1F67B',
  'U+1F67C',
  'U+1F67D',
  'U+1F67E',
  'U+1F67F',
])

const E69U00_WARN = Object.freeze([
])

const E69U00_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69U00Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69U00In (list, v) {
  for (const x of list) { if (E69U00Lower(x) === v) return true }
  return false
}

function E69U00Classify (tok) {
  const v = E69U00Lower(String(tok == null ? '' : tok))
  if (E69U00In(E69U00_BLOCK, v)) return E69U00_CLASS.BLOCK
  if (E69U00In(E69U00_WARN, v)) return E69U00_CLASS.WARN
  if (E69U00In(E69U00_ALLOW, v)) return E69U00_CLASS.ALLOW
  return E69U00_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69U00_CLASS: E69U00_CLASS,
  E69U00_BLOCK: E69U00_BLOCK,
  E69U00_WARN: E69U00_WARN,
  E69U00_ALLOW: E69U00_ALLOW,
  E69U00Classify: E69U00Classify
})
