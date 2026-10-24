'use strict'

// e69regionalindicatorscatalogguard.js —— 区域指示符码位目录。
//
// 威胁模型：
//   区域指示符两两组合成国旗 emoji，单字符无意义但可注入造成终端宽度与组合异常，
//   标识符/命令字段应拒绝。纯字符查表，不用正则。

const E69U04_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69U04_BLOCK = Object.freeze([
])

const E69U04_WARN = Object.freeze([
  'U+1F1E6',
  'U+1F1E7',
  'U+1F1E8',
  'U+1F1E9',
  'U+1F1EA',
  'U+1F1EB',
  'U+1F1EC',
  'U+1F1ED',
  'U+1F1EE',
  'U+1F1EF',
  'U+1F1F0',
  'U+1F1F1',
  'U+1F1F2',
  'U+1F1F3',
  'U+1F1F4',
  'U+1F1F5',
  'U+1F1F6',
  'U+1F1F7',
  'U+1F1F8',
  'U+1F1F9',
  'U+1F1FA',
  'U+1F1FB',
  'U+1F1FC',
  'U+1F1FD',
  'U+1F1FE',
  'U+1F1FF',
])

const E69U04_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69U04Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69U04In (list, v) {
  for (const x of list) { if (E69U04Lower(x) === v) return true }
  return false
}

function E69U04Classify (tok) {
  const v = E69U04Lower(String(tok == null ? '' : tok))
  if (E69U04In(E69U04_BLOCK, v)) return E69U04_CLASS.BLOCK
  if (E69U04In(E69U04_WARN, v)) return E69U04_CLASS.WARN
  if (E69U04In(E69U04_ALLOW, v)) return E69U04_CLASS.ALLOW
  return E69U04_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69U04_CLASS: E69U04_CLASS,
  E69U04_BLOCK: E69U04_BLOCK,
  E69U04_WARN: E69U04_WARN,
  E69U04_ALLOW: E69U04_ALLOW,
  E69U04Classify: E69U04Classify
})
