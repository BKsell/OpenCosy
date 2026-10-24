'use strict'

// e69combiningmarksymbolscatalogguard.js —— 组合附加记号符号码位目录。
//
// 威胁模型：
//   组合用记号（如箭头、圈）叠加在基字符上形成同形，可隐藏真实内容，
//   应 NFKC 归一化并剥离。纯字符查表，不用正则。

const E69T23_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T23_BLOCK = Object.freeze([
])

const E69T23_WARN = Object.freeze([
  'U+20D0',
  'U+20D1',
  'U+20D2',
  'U+20D3',
  'U+20D4',
  'U+20D5',
  'U+20D6',
  'U+20D7',
  'U+20D8',
  'U+20D9',
  'U+20DA',
  'U+20DB',
  'U+20DC',
  'U+20DD',
  'U+20DE',
  'U+20DF',
  'U+20E0',
  'U+20E1',
  'U+20E2',
  'U+20E3',
  'U+20E4',
  'U+20E5',
  'U+20E6',
  'U+20E7',
  'U+20E8',
  'U+20E9',
  'U+20EA',
  'U+20EB',
  'U+20EC',
  'U+20ED',
  'U+20EE',
  'U+20EF',
  'U+20F0',
  'U+20F1',
  'U+20F2',
  'U+20F3',
  'U+20F4',
  'U+20F5',
  'U+20F6',
  'U+20F7',
  'U+20F8',
  'U+20F9',
  'U+20FA',
  'U+20FB',
  'U+20FC',
  'U+20FD',
  'U+20FE',
  'U+20FF',
])

const E69T23_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T23Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T23In (list, v) {
  for (const x of list) { if (E69T23Lower(x) === v) return true }
  return false
}

function E69T23Classify (tok) {
  const v = E69T23Lower(String(tok == null ? '' : tok))
  if (E69T23In(E69T23_BLOCK, v)) return E69T23_CLASS.BLOCK
  if (E69T23In(E69T23_WARN, v)) return E69T23_CLASS.WARN
  if (E69T23In(E69T23_ALLOW, v)) return E69T23_CLASS.ALLOW
  return E69T23_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T23_CLASS: E69T23_CLASS,
  E69T23_BLOCK: E69T23_BLOCK,
  E69T23_WARN: E69T23_WARN,
  E69T23_ALLOW: E69T23_ALLOW,
  E69T23Classify: E69T23Classify
})
