'use strict'

// e69combiningsuppcatalogguard.js —— 组合附加符补充码位目录。
//
// 威胁模型：
//   补充组合记号覆盖上标/附加显示，视觉与码位序列不一致，
//   应 NFKC 归一化并剥离。纯字符查表，不用正则。

const E69T38_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T38_BLOCK = Object.freeze([
])

const E69T38_WARN = Object.freeze([
  'U+1DC0',
  'U+1DC1',
  'U+1DC2',
  'U+1DC3',
  'U+1DC4',
  'U+1DC5',
  'U+1DC6',
  'U+1DC7',
  'U+1DC8',
  'U+1DC9',
  'U+1DCA',
  'U+1DCB',
  'U+1DCC',
  'U+1DCD',
  'U+1DCE',
  'U+1DCF',
  'U+1DD0',
  'U+1DD1',
  'U+1DD2',
  'U+1DD3',
  'U+1DD4',
  'U+1DD5',
  'U+1DD6',
  'U+1DD7',
  'U+1DD8',
  'U+1DD9',
  'U+1DDA',
  'U+1DDB',
  'U+1DDC',
  'U+1DDD',
  'U+1DDE',
  'U+1DDF',
  'U+1DE0',
  'U+1DE1',
  'U+1DE2',
  'U+1DE3',
  'U+1DE4',
  'U+1DE5',
  'U+1DE6',
  'U+1DE7',
  'U+1DE8',
  'U+1DE9',
  'U+1DEA',
  'U+1DEB',
  'U+1DEC',
  'U+1DED',
  'U+1DEE',
  'U+1DEF',
  'U+1DF0',
  'U+1DF1',
  'U+1DF2',
  'U+1DF3',
  'U+1DF4',
  'U+1DF5',
  'U+1DF6',
  'U+1DF7',
  'U+1DF8',
  'U+1DF9',
  'U+1DFA',
  'U+1DFB',
  'U+1DFC',
  'U+1DFD',
  'U+1DFE',
  'U+1DFF',
])

const E69T38_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T38Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T38In (list, v) {
  for (const x of list) { if (E69T38Lower(x) === v) return true }
  return false
}

function E69T38Classify (tok) {
  const v = E69T38Lower(String(tok == null ? '' : tok))
  if (E69T38In(E69T38_BLOCK, v)) return E69T38_CLASS.BLOCK
  if (E69T38In(E69T38_WARN, v)) return E69T38_CLASS.WARN
  if (E69T38In(E69T38_ALLOW, v)) return E69T38_CLASS.ALLOW
  return E69T38_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T38_CLASS: E69T38_CLASS,
  E69T38_BLOCK: E69T38_BLOCK,
  E69T38_WARN: E69T38_WARN,
  E69T38_ALLOW: E69T38_ALLOW,
  E69T38Classify: E69T38Classify
})
