'use strict'

// e69yijinghexagramcatalogguard.js —— 易经卦象符号码位目录。
//
// 威胁模型：
//   易经卦象符号在任何文本机器字段都无正当用途，缺字体时不可见，
//   应拒绝。纯字符查表，不用正则。

const E69T31_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T31_BLOCK = Object.freeze([
  'U+4DC0',
  'U+4DC1',
  'U+4DC2',
  'U+4DC3',
  'U+4DC4',
  'U+4DC5',
  'U+4DC6',
  'U+4DC7',
  'U+4DC8',
  'U+4DC9',
  'U+4DCA',
  'U+4DCB',
  'U+4DCC',
  'U+4DCD',
  'U+4DCE',
  'U+4DCF',
  'U+4DD0',
  'U+4DD1',
  'U+4DD2',
  'U+4DD3',
  'U+4DD4',
  'U+4DD5',
  'U+4DD6',
  'U+4DD7',
  'U+4DD8',
  'U+4DD9',
  'U+4DDA',
  'U+4DDB',
  'U+4DDC',
  'U+4DDD',
  'U+4DDE',
  'U+4DDF',
  'U+4DE0',
  'U+4DE1',
  'U+4DE2',
  'U+4DE3',
  'U+4DE4',
  'U+4DE5',
  'U+4DE6',
  'U+4DE7',
  'U+4DE8',
  'U+4DE9',
  'U+4DEA',
  'U+4DEB',
  'U+4DEC',
  'U+4DED',
  'U+4DEE',
  'U+4DEF',
  'U+4DF0',
  'U+4DF1',
  'U+4DF2',
  'U+4DF3',
  'U+4DF4',
  'U+4DF5',
  'U+4DF6',
  'U+4DF7',
  'U+4DF8',
  'U+4DF9',
  'U+4DFA',
  'U+4DFB',
  'U+4DFC',
  'U+4DFD',
  'U+4DFE',
  'U+4DFF',
])

const E69T31_WARN = Object.freeze([
])

const E69T31_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T31Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T31In (list, v) {
  for (const x of list) { if (E69T31Lower(x) === v) return true }
  return false
}

function E69T31Classify (tok) {
  const v = E69T31Lower(String(tok == null ? '' : tok))
  if (E69T31In(E69T31_BLOCK, v)) return E69T31_CLASS.BLOCK
  if (E69T31In(E69T31_WARN, v)) return E69T31_CLASS.WARN
  if (E69T31In(E69T31_ALLOW, v)) return E69T31_CLASS.ALLOW
  return E69T31_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T31_CLASS: E69T31_CLASS,
  E69T31_BLOCK: E69T31_BLOCK,
  E69T31_WARN: E69T31_WARN,
  E69T31_ALLOW: E69T31_ALLOW,
  E69T31Classify: E69T31Classify
})
