'use strict'

// e70shaviancatalogguard.js —— 萧伯纳字母平面目录。
//
// 威胁模型：
//   萧伯纳字母与拉丁音位对应但字形不同，机器字段无正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const E70U06_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70U06_BLOCK = Object.freeze([
  'U+10450',
  'U+10451',
  'U+10452',
  'U+10453',
  'U+10454',
  'U+10455',
  'U+10456',
  'U+10457',
  'U+10458',
  'U+10459',
  'U+1045A',
  'U+1045B',
  'U+1045C',
  'U+1045D',
  'U+1045E',
  'U+1045F',
  'U+10460',
  'U+10461',
  'U+10462',
  'U+10463',
  'U+10464',
  'U+10465',
  'U+10466',
  'U+10467',
  'U+10468',
  'U+10469',
  'U+1046A',
  'U+1046B',
  'U+1046C',
  'U+1046D',
  'U+1046E',
  'U+1046F',
  'U+10470',
  'U+10471',
  'U+10472',
  'U+10473',
  'U+10474',
  'U+10475',
  'U+10476',
  'U+10477',
  'U+10478',
  'U+10479',
  'U+1047A',
  'U+1047B',
  'U+1047C',
  'U+1047D',
  'U+1047E',
  'U+1047F',
])

const E70U06_WARN = Object.freeze([
])

const E70U06_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70U06Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70U06In (list, v) {
  for (const x of list) { if (E70U06Lower(x) === v) return true }
  return false
}

function E70U06Classify (tok) {
  const v = E70U06Lower(String(tok == null ? '' : tok))
  if (E70U06In(E70U06_BLOCK, v)) return E70U06_CLASS.BLOCK
  if (E70U06In(E70U06_WARN, v)) return E70U06_CLASS.WARN
  if (E70U06In(E70U06_ALLOW, v)) return E70U06_CLASS.ALLOW
  return E70U06_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70U06_CLASS: E70U06_CLASS,
  E70U06_BLOCK: E70U06_BLOCK,
  E70U06_WARN: E70U06_WARN,
  E70U06_ALLOW: E70U06_ALLOW,
  E70U06Classify: E70U06Classify
})
