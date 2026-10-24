'use strict'

// e68emoticonscatalogguard.js —— 补充平面表情符号目录。
//
// 威胁模型：
//   表情码位在不同系统字形差异大且占双宽，
//   标识符/路径/命令字段应拒绝。纯字符查表，不用正则。

const E68S01_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E68S01_BLOCK = Object.freeze([
])

const E68S01_WARN = Object.freeze([
  'U+1F600',
  'U+1F601',
  'U+1F602',
  'U+1F603',
  'U+1F604',
  'U+1F605',
  'U+1F606',
  'U+1F607',
  'U+1F608',
  'U+1F609',
  'U+1F60A',
  'U+1F60B',
  'U+1F60C',
  'U+1F60D',
  'U+1F60E',
  'U+1F60F',
  'U+1F610',
  'U+1F611',
  'U+1F612',
  'U+1F613',
  'U+1F614',
  'U+1F615',
  'U+1F616',
  'U+1F617',
  'U+1F618',
  'U+1F619',
  'U+1F61A',
  'U+1F61B',
  'U+1F61C',
  'U+1F61D',
  'U+1F61E',
  'U+1F61F',
  'U+1F620',
  'U+1F621',
  'U+1F622',
  'U+1F623',
  'U+1F624',
  'U+1F625',
  'U+1F626',
  'U+1F627',
  'U+1F628',
  'U+1F629',
  'U+1F62A',
  'U+1F62B',
  'U+1F62C',
  'U+1F62D',
  'U+1F62E',
  'U+1F62F',
  'U+1F630',
  'U+1F631',
  'U+1F632',
  'U+1F633',
  'U+1F634',
  'U+1F635',
  'U+1F636',
  'U+1F637',
  'U+1F638',
  'U+1F639',
  'U+1F63A',
  'U+1F63B',
  'U+1F63C',
  'U+1F63D',
  'U+1F63E',
  'U+1F63F',
  'U+1F640',
  'U+1F641',
  'U+1F642',
  'U+1F643',
  'U+1F644',
  'U+1F645',
  'U+1F646',
  'U+1F647',
  'U+1F648',
  'U+1F649',
  'U+1F64A',
  'U+1F64B',
  'U+1F64C',
  'U+1F64D',
  'U+1F64E',
  'U+1F64F',
])

const E68S01_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E68S01Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E68S01In (list, v) {
  for (const x of list) { if (E68S01Lower(x) === v) return true }
  return false
}

function E68S01Classify (tok) {
  const v = E68S01Lower(String(tok == null ? '' : tok).trim())
  if (E68S01In(E68S01_BLOCK, v)) return E68S01_CLASS.BLOCK
  if (E68S01In(E68S01_WARN, v)) return E68S01_CLASS.WARN
  if (E68S01In(E68S01_ALLOW, v)) return E68S01_CLASS.ALLOW
  return E68S01_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E68S01_CLASS: E68S01_CLASS,
  E68S01_BLOCK: E68S01_BLOCK,
  E68S01_WARN: E68S01_WARN,
  E68S01_ALLOW: E68S01_ALLOW,
  E68S01Classify: E68S01Classify
})
