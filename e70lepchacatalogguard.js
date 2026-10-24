'use strict'

// e70lepchacatalogguard.js —— 雷布查文字码位目录。
//
// 威胁模型：
//   雷布查文在机器字段无正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const E70T32_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T32_BLOCK = Object.freeze([
  'U+1C00',
  'U+1C01',
  'U+1C02',
  'U+1C03',
  'U+1C04',
  'U+1C05',
  'U+1C06',
  'U+1C07',
  'U+1C08',
  'U+1C09',
  'U+1C0A',
  'U+1C0B',
  'U+1C0C',
  'U+1C0D',
  'U+1C0E',
  'U+1C0F',
  'U+1C10',
  'U+1C11',
  'U+1C12',
  'U+1C13',
  'U+1C14',
  'U+1C15',
  'U+1C16',
  'U+1C17',
  'U+1C18',
  'U+1C19',
  'U+1C1A',
  'U+1C1B',
  'U+1C1C',
  'U+1C1D',
  'U+1C1E',
  'U+1C1F',
  'U+1C20',
  'U+1C21',
  'U+1C22',
  'U+1C23',
  'U+1C24',
  'U+1C25',
  'U+1C26',
  'U+1C27',
  'U+1C28',
  'U+1C29',
  'U+1C2A',
  'U+1C2B',
  'U+1C2C',
  'U+1C2D',
  'U+1C2E',
  'U+1C2F',
  'U+1C30',
  'U+1C31',
  'U+1C32',
  'U+1C33',
  'U+1C34',
  'U+1C35',
  'U+1C36',
  'U+1C37',
  'U+1C38',
  'U+1C39',
  'U+1C3A',
  'U+1C3B',
  'U+1C3C',
  'U+1C3D',
  'U+1C3E',
  'U+1C3F',
  'U+1C40',
  'U+1C41',
  'U+1C42',
  'U+1C43',
  'U+1C44',
  'U+1C45',
  'U+1C46',
  'U+1C47',
  'U+1C48',
  'U+1C49',
  'U+1C4A',
  'U+1C4B',
  'U+1C4C',
  'U+1C4D',
  'U+1C4E',
  'U+1C4F',
])

const E70T32_WARN = Object.freeze([
])

const E70T32_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T32Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T32In (list, v) {
  for (const x of list) { if (E70T32Lower(x) === v) return true }
  return false
}

function E70T32Classify (tok) {
  const v = E70T32Lower(String(tok == null ? '' : tok))
  if (E70T32In(E70T32_BLOCK, v)) return E70T32_CLASS.BLOCK
  if (E70T32In(E70T32_WARN, v)) return E70T32_CLASS.WARN
  if (E70T32In(E70T32_ALLOW, v)) return E70T32_CLASS.ALLOW
  return E70T32_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T32_CLASS: E70T32_CLASS,
  E70T32_BLOCK: E70T32_BLOCK,
  E70T32_WARN: E70T32_WARN,
  E70T32_ALLOW: E70T32_ALLOW,
  E70T32Classify: E70T32Classify
})
