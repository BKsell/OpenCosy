'use strict'

// e70glagoliticcatalogguard.js —— 格拉哥里文字码位目录。
//
// 威胁模型：
//   格拉哥里文字罕用、与拉丁近似，在常规字段无正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const E70T51_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T51_BLOCK = Object.freeze([
  'U+2C00',
  'U+2C01',
  'U+2C02',
  'U+2C03',
  'U+2C04',
  'U+2C05',
  'U+2C06',
  'U+2C07',
  'U+2C08',
  'U+2C09',
  'U+2C0A',
  'U+2C0B',
  'U+2C0C',
  'U+2C0D',
  'U+2C0E',
  'U+2C0F',
  'U+2C10',
  'U+2C11',
  'U+2C12',
  'U+2C13',
  'U+2C14',
  'U+2C15',
  'U+2C16',
  'U+2C17',
  'U+2C18',
  'U+2C19',
  'U+2C1A',
  'U+2C1B',
  'U+2C1C',
  'U+2C1D',
  'U+2C1E',
  'U+2C1F',
  'U+2C20',
  'U+2C21',
  'U+2C22',
  'U+2C23',
  'U+2C24',
  'U+2C25',
  'U+2C26',
  'U+2C27',
  'U+2C28',
  'U+2C29',
  'U+2C2A',
  'U+2C2B',
  'U+2C2C',
  'U+2C2D',
  'U+2C2E',
  'U+2C2F',
  'U+2C30',
  'U+2C31',
  'U+2C32',
  'U+2C33',
  'U+2C34',
  'U+2C35',
  'U+2C36',
  'U+2C37',
  'U+2C38',
  'U+2C39',
  'U+2C3A',
  'U+2C3B',
  'U+2C3C',
  'U+2C3D',
  'U+2C3E',
  'U+2C3F',
  'U+2C40',
  'U+2C41',
  'U+2C42',
  'U+2C43',
  'U+2C44',
  'U+2C45',
  'U+2C46',
  'U+2C47',
  'U+2C48',
  'U+2C49',
  'U+2C4A',
  'U+2C4B',
  'U+2C4C',
  'U+2C4D',
  'U+2C4E',
  'U+2C4F',
  'U+2C50',
  'U+2C51',
  'U+2C52',
  'U+2C53',
  'U+2C54',
  'U+2C55',
  'U+2C56',
  'U+2C57',
  'U+2C58',
  'U+2C59',
  'U+2C5A',
  'U+2C5B',
  'U+2C5C',
  'U+2C5D',
  'U+2C5E',
  'U+2C5F',
])

const E70T51_WARN = Object.freeze([
])

const E70T51_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T51Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T51In (list, v) {
  for (const x of list) { if (E70T51Lower(x) === v) return true }
  return false
}

function E70T51Classify (tok) {
  const v = E70T51Lower(String(tok == null ? '' : tok))
  if (E70T51In(E70T51_BLOCK, v)) return E70T51_CLASS.BLOCK
  if (E70T51In(E70T51_WARN, v)) return E70T51_CLASS.WARN
  if (E70T51In(E70T51_ALLOW, v)) return E70T51_CLASS.ALLOW
  return E70T51_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T51_CLASS: E70T51_CLASS,
  E70T51_BLOCK: E70T51_BLOCK,
  E70T51_WARN: E70T51_WARN,
  E70T51_ALLOW: E70T51_ALLOW,
  E70T51Classify: E70T51Classify
})
