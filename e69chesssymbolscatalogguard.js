'use strict'

// e69chesssymbolscatalogguard.js —— 棋类符号补充平面目录。
//
// 威胁模型：
//   棋子等符号在机器字段无正当用途，可用于界面仿冒，
//   结构化字段应拒绝。纯字符查表，不用正则。

const E69U03_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69U03_BLOCK = Object.freeze([
  'U+1FA00',
  'U+1FA01',
  'U+1FA02',
  'U+1FA03',
  'U+1FA04',
  'U+1FA05',
  'U+1FA06',
  'U+1FA07',
  'U+1FA08',
  'U+1FA09',
  'U+1FA0A',
  'U+1FA0B',
  'U+1FA0C',
  'U+1FA0D',
  'U+1FA0E',
  'U+1FA0F',
  'U+1FA10',
  'U+1FA11',
  'U+1FA12',
  'U+1FA13',
  'U+1FA14',
  'U+1FA15',
  'U+1FA16',
  'U+1FA17',
  'U+1FA18',
  'U+1FA19',
  'U+1FA1A',
  'U+1FA1B',
  'U+1FA1C',
  'U+1FA1D',
  'U+1FA1E',
  'U+1FA1F',
  'U+1FA20',
  'U+1FA21',
  'U+1FA22',
  'U+1FA23',
  'U+1FA24',
  'U+1FA25',
  'U+1FA26',
  'U+1FA27',
  'U+1FA28',
  'U+1FA29',
  'U+1FA2A',
  'U+1FA2B',
  'U+1FA2C',
  'U+1FA2D',
  'U+1FA2E',
  'U+1FA2F',
  'U+1FA30',
  'U+1FA31',
  'U+1FA32',
  'U+1FA33',
  'U+1FA34',
  'U+1FA35',
  'U+1FA36',
  'U+1FA37',
  'U+1FA38',
  'U+1FA39',
  'U+1FA3A',
  'U+1FA3B',
  'U+1FA3C',
  'U+1FA3D',
  'U+1FA3E',
  'U+1FA3F',
  'U+1FA40',
  'U+1FA41',
  'U+1FA42',
  'U+1FA43',
  'U+1FA44',
  'U+1FA45',
  'U+1FA46',
  'U+1FA47',
  'U+1FA48',
  'U+1FA49',
  'U+1FA4A',
  'U+1FA4B',
  'U+1FA4C',
  'U+1FA4D',
  'U+1FA4E',
  'U+1FA4F',
  'U+1FA50',
  'U+1FA51',
  'U+1FA52',
  'U+1FA53',
  'U+1FA54',
  'U+1FA55',
  'U+1FA56',
  'U+1FA57',
  'U+1FA58',
  'U+1FA59',
  'U+1FA5A',
  'U+1FA5B',
  'U+1FA5C',
  'U+1FA5D',
  'U+1FA5E',
  'U+1FA5F',
  'U+1FA60',
  'U+1FA61',
  'U+1FA62',
  'U+1FA63',
  'U+1FA64',
  'U+1FA65',
  'U+1FA66',
  'U+1FA67',
  'U+1FA68',
  'U+1FA69',
  'U+1FA6A',
  'U+1FA6B',
  'U+1FA6C',
  'U+1FA6D',
  'U+1FA6E',
  'U+1FA6F',
])

const E69U03_WARN = Object.freeze([
])

const E69U03_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69U03Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69U03In (list, v) {
  for (const x of list) { if (E69U03Lower(x) === v) return true }
  return false
}

function E69U03Classify (tok) {
  const v = E69U03Lower(String(tok == null ? '' : tok))
  if (E69U03In(E69U03_BLOCK, v)) return E69U03_CLASS.BLOCK
  if (E69U03In(E69U03_WARN, v)) return E69U03_CLASS.WARN
  if (E69U03In(E69U03_ALLOW, v)) return E69U03_CLASS.ALLOW
  return E69U03_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69U03_CLASS: E69U03_CLASS,
  E69U03_BLOCK: E69U03_BLOCK,
  E69U03_WARN: E69U03_WARN,
  E69U03_ALLOW: E69U03_ALLOW,
  E69U03Classify: E69U03Classify
})
