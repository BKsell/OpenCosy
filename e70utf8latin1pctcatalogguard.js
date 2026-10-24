'use strict'

// e70utf8latin1pctcatalogguard.js —— Latin-1 双字节 UTF-8 百分号目录。
//
// 威胁模型：
//   0x80-0xFF 的字符编码为 %C2%80..%C3%BF，规范化前后字节形态不同，可利用解码差异绕过单字节匹配，
//   危险码位编码应阻断。纯字符查表，不用正则。

const E70U8L_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70U8L_BLOCK = Object.freeze([
  '%C2%80',
  '%C2%81',
  '%C2%82',
  '%C2%83',
  '%C2%84',
  '%C2%85',
  '%C2%86',
  '%C2%87',
  '%C2%88',
  '%C2%89',
  '%C2%8A',
  '%C2%8B',
  '%C2%8C',
  '%C2%8D',
  '%C2%8E',
  '%C2%8F',
  '%C2%90',
  '%C2%91',
  '%C2%92',
  '%C2%93',
  '%C2%94',
  '%C2%95',
  '%C2%96',
  '%C2%97',
  '%C2%98',
  '%C2%99',
  '%C2%9A',
  '%C2%9B',
  '%C2%9C',
  '%C2%9D',
  '%C2%9E',
  '%C2%9F',
  '%C2%A0',
  '%C2%AD',
])

const E70U8L_WARN = Object.freeze([
  '%C2%A1',
  '%C2%A2',
  '%C2%A3',
  '%C2%A4',
  '%C2%A5',
  '%C2%A6',
  '%C2%A7',
  '%C2%A8',
  '%C2%A9',
  '%C2%AA',
  '%C2%AB',
  '%C2%AC',
  '%C2%AE',
  '%C2%AF',
  '%C2%B0',
  '%C2%B1',
  '%C2%B2',
  '%C2%B3',
  '%C2%B4',
  '%C2%B5',
  '%C2%B6',
  '%C2%B7',
  '%C2%B8',
  '%C2%B9',
  '%C2%BA',
  '%C2%BB',
  '%C2%BC',
  '%C2%BD',
  '%C2%BE',
  '%C2%BF',
  '%C3%80',
  '%C3%81',
  '%C3%82',
  '%C3%83',
  '%C3%84',
  '%C3%85',
  '%C3%86',
  '%C3%87',
  '%C3%88',
  '%C3%89',
  '%C3%8A',
  '%C3%8B',
  '%C3%8C',
  '%C3%8D',
  '%C3%8E',
  '%C3%8F',
  '%C3%90',
  '%C3%91',
  '%C3%92',
  '%C3%93',
  '%C3%94',
  '%C3%95',
  '%C3%96',
  '%C3%97',
  '%C3%98',
  '%C3%99',
  '%C3%9A',
  '%C3%9B',
  '%C3%9C',
  '%C3%9D',
  '%C3%9E',
  '%C3%9F',
  '%C3%A0',
  '%C3%A1',
  '%C3%A2',
  '%C3%A3',
  '%C3%A4',
  '%C3%A5',
  '%C3%A6',
  '%C3%A7',
  '%C3%A8',
  '%C3%A9',
  '%C3%AA',
  '%C3%AB',
  '%C3%AC',
  '%C3%AD',
  '%C3%AE',
  '%C3%AF',
  '%C3%B0',
  '%C3%B1',
  '%C3%B2',
  '%C3%B3',
  '%C3%B4',
  '%C3%B5',
  '%C3%B6',
  '%C3%B7',
  '%C3%B8',
  '%C3%B9',
  '%C3%BA',
  '%C3%BB',
  '%C3%BC',
  '%C3%BD',
  '%C3%BE',
  '%C3%BF',
])

const E70U8L_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70U8LLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70U8LIn (list, v) {
  for (const x of list) { if (E70U8LLower(x) === v) return true }
  return false
}

function E70U8LClassify (tok) {
  const v = E70U8LLower(String(tok == null ? '' : tok))
  if (E70U8LIn(E70U8L_BLOCK, v)) return E70U8L_CLASS.BLOCK
  if (E70U8LIn(E70U8L_WARN, v)) return E70U8L_CLASS.WARN
  if (E70U8LIn(E70U8L_ALLOW, v)) return E70U8L_CLASS.ALLOW
  return E70U8L_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70U8L_CLASS: E70U8L_CLASS,
  E70U8L_BLOCK: E70U8L_BLOCK,
  E70U8L_WARN: E70U8L_WARN,
  E70U8L_ALLOW: E70U8L_ALLOW,
  E70U8LClassify: E70U8LClassify
})
