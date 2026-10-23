'use strict'

// fontenumerationcatalogguard.js —— 字体枚举侧信道目录。
//
// 威胁模型：
//   measureText 探测字体列表或 document.fonts.check 可指纹系统环境，
//   Local Fonts 还能读取字体元数据。纯字符查表，不用正则。

const FEN_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const FEN_BLOCK = Object.freeze([
  'measuretext-fontlist',
  'fonts.check-enumerate',
  'querylocalfonts',
  'font-metric-probe',
])

const FEN_WARN = Object.freeze([
  'document.fonts-load',
])

const FEN_ALLOW = Object.freeze([
  'generic-fonts',
])

function FENLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function FENIn (list, v) {
  for (const x of list) { if (FENLower(x) === v) return true }
  return false
}

function FENClassify (tok) {
  const v = FENLower(String(tok == null ? '' : tok).trim())
  if (FENIn(FEN_BLOCK, v)) return FEN_CLASS.BLOCK
  if (FENIn(FEN_WARN, v)) return FEN_CLASS.WARN
  if (FENIn(FEN_ALLOW, v)) return FEN_CLASS.ALLOW
  return FEN_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  FEN_CLASS: FEN_CLASS,
  FEN_BLOCK: FEN_BLOCK,
  FEN_WARN: FEN_WARN,
  FEN_ALLOW: FEN_ALLOW,
  FENClassify: FENClassify
})
