'use strict'

// hightresstimingcatalogguard.js —— 高精度计时原语目录。
//
// 威胁模型：
//   performance.now 高精度、SharedArrayBuffer+Atomics 构成隐蔽计时通道，
//   敏感上下文应降低时钟分辨率。纯字符查表，不用正则。

const TMG_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const TMG_BLOCK = Object.freeze([
  'performance.now-highres',
  'sharedarraybuffer-timing',
  'atomics.wait',
  'crossorigin-isolation-timing',
])

const TMG_WARN = Object.freeze([
  'date.now-loop',
])

const TMG_ALLOW = Object.freeze([
  'reduced-resolution',
])

function TMGLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function TMGIn (list, v) {
  for (const x of list) { if (TMGLower(x) === v) return true }
  return false
}

function TMGClassify (tok) {
  const v = TMGLower(String(tok == null ? '' : tok).trim())
  if (TMGIn(TMG_BLOCK, v)) return TMG_CLASS.BLOCK
  if (TMGIn(TMG_WARN, v)) return TMG_CLASS.WARN
  if (TMGIn(TMG_ALLOW, v)) return TMG_CLASS.ALLOW
  return TMG_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  TMG_CLASS: TMG_CLASS,
  TMG_BLOCK: TMG_BLOCK,
  TMG_WARN: TMG_WARN,
  TMG_ALLOW: TMG_ALLOW,
  TMGClassify: TMGClassify
})
