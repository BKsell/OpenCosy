'use strict'

// cssfunctiondirectoryguard.js —— CSS 函数风险分级目录。
//
// 威胁模型：
//   url()/expression()/element()/javascript 伪函数可外连或执行，attr()/var()/calc() 等相对安全。
//   纯字符查表（不含括号），不用正则。

const CFN_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const CFN_BLOCK = Object.freeze([
  'url',
  'expression',
  'element',
  'javascript',
  'vbscript',
  'behavior',
  'binding',
  '-moz-binding',
])

const CFN_WARN = Object.freeze([
  'image',
  'image-set',
  'cross-fade',
  'paint',
  'var',
  'env',
  'counter',
  'counters',
  'linear-gradient',
  'radial-gradient',
  'conic-gradient',
  'repeating-linear-gradient',
  'repeating-radial-gradient',
  'repeating-conic-gradient',
  'device-cmyk',
  'filter',
])

const CFN_ALLOW = Object.freeze([
  'calc',
  'min',
  'max',
  'clamp',
  'attr',
  'fit-content',
  'minmax',
  'repeat',
  'cubic-bezier',
  'steps',
  'rgb',
  'rgba',
  'hsl',
  'hsla',
  'hwb',
  'lab',
  'lch',
  'oklab',
  'oklch',
  'color',
  'color-mix',
  'color-contrast',
  'scale',
  'rotate',
  'translate',
  'skew',
  'matrix',
  'matrix3d',
  'perspective',
  'blur',
  'brightness',
  'contrast',
  'drop-shadow',
  'grayscale',
  'hue-rotate',
  'invert',
  'saturate',
  'sepia',
  'circle',
  'ellipse',
  'polygon',
  'inset',
  'path',
  'translateX',
  'translateY',
  'translateZ',
  'translate3d',
  'scaleX',
  'scaleY',
  'scaleZ',
  'scale3d',
  'rotateX',
  'rotateY',
  'rotateZ',
  'rotate3d',
  'skewX',
  'skewY',
  'not',
  'local',
  'symbols',
  'leader',
  'target',
  'target-counter',
  'target-text',
  'format',
  'running',
  'annotation',
  'content',
  'toggle',
])

function CFNLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function CFNIn (list, v) {
  for (const x of list) { if (CFNLower(x) === v) return true }
  return false
}

function CFNClassify (tok) {
  const v = CFNLower(String(tok == null ? '' : tok).trim())
  if (CFNIn(CFN_BLOCK, v)) return CFN_CLASS.BLOCK
  if (CFNIn(CFN_WARN, v)) return CFN_CLASS.WARN
  if (CFNIn(CFN_ALLOW, v)) return CFN_CLASS.ALLOW
  return CFN_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  CFN_CLASS: CFN_CLASS,
  CFN_BLOCK: CFN_BLOCK,
  CFN_WARN: CFN_WARN,
  CFN_ALLOW: CFN_ALLOW,
  CFNClassify: CFNClassify
})
