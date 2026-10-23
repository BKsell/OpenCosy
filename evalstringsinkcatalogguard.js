'use strict'

// evalstringsinkcatalogguard.js —— 动态代码执行 Sink 目录。
//
// 威胁模型：
//   eval/Function 构造器、字符串形式 setTimeout/setInterval 会执行不可信代码，
//   应传函数引用并解析数据用 JSON.parse。纯字符查表，不用正则。

const EVL_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const EVL_BLOCK = Object.freeze([
  'eval',
  'function',
  'settimeout-string',
  'setinterval-string',
])

const EVL_WARN = Object.freeze([
  'new-function',
  'generatorscript',
])

const EVL_ALLOW = Object.freeze([
  'json.parse',
  'function-reference',
])

function EVLLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function EVLIn (list, v) {
  for (const x of list) { if (EVLLower(x) === v) return true }
  return false
}

function EVLClassify (tok) {
  const v = EVLLower(String(tok == null ? '' : tok).trim())
  if (EVLIn(EVL_BLOCK, v)) return EVL_CLASS.BLOCK
  if (EVLIn(EVL_WARN, v)) return EVL_CLASS.WARN
  if (EVLIn(EVL_ALLOW, v)) return EVL_CLASS.ALLOW
  return EVL_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  EVL_CLASS: EVL_CLASS,
  EVL_BLOCK: EVL_BLOCK,
  EVL_WARN: EVL_WARN,
  EVL_ALLOW: EVL_ALLOW,
  EVLClassify: EVLClassify
})
