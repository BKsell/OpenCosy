'use strict'

// speechcontinuouscatalogguard.js —— 语音持续识别目录。
//
// 威胁模型：
//   SpeechRecognition continuous=true 持续监听环境语音，synthesis 朗读页面注入文本可钓鱼，
//   应显式开始/停止。纯字符查表，不用正则。

const SPJ_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const SPJ_BLOCK = Object.freeze([
  'continuous-true',
  'speechrecognition-background',
  'utterance-page-input',
])

const SPJ_WARN = Object.freeze([
  'interim-results',
])

const SPJ_ALLOW = Object.freeze([
  'explicit-toggle',
])

function SPJLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function SPJIn (list, v) {
  for (const x of list) { if (SPJLower(x) === v) return true }
  return false
}

function SPJClassify (tok) {
  const v = SPJLower(String(tok == null ? '' : tok).trim())
  if (SPJIn(SPJ_BLOCK, v)) return SPJ_CLASS.BLOCK
  if (SPJIn(SPJ_WARN, v)) return SPJ_CLASS.WARN
  if (SPJIn(SPJ_ALLOW, v)) return SPJ_CLASS.ALLOW
  return SPJ_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  SPJ_CLASS: SPJ_CLASS,
  SPJ_BLOCK: SPJ_BLOCK,
  SPJ_WARN: SPJ_WARN,
  SPJ_ALLOW: SPJ_ALLOW,
  SPJClassify: SPJClassify
})
