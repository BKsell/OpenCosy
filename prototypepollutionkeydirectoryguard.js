'use strict'

// prototypepollutionkeydirectoryguard.js —— 原型链污染键目录。
//
// 威胁模型：
//   __proto__/prototype/constructor 及嵌套 polluted 键可触发原型链污染。本目录收录危险路径键，纯字符查表，不用正则。

const PPK_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const PPK_BLOCK = Object.freeze([
  '__proto__',
  'constructor',
  'prototype',
  '__defineGetter__',
  '__defineSetter__',
  '__lookupGetter__',
  '__lookupSetter__',
])

const PPK_WARN = Object.freeze([
  'polluted',
  'isPrototypeOf',
  'deep',
  'merge',
  'extend',
  'assign',
  'clone',
  'copy',
  'defaults',
  'mixin',
  'setPath',
  'setIn',
  'recursive',
  'nested',
  'dot',
  'bracket',
  'object',
  'Object',
  'Object.prototype',
  'Array.prototype',
  'Function.prototype',
])

const PPK_ALLOW = Object.freeze([
  'hasOwnProperty',
  'Object.create',
  'Object.freeze',
  'Object.seal',
  'Object.keys',
  'Object.entries',
  'map',
  'filter',
  'reduce',
  'freeze',
  'seal',
])

function PPKLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function PPKIn (list, v) {
  for (const x of list) { if (PPKLower(x) === v) return true }
  return false
}

function PPKClassify (tok) {
  const v = PPKLower(String(tok == null ? '' : tok).trim())
  if (PPKIn(PPK_BLOCK, v)) return PPK_CLASS.BLOCK
  if (PPKIn(PPK_WARN, v)) return PPK_CLASS.WARN
  if (PPKIn(PPK_ALLOW, v)) return PPK_CLASS.ALLOW
  return PPK_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  PPK_CLASS: PPK_CLASS,
  PPK_BLOCK: PPK_BLOCK,
  PPK_WARN: PPK_WARN,
  PPK_ALLOW: PPK_ALLOW,
  PPKClassify: PPKClassify
})
