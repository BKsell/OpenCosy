'use strict'

// dangerousglobalcatalogguard.js —— 危险 JS 全局/反射入口目录。
//
// 威胁模型：
//   constructor/__proto__/Reflect/Proxy/Function/generator/import() 等反射与代码生成入口是注入与污染高发面。
//   纯字符查表，不用正则。

const DJG_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const DJG_BLOCK = Object.freeze([
  'eval',
  'Function',
  'AsyncFunction',
  'GeneratorFunction',
  'AsyncGeneratorFunction',
  'constructor',
  '__proto__',
  '__defineGetter__',
  '__defineSetter__',
  '__lookupGetter__',
  '__lookupSetter__',
  'import',
  'importScripts',
  'Reflect',
  'Proxy',
  'Reflect.construct',
  'Reflect.apply',
  'document.write',
  'setTimeout',
  'setInterval',
  'setImmediate',
  'execScript',
])

const DJG_WARN = Object.freeze([
  'globalThis',
  'window',
  'self',
  'global',
  'top',
  'parent',
  'frames',
  'Reflect.get',
  'Reflect.set',
  'Reflect.defineProperty',
  'Object.defineProperty',
  'Object.defineProperties',
  'Object.create',
  'new',
  'bind',
  'call',
  'apply',
  'arguments',
  'caller',
  'prototype',
  '__esModule',
  'Symbol.hasInstance',
  'Symbol.toPrimitive',
  'Symbol.iterator',
  'Symbol.asyncIterator',
  'Promise',
  'async',
  'await',
  'yield',
  'generator',
])

const DJG_ALLOW = Object.freeze([
  'JSON',
  'Math',
  'Number',
  'String',
  'Boolean',
  'Array',
  'Map',
  'Set',
  'WeakMap',
  'WeakSet',
  'Date',
  'RegExp',
  'Error',
  'TypeError',
  'Symbol',
  'parseInt',
  'parseFloat',
  'isNaN',
  'isFinite',
  'Object.keys',
  'Object.values',
  'Object.entries',
  'Object.freeze',
  'Object.seal',
  'Promise.resolve',
  'Promise.all',
])

function DJGLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function DJGIn (list, v) {
  for (const x of list) { if (DJGLower(x) === v) return true }
  return false
}

function DJGClassify (tok) {
  const v = DJGLower(String(tok == null ? '' : tok).trim())
  if (DJGIn(DJG_BLOCK, v)) return DJG_CLASS.BLOCK
  if (DJGIn(DJG_WARN, v)) return DJG_CLASS.WARN
  if (DJGIn(DJG_ALLOW, v)) return DJG_CLASS.ALLOW
  return DJG_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  DJG_CLASS: DJG_CLASS,
  DJG_BLOCK: DJG_BLOCK,
  DJG_WARN: DJG_WARN,
  DJG_ALLOW: DJG_ALLOW,
  DJGClassify: DJGClassify
})
