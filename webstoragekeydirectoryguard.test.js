'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { WSKClassify, WSK_CLASS, WSK_BLOCK, WSK_WARN, WSK_ALLOW } = require('./webstoragekeydirectoryguard.js')

test('WSK block classification', () => {
  for (const v of WSK_BLOCK) assert.equal(WSKClassify(v), WSK_CLASS.BLOCK, v)
})

test('WSK warn classification', () => {
  for (const v of WSK_WARN) assert.equal(WSKClassify(v), WSK_CLASS.WARN, v)
})

test('WSK allow classification', () => {
  for (const v of WSK_ALLOW) assert.equal(WSKClassify(v), WSK_CLASS.ALLOW, v)
})

test('WSK unknown classification', () => {
  assert.equal(WSKClassify('zzz-not-in-catalog-7'), WSK_CLASS.UNKNOWN)
})
