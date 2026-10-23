'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { SPJClassify, SPJ_CLASS, SPJ_BLOCK, SPJ_WARN, SPJ_ALLOW } = require('./speechcontinuouscatalogguard.js')

test('SPJ block classification', () => {
  for (const v of SPJ_BLOCK) assert.equal(SPJClassify(v), SPJ_CLASS.BLOCK, v)
})

test('SPJ warn classification', () => {
  for (const v of SPJ_WARN) assert.equal(SPJClassify(v), SPJ_CLASS.WARN, v)
})

test('SPJ allow classification', () => {
  for (const v of SPJ_ALLOW) assert.equal(SPJClassify(v), SPJ_CLASS.ALLOW, v)
})

test('SPJ unknown classification', () => {
  assert.equal(SPJClassify('zzz-not-in-catalog-7'), SPJ_CLASS.UNKNOWN)
})
