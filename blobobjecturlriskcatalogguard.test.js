'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { BLUClassify, BLU_CLASS, BLU_BLOCK, BLU_WARN, BLU_ALLOW } = require('./blobobjecturlriskcatalogguard.js')

test('BLU block classification', () => {
  for (const v of BLU_BLOCK) assert.equal(BLUClassify(v), BLU_CLASS.BLOCK, v)
})

test('BLU warn classification', () => {
  for (const v of BLU_WARN) assert.equal(BLUClassify(v), BLU_CLASS.WARN, v)
})

test('BLU allow classification', () => {
  for (const v of BLU_ALLOW) assert.equal(BLUClassify(v), BLU_CLASS.ALLOW, v)
})

test('BLU unknown classification', () => {
  assert.equal(BLUClassify('zzz-not-in-catalog-7'), BLU_CLASS.UNKNOWN)
})
