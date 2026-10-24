'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70PPCClassify, E70PPC_CLASS, E70PPC_BLOCK, E70PPC_WARN, E70PPC_ALLOW } = require('./e70pypercentccatalogguard.js')

test('E70PPC block classification', () => {
  for (const v of E70PPC_BLOCK) assert.equal(E70PPCClassify(v), E70PPC_CLASS.BLOCK, v)
})

test('E70PPC warn classification', () => {
  for (const v of E70PPC_WARN) assert.equal(E70PPCClassify(v), E70PPC_CLASS.WARN, v)
})

test('E70PPC allow classification', () => {
  for (const v of E70PPC_ALLOW) assert.equal(E70PPCClassify(v), E70PPC_CLASS.ALLOW, v)
})

test('E70PPC unknown classification', () => {
  assert.equal(E70PPCClassify('zzz-not-in-any-e70-catalog-99'), E70PPC_CLASS.UNKNOWN)
})
