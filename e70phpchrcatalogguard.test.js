'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70PHCClassify, E70PHC_CLASS, E70PHC_BLOCK, E70PHC_WARN, E70PHC_ALLOW } = require('./e70phpchrcatalogguard.js')

test('E70PHC block classification', () => {
  for (const v of E70PHC_BLOCK) assert.equal(E70PHCClassify(v), E70PHC_CLASS.BLOCK, v)
})

test('E70PHC warn classification', () => {
  for (const v of E70PHC_WARN) assert.equal(E70PHCClassify(v), E70PHC_CLASS.WARN, v)
})

test('E70PHC allow classification', () => {
  for (const v of E70PHC_ALLOW) assert.equal(E70PHCClassify(v), E70PHC_CLASS.ALLOW, v)
})

test('E70PHC unknown classification', () => {
  assert.equal(E70PHCClassify('zzz-not-in-any-e70-catalog-99'), E70PHC_CLASS.UNKNOWN)
})
