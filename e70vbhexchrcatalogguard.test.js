'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70VHCClassify, E70VHC_CLASS, E70VHC_BLOCK, E70VHC_WARN, E70VHC_ALLOW } = require('./e70vbhexchrcatalogguard.js')

test('E70VHC block classification', () => {
  for (const v of E70VHC_BLOCK) assert.equal(E70VHCClassify(v), E70VHC_CLASS.BLOCK, v)
})

test('E70VHC warn classification', () => {
  for (const v of E70VHC_WARN) assert.equal(E70VHCClassify(v), E70VHC_CLASS.WARN, v)
})

test('E70VHC allow classification', () => {
  for (const v of E70VHC_ALLOW) assert.equal(E70VHCClassify(v), E70VHC_CLASS.ALLOW, v)
})

test('E70VHC unknown classification', () => {
  assert.equal(E70VHCClassify('zzz-not-in-any-e70-catalog-99'), E70VHC_CLASS.UNKNOWN)
})
