'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70VCWClassify, E70VCW_CLASS, E70VCW_BLOCK, E70VCW_WARN, E70VCW_ALLOW } = require('./e70vbchrwcatalogguard.js')

test('E70VCW block classification', () => {
  for (const v of E70VCW_BLOCK) assert.equal(E70VCWClassify(v), E70VCW_CLASS.BLOCK, v)
})

test('E70VCW warn classification', () => {
  for (const v of E70VCW_WARN) assert.equal(E70VCWClassify(v), E70VCW_CLASS.WARN, v)
})

test('E70VCW allow classification', () => {
  for (const v of E70VCW_ALLOW) assert.equal(E70VCWClassify(v), E70VCW_CLASS.ALLOW, v)
})

test('E70VCW unknown classification', () => {
  assert.equal(E70VCWClassify('zzz-not-in-any-e70-catalog-99'), E70VCW_CLASS.UNKNOWN)
})
