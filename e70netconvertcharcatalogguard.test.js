'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70NCCClassify, E70NCC_CLASS, E70NCC_BLOCK, E70NCC_WARN, E70NCC_ALLOW } = require('./e70netconvertcharcatalogguard.js')

test('E70NCC block classification', () => {
  for (const v of E70NCC_BLOCK) assert.equal(E70NCCClassify(v), E70NCC_CLASS.BLOCK, v)
})

test('E70NCC warn classification', () => {
  for (const v of E70NCC_WARN) assert.equal(E70NCCClassify(v), E70NCC_CLASS.WARN, v)
})

test('E70NCC allow classification', () => {
  for (const v of E70NCC_ALLOW) assert.equal(E70NCCClassify(v), E70NCC_CLASS.ALLOW, v)
})

test('E70NCC unknown classification', () => {
  assert.equal(E70NCCClassify('zzz-not-in-any-e70-catalog-99'), E70NCC_CLASS.UNKNOWN)
})
