'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70PPKClassify, E70PPK_CLASS, E70PPK_BLOCK, E70PPK_WARN, E70PPK_ALLOW } = require('./e70perlpackcatalogguard.js')

test('E70PPK block classification', () => {
  for (const v of E70PPK_BLOCK) assert.equal(E70PPKClassify(v), E70PPK_CLASS.BLOCK, v)
})

test('E70PPK warn classification', () => {
  for (const v of E70PPK_WARN) assert.equal(E70PPKClassify(v), E70PPK_CLASS.WARN, v)
})

test('E70PPK allow classification', () => {
  for (const v of E70PPK_ALLOW) assert.equal(E70PPKClassify(v), E70PPK_CLASS.ALLOW, v)
})

test('E70PPK unknown classification', () => {
  assert.equal(E70PPKClassify('zzz-not-in-any-e70-catalog-99'), E70PPK_CLASS.UNKNOWN)
})
