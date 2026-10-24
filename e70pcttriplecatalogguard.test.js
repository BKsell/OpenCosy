'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70PTRClassify, E70PTR_CLASS, E70PTR_BLOCK, E70PTR_WARN, E70PTR_ALLOW } = require('./e70pcttriplecatalogguard.js')

test('E70PTR block classification', () => {
  for (const v of E70PTR_BLOCK) assert.equal(E70PTRClassify(v), E70PTR_CLASS.BLOCK, v)
})

test('E70PTR warn classification', () => {
  for (const v of E70PTR_WARN) assert.equal(E70PTRClassify(v), E70PTR_CLASS.WARN, v)
})

test('E70PTR allow classification', () => {
  for (const v of E70PTR_ALLOW) assert.equal(E70PTRClassify(v), E70PTR_CLASS.ALLOW, v)
})

test('E70PTR unknown classification', () => {
  assert.equal(E70PTRClassify('zzz-not-in-any-e70-catalog-99'), E70PTR_CLASS.UNKNOWN)
})
