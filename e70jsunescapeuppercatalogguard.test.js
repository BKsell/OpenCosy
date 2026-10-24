'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70JUUClassify, E70JUU_CLASS, E70JUU_BLOCK, E70JUU_WARN, E70JUU_ALLOW } = require('./e70jsunescapeuppercatalogguard.js')

test('E70JUU block classification', () => {
  for (const v of E70JUU_BLOCK) assert.equal(E70JUUClassify(v), E70JUU_CLASS.BLOCK, v)
})

test('E70JUU warn classification', () => {
  for (const v of E70JUU_WARN) assert.equal(E70JUUClassify(v), E70JUU_CLASS.WARN, v)
})

test('E70JUU allow classification', () => {
  for (const v of E70JUU_ALLOW) assert.equal(E70JUUClassify(v), E70JUU_CLASS.ALLOW, v)
})

test('E70JUU unknown classification', () => {
  assert.equal(E70JUUClassify('zzz-not-in-any-e70-catalog-99'), E70JUU_CLASS.UNKNOWN)
})
