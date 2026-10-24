'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70BAXClassify, E70BAX_CLASS, E70BAX_BLOCK, E70BAX_WARN, E70BAX_ALLOW } = require('./e70bashansixcatalogguard.js')

test('E70BAX block classification', () => {
  for (const v of E70BAX_BLOCK) assert.equal(E70BAXClassify(v), E70BAX_CLASS.BLOCK, v)
})

test('E70BAX warn classification', () => {
  for (const v of E70BAX_WARN) assert.equal(E70BAXClassify(v), E70BAX_CLASS.WARN, v)
})

test('E70BAX allow classification', () => {
  for (const v of E70BAX_ALLOW) assert.equal(E70BAXClassify(v), E70BAX_CLASS.ALLOW, v)
})

test('E70BAX unknown classification', () => {
  assert.equal(E70BAXClassify('zzz-not-in-any-e70-catalog-99'), E70BAX_CLASS.UNKNOWN)
})
