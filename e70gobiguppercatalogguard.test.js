'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70GBUClassify, E70GBU_CLASS, E70GBU_BLOCK, E70GBU_WARN, E70GBU_ALLOW } = require('./e70gobiguppercatalogguard.js')

test('E70GBU block classification', () => {
  for (const v of E70GBU_BLOCK) assert.equal(E70GBUClassify(v), E70GBU_CLASS.BLOCK, v)
})

test('E70GBU warn classification', () => {
  for (const v of E70GBU_WARN) assert.equal(E70GBUClassify(v), E70GBU_CLASS.WARN, v)
})

test('E70GBU allow classification', () => {
  for (const v of E70GBU_ALLOW) assert.equal(E70GBUClassify(v), E70GBU_CLASS.ALLOW, v)
})

test('E70GBU unknown classification', () => {
  assert.equal(E70GBUClassify('zzz-not-in-any-e70-catalog-99'), E70GBU_CLASS.UNKNOWN)
})
