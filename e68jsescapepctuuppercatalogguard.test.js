'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68JPUClassify, E68JPU_CLASS, E68JPU_BLOCK, E68JPU_WARN, E68JPU_ALLOW } = require('./e68jsescapepctuuppercatalogguard.js')

test('E68JPU block classification', () => {
  for (const v of E68JPU_BLOCK) assert.equal(E68JPUClassify(v), E68JPU_CLASS.BLOCK, v)
})

test('E68JPU warn classification', () => {
  for (const v of E68JPU_WARN) assert.equal(E68JPUClassify(v), E68JPU_CLASS.WARN, v)
})

test('E68JPU allow classification', () => {
  for (const v of E68JPU_ALLOW) assert.equal(E68JPUClassify(v), E68JPU_CLASS.ALLOW, v)
})

test('E68JPU unknown classification', () => {
  assert.equal(E68JPUClassify('zzz-not-in-any-e68-catalog-77'), E68JPU_CLASS.UNKNOWN)
})
