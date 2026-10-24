'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68CUUClassify, E68CUU_CLASS, E68CUU_BLOCK, E68CUU_WARN, E68CUU_ALLOW } = require('./e68curlyuuppercatalogguard.js')

test('E68CUU block classification', () => {
  for (const v of E68CUU_BLOCK) assert.equal(E68CUUClassify(v), E68CUU_CLASS.BLOCK, v)
})

test('E68CUU warn classification', () => {
  for (const v of E68CUU_WARN) assert.equal(E68CUUClassify(v), E68CUU_CLASS.WARN, v)
})

test('E68CUU allow classification', () => {
  for (const v of E68CUU_ALLOW) assert.equal(E68CUUClassify(v), E68CUU_CLASS.ALLOW, v)
})

test('E68CUU unknown classification', () => {
  assert.equal(E68CUUClassify('zzz-not-in-any-e68-catalog-77'), E68CUU_CLASS.UNKNOWN)
})
