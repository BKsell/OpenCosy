'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68CULClassify, E68CUL_CLASS, E68CUL_BLOCK, E68CUL_WARN, E68CUL_ALLOW } = require('./e68curlyulowercatalogguard.js')

test('E68CUL block classification', () => {
  for (const v of E68CUL_BLOCK) assert.equal(E68CULClassify(v), E68CUL_CLASS.BLOCK, v)
})

test('E68CUL warn classification', () => {
  for (const v of E68CUL_WARN) assert.equal(E68CULClassify(v), E68CUL_CLASS.WARN, v)
})

test('E68CUL allow classification', () => {
  for (const v of E68CUL_ALLOW) assert.equal(E68CULClassify(v), E68CUL_CLASS.ALLOW, v)
})

test('E68CUL unknown classification', () => {
  assert.equal(E68CULClassify('zzz-not-in-any-e68-catalog-77'), E68CUL_CLASS.UNKNOWN)
})
