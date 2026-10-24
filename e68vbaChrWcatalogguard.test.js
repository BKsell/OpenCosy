'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68VBWClassify, E68VBW_CLASS, E68VBW_BLOCK, E68VBW_WARN, E68VBW_ALLOW } = require('./e68vbaChrWcatalogguard.js')

test('E68VBW block classification', () => {
  for (const v of E68VBW_BLOCK) assert.equal(E68VBWClassify(v), E68VBW_CLASS.BLOCK, v)
})

test('E68VBW warn classification', () => {
  for (const v of E68VBW_WARN) assert.equal(E68VBWClassify(v), E68VBW_CLASS.WARN, v)
})

test('E68VBW allow classification', () => {
  for (const v of E68VBW_ALLOW) assert.equal(E68VBWClassify(v), E68VBW_CLASS.ALLOW, v)
})

test('E68VBW unknown classification', () => {
  assert.equal(E68VBWClassify('zzz-not-in-any-e68-catalog-77'), E68VBW_CLASS.UNKNOWN)
})
