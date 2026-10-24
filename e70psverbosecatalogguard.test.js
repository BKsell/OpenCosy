'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70PSVClassify, E70PSV_CLASS, E70PSV_BLOCK, E70PSV_WARN, E70PSV_ALLOW } = require('./e70psverbosecatalogguard.js')

test('E70PSV block classification', () => {
  for (const v of E70PSV_BLOCK) assert.equal(E70PSVClassify(v), E70PSV_CLASS.BLOCK, v)
})

test('E70PSV warn classification', () => {
  for (const v of E70PSV_WARN) assert.equal(E70PSVClassify(v), E70PSV_CLASS.WARN, v)
})

test('E70PSV allow classification', () => {
  for (const v of E70PSV_ALLOW) assert.equal(E70PSVClassify(v), E70PSV_CLASS.ALLOW, v)
})

test('E70PSV unknown classification', () => {
  assert.equal(E70PSVClassify('zzz-not-in-any-e70-catalog-99'), E70PSV_CLASS.UNKNOWN)
})
