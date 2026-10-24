'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70PSEClassify, E70PSE_CLASS, E70PSE_BLOCK, E70PSE_WARN, E70PSE_ALLOW } = require('./e70pssubexprcatalogguard.js')

test('E70PSE block classification', () => {
  for (const v of E70PSE_BLOCK) assert.equal(E70PSEClassify(v), E70PSE_CLASS.BLOCK, v)
})

test('E70PSE warn classification', () => {
  for (const v of E70PSE_WARN) assert.equal(E70PSEClassify(v), E70PSE_CLASS.WARN, v)
})

test('E70PSE allow classification', () => {
  for (const v of E70PSE_ALLOW) assert.equal(E70PSEClassify(v), E70PSE_CLASS.ALLOW, v)
})

test('E70PSE unknown classification', () => {
  assert.equal(E70PSEClassify('zzz-not-in-any-e70-catalog-99'), E70PSE_CLASS.UNKNOWN)
})
