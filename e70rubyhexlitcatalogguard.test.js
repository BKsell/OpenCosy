'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70RHLClassify, E70RHL_CLASS, E70RHL_BLOCK, E70RHL_WARN, E70RHL_ALLOW } = require('./e70rubyhexlitcatalogguard.js')

test('E70RHL block classification', () => {
  for (const v of E70RHL_BLOCK) assert.equal(E70RHLClassify(v), E70RHL_CLASS.BLOCK, v)
})

test('E70RHL warn classification', () => {
  for (const v of E70RHL_WARN) assert.equal(E70RHLClassify(v), E70RHL_CLASS.WARN, v)
})

test('E70RHL allow classification', () => {
  for (const v of E70RHL_ALLOW) assert.equal(E70RHLClassify(v), E70RHL_CLASS.ALLOW, v)
})

test('E70RHL unknown classification', () => {
  assert.equal(E70RHLClassify('zzz-not-in-any-e70-catalog-99'), E70RHL_CLASS.UNKNOWN)
})
