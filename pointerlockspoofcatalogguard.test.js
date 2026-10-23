'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { PTLClassify, PTL_CLASS, PTL_BLOCK, PTL_WARN, PTL_ALLOW } = require('./pointerlockspoofcatalogguard.js')

test('PTL block classification', () => {
  for (const v of PTL_BLOCK) assert.equal(PTLClassify(v), PTL_CLASS.BLOCK, v)
})

test('PTL warn classification', () => {
  for (const v of PTL_WARN) assert.equal(PTLClassify(v), PTL_CLASS.WARN, v)
})

test('PTL allow classification', () => {
  for (const v of PTL_ALLOW) assert.equal(PTLClassify(v), PTL_CLASS.ALLOW, v)
})

test('PTL unknown classification', () => {
  assert.equal(PTLClassify('zzz-not-in-catalog-7'), PTL_CLASS.UNKNOWN)
})
