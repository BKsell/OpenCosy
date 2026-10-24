'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68HXLClassify, E68HXL_CLASS, E68HXL_BLOCK, E68HXL_WARN, E68HXL_ALLOW } = require('./e68htmlhexlowercatalogguard.js')

test('E68HXL block classification', () => {
  for (const v of E68HXL_BLOCK) assert.equal(E68HXLClassify(v), E68HXL_CLASS.BLOCK, v)
})

test('E68HXL warn classification', () => {
  for (const v of E68HXL_WARN) assert.equal(E68HXLClassify(v), E68HXL_CLASS.WARN, v)
})

test('E68HXL allow classification', () => {
  for (const v of E68HXL_ALLOW) assert.equal(E68HXLClassify(v), E68HXL_CLASS.ALLOW, v)
})

test('E68HXL unknown classification', () => {
  assert.equal(E68HXLClassify('zzz-not-in-any-e68-catalog-77'), E68HXL_CLASS.UNKNOWN)
})
