'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68JPLClassify, E68JPL_CLASS, E68JPL_BLOCK, E68JPL_WARN, E68JPL_ALLOW } = require('./e68jsescapepctulowercatalogguard.js')

test('E68JPL block classification', () => {
  for (const v of E68JPL_BLOCK) assert.equal(E68JPLClassify(v), E68JPL_CLASS.BLOCK, v)
})

test('E68JPL warn classification', () => {
  for (const v of E68JPL_WARN) assert.equal(E68JPLClassify(v), E68JPL_CLASS.WARN, v)
})

test('E68JPL allow classification', () => {
  for (const v of E68JPL_ALLOW) assert.equal(E68JPLClassify(v), E68JPL_CLASS.ALLOW, v)
})

test('E68JPL unknown classification', () => {
  assert.equal(E68JPLClassify('zzz-not-in-any-e68-catalog-77'), E68JPL_CLASS.UNKNOWN)
})
