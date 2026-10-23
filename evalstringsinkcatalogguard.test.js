'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { EVLClassify, EVL_CLASS, EVL_BLOCK, EVL_WARN, EVL_ALLOW } = require('./evalstringsinkcatalogguard.js')

test('EVL block classification', () => {
  for (const v of EVL_BLOCK) assert.equal(EVLClassify(v), EVL_CLASS.BLOCK, v)
})

test('EVL warn classification', () => {
  for (const v of EVL_WARN) assert.equal(EVLClassify(v), EVL_CLASS.WARN, v)
})

test('EVL allow classification', () => {
  for (const v of EVL_ALLOW) assert.equal(EVLClassify(v), EVL_CLASS.ALLOW, v)
})

test('EVL unknown classification', () => {
  assert.equal(EVLClassify('zzz-not-in-catalog-7'), EVL_CLASS.UNKNOWN)
})
