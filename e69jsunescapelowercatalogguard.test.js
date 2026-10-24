'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69JULClassify, E69JUL_CLASS, E69JUL_BLOCK, E69JUL_WARN, E69JUL_ALLOW } = require('./e69jsunescapelowercatalogguard.js')

test('E69JUL block classification', () => {
  for (const v of E69JUL_BLOCK) assert.equal(E69JULClassify(v), E69JUL_CLASS.BLOCK, v)
})

test('E69JUL warn classification', () => {
  for (const v of E69JUL_WARN) assert.equal(E69JULClassify(v), E69JUL_CLASS.WARN, v)
})

test('E69JUL allow classification', () => {
  for (const v of E69JUL_ALLOW) assert.equal(E69JULClassify(v), E69JUL_CLASS.ALLOW, v)
})

test('E69JUL unknown classification', () => {
  assert.equal(E69JULClassify('zzz-not-in-any-e69-catalog-88'), E69JUL_CLASS.UNKNOWN)
})
