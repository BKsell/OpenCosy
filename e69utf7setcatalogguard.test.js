'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69U7SClassify, E69U7S_CLASS, E69U7S_BLOCK, E69U7S_WARN, E69U7S_ALLOW } = require('./e69utf7setcatalogguard.js')

test('E69U7S block classification', () => {
  for (const v of E69U7S_BLOCK) assert.equal(E69U7SClassify(v), E69U7S_CLASS.BLOCK, v)
})

test('E69U7S warn classification', () => {
  for (const v of E69U7S_WARN) assert.equal(E69U7SClassify(v), E69U7S_CLASS.WARN, v)
})

test('E69U7S allow classification', () => {
  for (const v of E69U7S_ALLOW) assert.equal(E69U7SClassify(v), E69U7S_CLASS.ALLOW, v)
})

test('E69U7S unknown classification', () => {
  assert.equal(E69U7SClassify('zzz-not-in-any-e69-catalog-88'), E69U7S_CLASS.UNKNOWN)
})
