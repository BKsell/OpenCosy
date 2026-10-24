'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69H6PClassify, E69H6P_CLASS, E69H6P_BLOCK, E69H6P_WARN, E69H6P_ALLOW } = require('./e69htmlhex6padcatalogguard.js')

test('E69H6P block classification', () => {
  for (const v of E69H6P_BLOCK) assert.equal(E69H6PClassify(v), E69H6P_CLASS.BLOCK, v)
})

test('E69H6P warn classification', () => {
  for (const v of E69H6P_WARN) assert.equal(E69H6PClassify(v), E69H6P_CLASS.WARN, v)
})

test('E69H6P allow classification', () => {
  for (const v of E69H6P_ALLOW) assert.equal(E69H6PClassify(v), E69H6P_CLASS.ALLOW, v)
})

test('E69H6P unknown classification', () => {
  assert.equal(E69H6PClassify('zzz-not-in-any-e69-catalog-88'), E69H6P_CLASS.UNKNOWN)
})
