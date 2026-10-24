'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69PCHClassify, E69PCH_CLASS, E69PCH_BLOCK, E69PCH_WARN, E69PCH_ALLOW } = require('./e69pscharhexcatalogguard.js')

test('E69PCH block classification', () => {
  for (const v of E69PCH_BLOCK) assert.equal(E69PCHClassify(v), E69PCH_CLASS.BLOCK, v)
})

test('E69PCH warn classification', () => {
  for (const v of E69PCH_WARN) assert.equal(E69PCHClassify(v), E69PCH_CLASS.WARN, v)
})

test('E69PCH allow classification', () => {
  for (const v of E69PCH_ALLOW) assert.equal(E69PCHClassify(v), E69PCH_CLASS.ALLOW, v)
})

test('E69PCH unknown classification', () => {
  assert.equal(E69PCHClassify('zzz-not-in-any-e69-catalog-88'), E69PCH_CLASS.UNKNOWN)
})
