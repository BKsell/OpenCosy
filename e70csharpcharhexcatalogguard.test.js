'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70CCHClassify, E70CCH_CLASS, E70CCH_BLOCK, E70CCH_WARN, E70CCH_ALLOW } = require('./e70csharpcharhexcatalogguard.js')

test('E70CCH block classification', () => {
  for (const v of E70CCH_BLOCK) assert.equal(E70CCHClassify(v), E70CCH_CLASS.BLOCK, v)
})

test('E70CCH warn classification', () => {
  for (const v of E70CCH_WARN) assert.equal(E70CCHClassify(v), E70CCH_CLASS.WARN, v)
})

test('E70CCH allow classification', () => {
  for (const v of E70CCH_ALLOW) assert.equal(E70CCHClassify(v), E70CCH_CLASS.ALLOW, v)
})

test('E70CCH unknown classification', () => {
  assert.equal(E70CCHClassify('zzz-not-in-any-e70-catalog-99'), E70CCH_CLASS.UNKNOWN)
})
