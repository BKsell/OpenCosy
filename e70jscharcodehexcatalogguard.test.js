'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70JCHClassify, E70JCH_CLASS, E70JCH_BLOCK, E70JCH_WARN, E70JCH_ALLOW } = require('./e70jscharcodehexcatalogguard.js')

test('E70JCH block classification', () => {
  for (const v of E70JCH_BLOCK) assert.equal(E70JCHClassify(v), E70JCH_CLASS.BLOCK, v)
})

test('E70JCH warn classification', () => {
  for (const v of E70JCH_WARN) assert.equal(E70JCHClassify(v), E70JCH_CLASS.WARN, v)
})

test('E70JCH allow classification', () => {
  for (const v of E70JCH_ALLOW) assert.equal(E70JCHClassify(v), E70JCH_CLASS.ALLOW, v)
})

test('E70JCH unknown classification', () => {
  assert.equal(E70JCHClassify('zzz-not-in-any-e70-catalog-99'), E70JCH_CLASS.UNKNOWN)
})
