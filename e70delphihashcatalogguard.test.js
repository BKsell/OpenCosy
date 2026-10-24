'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70DLHClassify, E70DLH_CLASS, E70DLH_BLOCK, E70DLH_WARN, E70DLH_ALLOW } = require('./e70delphihashcatalogguard.js')

test('E70DLH block classification', () => {
  for (const v of E70DLH_BLOCK) assert.equal(E70DLHClassify(v), E70DLH_CLASS.BLOCK, v)
})

test('E70DLH warn classification', () => {
  for (const v of E70DLH_WARN) assert.equal(E70DLHClassify(v), E70DLH_CLASS.WARN, v)
})

test('E70DLH allow classification', () => {
  for (const v of E70DLH_ALLOW) assert.equal(E70DLHClassify(v), E70DLH_CLASS.ALLOW, v)
})

test('E70DLH unknown classification', () => {
  assert.equal(E70DLHClassify('zzz-not-in-any-e70-catalog-99'), E70DLH_CLASS.UNKNOWN)
})
