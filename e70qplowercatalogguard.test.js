'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70QPLClassify, E70QPL_CLASS, E70QPL_BLOCK, E70QPL_WARN, E70QPL_ALLOW } = require('./e70qplowercatalogguard.js')

test('E70QPL block classification', () => {
  for (const v of E70QPL_BLOCK) assert.equal(E70QPLClassify(v), E70QPL_CLASS.BLOCK, v)
})

test('E70QPL warn classification', () => {
  for (const v of E70QPL_WARN) assert.equal(E70QPLClassify(v), E70QPL_CLASS.WARN, v)
})

test('E70QPL allow classification', () => {
  for (const v of E70QPL_ALLOW) assert.equal(E70QPLClassify(v), E70QPL_CLASS.ALLOW, v)
})

test('E70QPL unknown classification', () => {
  assert.equal(E70QPLClassify('zzz-not-in-any-e70-catalog-99'), E70QPL_CLASS.UNKNOWN)
})
