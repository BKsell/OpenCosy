'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70APCClassify, E70APC_CLASS, E70APC_BLOCK, E70APC_WARN, E70APC_ALLOW } = require('./e70aspchrcatalogguard.js')

test('E70APC block classification', () => {
  for (const v of E70APC_BLOCK) assert.equal(E70APCClassify(v), E70APC_CLASS.BLOCK, v)
})

test('E70APC warn classification', () => {
  for (const v of E70APC_WARN) assert.equal(E70APCClassify(v), E70APC_CLASS.WARN, v)
})

test('E70APC allow classification', () => {
  for (const v of E70APC_ALLOW) assert.equal(E70APCClassify(v), E70APC_CLASS.ALLOW, v)
})

test('E70APC unknown classification', () => {
  assert.equal(E70APCClassify('zzz-not-in-any-e70-catalog-99'), E70APC_CLASS.UNKNOWN)
})
