'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70PUCClassify, E70PUC_CLASS, E70PUC_BLOCK, E70PUC_WARN, E70PUC_ALLOW } = require('./e70py2unichrcatalogguard.js')

test('E70PUC block classification', () => {
  for (const v of E70PUC_BLOCK) assert.equal(E70PUCClassify(v), E70PUC_CLASS.BLOCK, v)
})

test('E70PUC warn classification', () => {
  for (const v of E70PUC_WARN) assert.equal(E70PUCClassify(v), E70PUC_CLASS.WARN, v)
})

test('E70PUC allow classification', () => {
  for (const v of E70PUC_ALLOW) assert.equal(E70PUCClassify(v), E70PUC_CLASS.ALLOW, v)
})

test('E70PUC unknown classification', () => {
  assert.equal(E70PUCClassify('zzz-not-in-any-e70-catalog-99'), E70PUC_CLASS.UNKNOWN)
})
