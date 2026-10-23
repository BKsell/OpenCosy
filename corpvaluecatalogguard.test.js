'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CRVClassify, CRV_CLASS, CRV_BLOCK, CRV_WARN, CRV_ALLOW } = require('./corpvaluecatalogguard.js')

test('CRV block classification', () => {
  for (const v of CRV_BLOCK) assert.equal(CRVClassify(v), CRV_CLASS.BLOCK, v)
})

test('CRV warn classification', () => {
  for (const v of CRV_WARN) assert.equal(CRVClassify(v), CRV_CLASS.WARN, v)
})

test('CRV allow classification', () => {
  for (const v of CRV_ALLOW) assert.equal(CRVClassify(v), CRV_CLASS.ALLOW, v)
})

test('CRV unknown classification', () => {
  assert.equal(CRVClassify('zzz-not-in-catalog-7'), CRV_CLASS.UNKNOWN)
})
