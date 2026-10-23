'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CRJClassify, CRJ_CLASS, CRJ_BLOCK, CRJ_WARN, CRJ_ALLOW } = require('./cspreporturiinsecurecatalogguard.js')

test('CRJ block classification', () => {
  for (const v of CRJ_BLOCK) assert.equal(CRJClassify(v), CRJ_CLASS.BLOCK, v)
})

test('CRJ warn classification', () => {
  for (const v of CRJ_WARN) assert.equal(CRJClassify(v), CRJ_CLASS.WARN, v)
})

test('CRJ allow classification', () => {
  for (const v of CRJ_ALLOW) assert.equal(CRJClassify(v), CRJ_CLASS.ALLOW, v)
})

test('CRJ unknown classification', () => {
  assert.equal(CRJClassify('zzz-not-in-catalog-7'), CRJ_CLASS.UNKNOWN)
})
