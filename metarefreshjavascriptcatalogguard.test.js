'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { MRFClassify, MRF_CLASS, MRF_BLOCK, MRF_WARN, MRF_ALLOW } = require('./metarefreshjavascriptcatalogguard.js')

test('MRF block classification', () => {
  for (const v of MRF_BLOCK) assert.equal(MRFClassify(v), MRF_CLASS.BLOCK, v)
})

test('MRF warn classification', () => {
  for (const v of MRF_WARN) assert.equal(MRFClassify(v), MRF_CLASS.WARN, v)
})

test('MRF allow classification', () => {
  for (const v of MRF_ALLOW) assert.equal(MRFClassify(v), MRF_CLASS.ALLOW, v)
})

test('MRF unknown classification', () => {
  assert.equal(MRFClassify('zzz-not-in-catalog-7'), MRF_CLASS.UNKNOWN)
})
