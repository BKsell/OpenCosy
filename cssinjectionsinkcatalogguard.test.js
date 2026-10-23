'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CSSIClassify, CSSI_CLASS, CSSI_BLOCK, CSSI_WARN, CSSI_ALLOW } = require('./cssinjectionsinkcatalogguard.js')

test('CSSI block classification', () => {
  for (const v of CSSI_BLOCK) assert.equal(CSSIClassify(v), CSSI_CLASS.BLOCK, v)
})

test('CSSI warn classification', () => {
  for (const v of CSSI_WARN) assert.equal(CSSIClassify(v), CSSI_CLASS.WARN, v)
})

test('CSSI allow classification', () => {
  for (const v of CSSI_ALLOW) assert.equal(CSSIClassify(v), CSSI_CLASS.ALLOW, v)
})

test('CSSI unknown classification', () => {
  assert.equal(CSSIClassify('zzz-not-in-catalog-7'), CSSI_CLASS.UNKNOWN)
})
