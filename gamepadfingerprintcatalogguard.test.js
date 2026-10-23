'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { GPDClassify, GPD_CLASS, GPD_BLOCK, GPD_WARN, GPD_ALLOW } = require('./gamepadfingerprintcatalogguard.js')

test('GPD block classification', () => {
  for (const v of GPD_BLOCK) assert.equal(GPDClassify(v), GPD_CLASS.BLOCK, v)
})

test('GPD warn classification', () => {
  for (const v of GPD_WARN) assert.equal(GPDClassify(v), GPD_CLASS.WARN, v)
})

test('GPD allow classification', () => {
  for (const v of GPD_ALLOW) assert.equal(GPDClassify(v), GPD_CLASS.ALLOW, v)
})

test('GPD unknown classification', () => {
  assert.equal(GPDClassify('zzz-not-in-catalog-7'), GPD_CLASS.UNKNOWN)
})
