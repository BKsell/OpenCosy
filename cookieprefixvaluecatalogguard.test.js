'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CPVClassify, CPV_CLASS, CPV_BLOCK, CPV_WARN, CPV_ALLOW } = require('./cookieprefixvaluecatalogguard.js')

test('CPV block classification', () => {
  for (const v of CPV_BLOCK) assert.equal(CPVClassify(v), CPV_CLASS.BLOCK, v)
})

test('CPV warn classification', () => {
  for (const v of CPV_WARN) assert.equal(CPVClassify(v), CPV_CLASS.WARN, v)
})

test('CPV allow classification', () => {
  for (const v of CPV_ALLOW) assert.equal(CPVClassify(v), CPV_CLASS.ALLOW, v)
})

test('CPV unknown classification', () => {
  assert.equal(CPVClassify('zzz-not-in-catalog-7'), CPV_CLASS.UNKNOWN)
})
