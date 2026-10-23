'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CPRClassify, CPR_CLASS, CPR_BLOCK, CPR_WARN, CPR_ALLOW } = require('./cspreportkeycatalogguard.js')

test('CPR block classification', () => {
  for (const v of CPR_BLOCK) assert.equal(CPRClassify(v), CPR_CLASS.BLOCK, v)
})

test('CPR warn classification', () => {
  for (const v of CPR_WARN) assert.equal(CPRClassify(v), CPR_CLASS.WARN, v)
})

test('CPR allow classification', () => {
  for (const v of CPR_ALLOW) assert.equal(CPRClassify(v), CPR_CLASS.ALLOW, v)
})

test('CPR unknown classification', () => {
  assert.equal(CPRClassify('zzz-not-in-catalog-7'), CPR_CLASS.UNKNOWN)
})
