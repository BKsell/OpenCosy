'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { SPWClassify, SPW_CLASS, SPW_BLOCK, SPW_WARN, SPW_ALLOW } = require('./serialportwritecatalogguard.js')

test('SPW block classification', () => {
  for (const v of SPW_BLOCK) assert.equal(SPWClassify(v), SPW_CLASS.BLOCK, v)
})

test('SPW warn classification', () => {
  for (const v of SPW_WARN) assert.equal(SPWClassify(v), SPW_CLASS.WARN, v)
})

test('SPW allow classification', () => {
  for (const v of SPW_ALLOW) assert.equal(SPWClassify(v), SPW_CLASS.ALLOW, v)
})

test('SPW unknown classification', () => {
  assert.equal(SPWClassify('zzz-not-in-catalog-7'), SPW_CLASS.UNKNOWN)
})
