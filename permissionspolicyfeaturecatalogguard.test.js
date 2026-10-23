'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { PPFClassify, PPF_CLASS, PPF_BLOCK, PPF_WARN, PPF_ALLOW } = require('./permissionspolicyfeaturecatalogguard.js')

test('PPF block classification', () => {
  for (const v of PPF_BLOCK) assert.equal(PPFClassify(v), PPF_CLASS.BLOCK, v)
})

test('PPF warn classification', () => {
  for (const v of PPF_WARN) assert.equal(PPFClassify(v), PPF_CLASS.WARN, v)
})

test('PPF allow classification', () => {
  for (const v of PPF_ALLOW) assert.equal(PPFClassify(v), PPF_CLASS.ALLOW, v)
})

test('PPF unknown classification', () => {
  assert.equal(PPFClassify('zzz-not-in-catalog-7'), PPF_CLASS.UNKNOWN)
})
