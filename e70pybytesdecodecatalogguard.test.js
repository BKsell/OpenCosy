'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70PBDClassify, E70PBD_CLASS, E70PBD_BLOCK, E70PBD_WARN, E70PBD_ALLOW } = require('./e70pybytesdecodecatalogguard.js')

test('E70PBD block classification', () => {
  for (const v of E70PBD_BLOCK) assert.equal(E70PBDClassify(v), E70PBD_CLASS.BLOCK, v)
})

test('E70PBD warn classification', () => {
  for (const v of E70PBD_WARN) assert.equal(E70PBDClassify(v), E70PBD_CLASS.WARN, v)
})

test('E70PBD allow classification', () => {
  for (const v of E70PBD_ALLOW) assert.equal(E70PBDClassify(v), E70PBD_CLASS.ALLOW, v)
})

test('E70PBD unknown classification', () => {
  assert.equal(E70PBDClassify('zzz-not-in-any-e70-catalog-99'), E70PBD_CLASS.UNKNOWN)
})
