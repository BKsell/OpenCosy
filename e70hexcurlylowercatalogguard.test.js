'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70HCLClassify, E70HCL_CLASS, E70HCL_BLOCK, E70HCL_WARN, E70HCL_ALLOW } = require('./e70hexcurlylowercatalogguard.js')

test('E70HCL block classification', () => {
  for (const v of E70HCL_BLOCK) assert.equal(E70HCLClassify(v), E70HCL_CLASS.BLOCK, v)
})

test('E70HCL warn classification', () => {
  for (const v of E70HCL_WARN) assert.equal(E70HCLClassify(v), E70HCL_CLASS.WARN, v)
})

test('E70HCL allow classification', () => {
  for (const v of E70HCL_ALLOW) assert.equal(E70HCLClassify(v), E70HCL_CLASS.ALLOW, v)
})

test('E70HCL unknown classification', () => {
  assert.equal(E70HCLClassify('zzz-not-in-any-e70-catalog-99'), E70HCL_CLASS.UNKNOWN)
})
