'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69XLFClassify, E69XLF_CLASS, E69XLF_BLOCK, E69XLF_WARN, E69XLF_ALLOW } = require('./e69excelcharformulacatalogguard.js')

test('E69XLF block classification', () => {
  for (const v of E69XLF_BLOCK) assert.equal(E69XLFClassify(v), E69XLF_CLASS.BLOCK, v)
})

test('E69XLF warn classification', () => {
  for (const v of E69XLF_WARN) assert.equal(E69XLFClassify(v), E69XLF_CLASS.WARN, v)
})

test('E69XLF allow classification', () => {
  for (const v of E69XLF_ALLOW) assert.equal(E69XLFClassify(v), E69XLF_CLASS.ALLOW, v)
})

test('E69XLF unknown classification', () => {
  assert.equal(E69XLFClassify('zzz-not-in-any-e69-catalog-88'), E69XLF_CLASS.UNKNOWN)
})
