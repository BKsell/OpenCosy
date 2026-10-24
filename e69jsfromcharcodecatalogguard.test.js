'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69JFCClassify, E69JFC_CLASS, E69JFC_BLOCK, E69JFC_WARN, E69JFC_ALLOW } = require('./e69jsfromcharcodecatalogguard.js')

test('E69JFC block classification', () => {
  for (const v of E69JFC_BLOCK) assert.equal(E69JFCClassify(v), E69JFC_CLASS.BLOCK, v)
})

test('E69JFC warn classification', () => {
  for (const v of E69JFC_WARN) assert.equal(E69JFCClassify(v), E69JFC_CLASS.WARN, v)
})

test('E69JFC allow classification', () => {
  for (const v of E69JFC_ALLOW) assert.equal(E69JFCClassify(v), E69JFC_CLASS.ALLOW, v)
})

test('E69JFC unknown classification', () => {
  assert.equal(E69JFCClassify('zzz-not-in-any-e69-catalog-88'), E69JFC_CLASS.UNKNOWN)
})
