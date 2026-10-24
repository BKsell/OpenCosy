'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69JFPClassify, E69JFP_CLASS, E69JFP_BLOCK, E69JFP_WARN, E69JFP_ALLOW } = require('./e69jsfromcodepointcatalogguard.js')

test('E69JFP block classification', () => {
  for (const v of E69JFP_BLOCK) assert.equal(E69JFPClassify(v), E69JFP_CLASS.BLOCK, v)
})

test('E69JFP warn classification', () => {
  for (const v of E69JFP_WARN) assert.equal(E69JFPClassify(v), E69JFP_CLASS.WARN, v)
})

test('E69JFP allow classification', () => {
  for (const v of E69JFP_ALLOW) assert.equal(E69JFPClassify(v), E69JFP_CLASS.ALLOW, v)
})

test('E69JFP unknown classification', () => {
  assert.equal(E69JFPClassify('zzz-not-in-any-e69-catalog-88'), E69JFP_CLASS.UNKNOWN)
})
