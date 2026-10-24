'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69VBCClassify, E69VBC_CLASS, E69VBC_BLOCK, E69VBC_WARN, E69VBC_ALLOW } = require('./e69vbchrcatalogguard.js')

test('E69VBC block classification', () => {
  for (const v of E69VBC_BLOCK) assert.equal(E69VBCClassify(v), E69VBC_CLASS.BLOCK, v)
})

test('E69VBC warn classification', () => {
  for (const v of E69VBC_WARN) assert.equal(E69VBCClassify(v), E69VBC_CLASS.WARN, v)
})

test('E69VBC allow classification', () => {
  for (const v of E69VBC_ALLOW) assert.equal(E69VBCClassify(v), E69VBC_CLASS.ALLOW, v)
})

test('E69VBC unknown classification', () => {
  assert.equal(E69VBCClassify('zzz-not-in-any-e69-catalog-88'), E69VBC_CLASS.UNKNOWN)
})
