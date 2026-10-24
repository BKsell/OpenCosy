'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69MHLClassify, E69MHL_CLASS, E69MHL_BLOCK, E69MHL_WARN, E69MHL_ALLOW } = require('./e69mysqlhexlitcatalogguard.js')

test('E69MHL block classification', () => {
  for (const v of E69MHL_BLOCK) assert.equal(E69MHLClassify(v), E69MHL_CLASS.BLOCK, v)
})

test('E69MHL warn classification', () => {
  for (const v of E69MHL_WARN) assert.equal(E69MHLClassify(v), E69MHL_CLASS.WARN, v)
})

test('E69MHL allow classification', () => {
  for (const v of E69MHL_ALLOW) assert.equal(E69MHLClassify(v), E69MHL_CLASS.ALLOW, v)
})

test('E69MHL unknown classification', () => {
  assert.equal(E69MHLClassify('zzz-not-in-any-e69-catalog-88'), E69MHL_CLASS.UNKNOWN)
})
