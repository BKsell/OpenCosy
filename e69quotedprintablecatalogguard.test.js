'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69QPPClassify, E69QPP_CLASS, E69QPP_BLOCK, E69QPP_WARN, E69QPP_ALLOW } = require('./e69quotedprintablecatalogguard.js')

test('E69QPP block classification', () => {
  for (const v of E69QPP_BLOCK) assert.equal(E69QPPClassify(v), E69QPP_CLASS.BLOCK, v)
})

test('E69QPP warn classification', () => {
  for (const v of E69QPP_WARN) assert.equal(E69QPPClassify(v), E69QPP_CLASS.WARN, v)
})

test('E69QPP allow classification', () => {
  for (const v of E69QPP_ALLOW) assert.equal(E69QPPClassify(v), E69QPP_CLASS.ALLOW, v)
})

test('E69QPP unknown classification', () => {
  assert.equal(E69QPPClassify('zzz-not-in-any-e69-catalog-88'), E69QPP_CLASS.UNKNOWN)
})
