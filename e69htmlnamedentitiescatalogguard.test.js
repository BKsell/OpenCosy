'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69HNEClassify, E69HNE_CLASS, E69HNE_BLOCK, E69HNE_WARN, E69HNE_ALLOW } = require('./e69htmlnamedentitiescatalogguard.js')

test('E69HNE block classification', () => {
  for (const v of E69HNE_BLOCK) assert.equal(E69HNEClassify(v), E69HNE_CLASS.BLOCK, v)
})

test('E69HNE warn classification', () => {
  for (const v of E69HNE_WARN) assert.equal(E69HNEClassify(v), E69HNE_CLASS.WARN, v)
})

test('E69HNE allow classification', () => {
  for (const v of E69HNE_ALLOW) assert.equal(E69HNEClassify(v), E69HNE_CLASS.ALLOW, v)
})

test('E69HNE unknown classification', () => {
  assert.equal(E69HNEClassify('zzz-not-in-any-e69-catalog-88'), E69HNE_CLASS.UNKNOWN)
})
