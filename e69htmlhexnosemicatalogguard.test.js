'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69HNSClassify, E69HNS_CLASS, E69HNS_BLOCK, E69HNS_WARN, E69HNS_ALLOW } = require('./e69htmlhexnosemicatalogguard.js')

test('E69HNS block classification', () => {
  for (const v of E69HNS_BLOCK) assert.equal(E69HNSClassify(v), E69HNS_CLASS.BLOCK, v)
})

test('E69HNS warn classification', () => {
  for (const v of E69HNS_WARN) assert.equal(E69HNSClassify(v), E69HNS_CLASS.WARN, v)
})

test('E69HNS allow classification', () => {
  for (const v of E69HNS_ALLOW) assert.equal(E69HNSClassify(v), E69HNS_CLASS.ALLOW, v)
})

test('E69HNS unknown classification', () => {
  assert.equal(E69HNSClassify('zzz-not-in-any-e69-catalog-88'), E69HNS_CLASS.UNKNOWN)
})
