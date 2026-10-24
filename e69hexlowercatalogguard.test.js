'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69HLOClassify, E69HLO_CLASS, E69HLO_BLOCK, E69HLO_WARN, E69HLO_ALLOW } = require('./e69hexlowercatalogguard.js')

test('E69HLO block classification', () => {
  for (const v of E69HLO_BLOCK) assert.equal(E69HLOClassify(v), E69HLO_CLASS.BLOCK, v)
})

test('E69HLO warn classification', () => {
  for (const v of E69HLO_WARN) assert.equal(E69HLOClassify(v), E69HLO_CLASS.WARN, v)
})

test('E69HLO allow classification', () => {
  for (const v of E69HLO_ALLOW) assert.equal(E69HLOClassify(v), E69HLO_CLASS.ALLOW, v)
})

test('E69HLO unknown classification', () => {
  assert.equal(E69HLOClassify('zzz-not-in-any-e69-catalog-88'), E69HLO_CLASS.UNKNOWN)
})
