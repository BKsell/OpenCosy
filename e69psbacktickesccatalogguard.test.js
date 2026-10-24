'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69PBTClassify, E69PBT_CLASS, E69PBT_BLOCK, E69PBT_WARN, E69PBT_ALLOW } = require('./e69psbacktickesccatalogguard.js')

test('E69PBT block classification', () => {
  for (const v of E69PBT_BLOCK) assert.equal(E69PBTClassify(v), E69PBT_CLASS.BLOCK, v)
})

test('E69PBT warn classification', () => {
  for (const v of E69PBT_WARN) assert.equal(E69PBTClassify(v), E69PBT_CLASS.WARN, v)
})

test('E69PBT allow classification', () => {
  for (const v of E69PBT_ALLOW) assert.equal(E69PBTClassify(v), E69PBT_CLASS.ALLOW, v)
})

test('E69PBT unknown classification', () => {
  assert.equal(E69PBTClassify('zzz-not-in-any-e69-catalog-88'), E69PBT_CLASS.UNKNOWN)
})
