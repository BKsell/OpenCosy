'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69PUBClassify, E69PUB_CLASS, E69PUB_BLOCK, E69PUB_WARN, E69PUB_ALLOW } = require('./e69pctuppercatalogguard.js')

test('E69PUB block classification', () => {
  for (const v of E69PUB_BLOCK) assert.equal(E69PUBClassify(v), E69PUB_CLASS.BLOCK, v)
})

test('E69PUB warn classification', () => {
  for (const v of E69PUB_WARN) assert.equal(E69PUBClassify(v), E69PUB_CLASS.WARN, v)
})

test('E69PUB allow classification', () => {
  for (const v of E69PUB_ALLOW) assert.equal(E69PUBClassify(v), E69PUB_CLASS.ALLOW, v)
})

test('E69PUB unknown classification', () => {
  assert.equal(E69PUBClassify('zzz-not-in-any-e69-catalog-88'), E69PUB_CLASS.UNKNOWN)
})
