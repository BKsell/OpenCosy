'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69CHUClassify, E69CHU_CLASS, E69CHU_BLOCK, E69CHU_WARN, E69CHU_ALLOW } = require('./e69curlhexuppercatalogguard.js')

test('E69CHU block classification', () => {
  for (const v of E69CHU_BLOCK) assert.equal(E69CHUClassify(v), E69CHU_CLASS.BLOCK, v)
})

test('E69CHU warn classification', () => {
  for (const v of E69CHU_WARN) assert.equal(E69CHUClassify(v), E69CHU_CLASS.WARN, v)
})

test('E69CHU allow classification', () => {
  for (const v of E69CHU_ALLOW) assert.equal(E69CHUClassify(v), E69CHU_CLASS.ALLOW, v)
})

test('E69CHU unknown classification', () => {
  assert.equal(E69CHUClassify('zzz-not-in-any-e69-catalog-88'), E69CHU_CLASS.UNKNOWN)
})
