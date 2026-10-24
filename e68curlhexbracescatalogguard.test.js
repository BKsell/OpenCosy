'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68CHBClassify, E68CHB_CLASS, E68CHB_BLOCK, E68CHB_WARN, E68CHB_ALLOW } = require('./e68curlhexbracescatalogguard.js')

test('E68CHB block classification', () => {
  for (const v of E68CHB_BLOCK) assert.equal(E68CHBClassify(v), E68CHB_CLASS.BLOCK, v)
})

test('E68CHB warn classification', () => {
  for (const v of E68CHB_WARN) assert.equal(E68CHBClassify(v), E68CHB_CLASS.WARN, v)
})

test('E68CHB allow classification', () => {
  for (const v of E68CHB_ALLOW) assert.equal(E68CHBClassify(v), E68CHB_CLASS.ALLOW, v)
})

test('E68CHB unknown classification', () => {
  assert.equal(E68CHBClassify('zzz-not-in-any-e68-catalog-77'), E68CHB_CLASS.UNKNOWN)
})
