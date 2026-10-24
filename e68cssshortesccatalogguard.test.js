'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68CSEClassify, E68CSE_CLASS, E68CSE_BLOCK, E68CSE_WARN, E68CSE_ALLOW } = require('./e68cssshortesccatalogguard.js')

test('E68CSE block classification', () => {
  for (const v of E68CSE_BLOCK) assert.equal(E68CSEClassify(v), E68CSE_CLASS.BLOCK, v)
})

test('E68CSE warn classification', () => {
  for (const v of E68CSE_WARN) assert.equal(E68CSEClassify(v), E68CSE_CLASS.WARN, v)
})

test('E68CSE allow classification', () => {
  for (const v of E68CSE_ALLOW) assert.equal(E68CSEClassify(v), E68CSE_CLASS.ALLOW, v)
})

test('E68CSE unknown classification', () => {
  assert.equal(E68CSEClassify('zzz-not-in-any-e68-catalog-77'), E68CSE_CLASS.UNKNOWN)
})
