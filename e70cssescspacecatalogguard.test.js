'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70CESClassify, E70CES_CLASS, E70CES_BLOCK, E70CES_WARN, E70CES_ALLOW } = require('./e70cssescspacecatalogguard.js')

test('E70CES block classification', () => {
  for (const v of E70CES_BLOCK) assert.equal(E70CESClassify(v), E70CES_CLASS.BLOCK, v)
})

test('E70CES warn classification', () => {
  for (const v of E70CES_WARN) assert.equal(E70CESClassify(v), E70CES_CLASS.WARN, v)
})

test('E70CES allow classification', () => {
  for (const v of E70CES_ALLOW) assert.equal(E70CESClassify(v), E70CES_CLASS.ALLOW, v)
})

test('E70CES unknown classification', () => {
  assert.equal(E70CESClassify('zzz-not-in-any-e70-catalog-99'), E70CES_CLASS.UNKNOWN)
})
