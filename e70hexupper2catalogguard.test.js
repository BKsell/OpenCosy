'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70HXUClassify, E70HXU_CLASS, E70HXU_BLOCK, E70HXU_WARN, E70HXU_ALLOW } = require('./e70hexupper2catalogguard.js')

test('E70HXU block classification', () => {
  for (const v of E70HXU_BLOCK) assert.equal(E70HXUClassify(v), E70HXU_CLASS.BLOCK, v)
})

test('E70HXU warn classification', () => {
  for (const v of E70HXU_WARN) assert.equal(E70HXUClassify(v), E70HXU_CLASS.WARN, v)
})

test('E70HXU allow classification', () => {
  for (const v of E70HXU_ALLOW) assert.equal(E70HXUClassify(v), E70HXU_CLASS.ALLOW, v)
})

test('E70HXU unknown classification', () => {
  assert.equal(E70HXUClassify('zzz-not-in-any-e70-catalog-99'), E70HXU_CLASS.UNKNOWN)
})
