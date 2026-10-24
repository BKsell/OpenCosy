'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70C5LClassify, E70C5L_CLASS, E70C5L_BLOCK, E70C5L_WARN, E70C5L_ALLOW } = require('./e70cssfivelowercatalogguard.js')

test('E70C5L block classification', () => {
  for (const v of E70C5L_BLOCK) assert.equal(E70C5LClassify(v), E70C5L_CLASS.BLOCK, v)
})

test('E70C5L warn classification', () => {
  for (const v of E70C5L_WARN) assert.equal(E70C5LClassify(v), E70C5L_CLASS.WARN, v)
})

test('E70C5L allow classification', () => {
  for (const v of E70C5L_ALLOW) assert.equal(E70C5LClassify(v), E70C5L_CLASS.ALLOW, v)
})

test('E70C5L unknown classification', () => {
  assert.equal(E70C5LClassify('zzz-not-in-any-e70-catalog-99'), E70C5L_CLASS.UNKNOWN)
})
