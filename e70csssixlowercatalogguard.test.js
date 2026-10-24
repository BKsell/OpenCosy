'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70C6LClassify, E70C6L_CLASS, E70C6L_BLOCK, E70C6L_WARN, E70C6L_ALLOW } = require('./e70csssixlowercatalogguard.js')

test('E70C6L block classification', () => {
  for (const v of E70C6L_BLOCK) assert.equal(E70C6LClassify(v), E70C6L_CLASS.BLOCK, v)
})

test('E70C6L warn classification', () => {
  for (const v of E70C6L_WARN) assert.equal(E70C6LClassify(v), E70C6L_CLASS.WARN, v)
})

test('E70C6L allow classification', () => {
  for (const v of E70C6L_ALLOW) assert.equal(E70C6LClassify(v), E70C6L_CLASS.ALLOW, v)
})

test('E70C6L unknown classification', () => {
  assert.equal(E70C6LClassify('zzz-not-in-any-e70-catalog-99'), E70C6L_CLASS.UNKNOWN)
})
