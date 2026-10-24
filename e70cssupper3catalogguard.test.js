'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70C3UClassify, E70C3U_CLASS, E70C3U_BLOCK, E70C3U_WARN, E70C3U_ALLOW } = require('./e70cssupper3catalogguard.js')

test('E70C3U block classification', () => {
  for (const v of E70C3U_BLOCK) assert.equal(E70C3UClassify(v), E70C3U_CLASS.BLOCK, v)
})

test('E70C3U warn classification', () => {
  for (const v of E70C3U_WARN) assert.equal(E70C3UClassify(v), E70C3U_CLASS.WARN, v)
})

test('E70C3U allow classification', () => {
  for (const v of E70C3U_ALLOW) assert.equal(E70C3UClassify(v), E70C3U_CLASS.ALLOW, v)
})

test('E70C3U unknown classification', () => {
  assert.equal(E70C3UClassify('zzz-not-in-any-e70-catalog-99'), E70C3U_CLASS.UNKNOWN)
})
