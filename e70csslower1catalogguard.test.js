'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70C1LClassify, E70C1L_CLASS, E70C1L_BLOCK, E70C1L_WARN, E70C1L_ALLOW } = require('./e70csslower1catalogguard.js')

test('E70C1L block classification', () => {
  for (const v of E70C1L_BLOCK) assert.equal(E70C1LClassify(v), E70C1L_CLASS.BLOCK, v)
})

test('E70C1L warn classification', () => {
  for (const v of E70C1L_WARN) assert.equal(E70C1LClassify(v), E70C1L_CLASS.WARN, v)
})

test('E70C1L allow classification', () => {
  for (const v of E70C1L_ALLOW) assert.equal(E70C1LClassify(v), E70C1L_CLASS.ALLOW, v)
})

test('E70C1L unknown classification', () => {
  assert.equal(E70C1LClassify('zzz-not-in-any-e70-catalog-99'), E70C1L_CLASS.UNKNOWN)
})
