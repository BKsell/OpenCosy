'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70U8LClassify, E70U8L_CLASS, E70U8L_BLOCK, E70U8L_WARN, E70U8L_ALLOW } = require('./e70utf8latin1pctcatalogguard.js')

test('E70U8L block classification', () => {
  for (const v of E70U8L_BLOCK) assert.equal(E70U8LClassify(v), E70U8L_CLASS.BLOCK, v)
})

test('E70U8L warn classification', () => {
  for (const v of E70U8L_WARN) assert.equal(E70U8LClassify(v), E70U8L_CLASS.WARN, v)
})

test('E70U8L allow classification', () => {
  for (const v of E70U8L_ALLOW) assert.equal(E70U8LClassify(v), E70U8L_CLASS.ALLOW, v)
})

test('E70U8L unknown classification', () => {
  assert.equal(E70U8LClassify('zzz-not-in-any-e70-catalog-99'), E70U8L_CLASS.UNKNOWN)
})
