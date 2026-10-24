'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70RUBClassify, E70RUB_CLASS, E70RUB_BLOCK, E70RUB_WARN, E70RUB_ALLOW } = require('./e70rustubracecatalogguard.js')

test('E70RUB block classification', () => {
  for (const v of E70RUB_BLOCK) assert.equal(E70RUBClassify(v), E70RUB_CLASS.BLOCK, v)
})

test('E70RUB warn classification', () => {
  for (const v of E70RUB_WARN) assert.equal(E70RUBClassify(v), E70RUB_CLASS.WARN, v)
})

test('E70RUB allow classification', () => {
  for (const v of E70RUB_ALLOW) assert.equal(E70RUBClassify(v), E70RUB_CLASS.ALLOW, v)
})

test('E70RUB unknown classification', () => {
  assert.equal(E70RUBClassify('zzz-not-in-any-e70-catalog-99'), E70RUB_CLASS.UNKNOWN)
})
