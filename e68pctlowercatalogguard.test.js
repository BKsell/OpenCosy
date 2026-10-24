'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68PLBClassify, E68PLB_CLASS, E68PLB_BLOCK, E68PLB_WARN, E68PLB_ALLOW } = require('./e68pctlowercatalogguard.js')

test('E68PLB block classification', () => {
  for (const v of E68PLB_BLOCK) assert.equal(E68PLBClassify(v), E68PLB_CLASS.BLOCK, v)
})

test('E68PLB warn classification', () => {
  for (const v of E68PLB_WARN) assert.equal(E68PLBClassify(v), E68PLB_CLASS.WARN, v)
})

test('E68PLB allow classification', () => {
  for (const v of E68PLB_ALLOW) assert.equal(E68PLBClassify(v), E68PLB_CLASS.ALLOW, v)
})

test('E68PLB unknown classification', () => {
  assert.equal(E68PLBClassify('zzz-not-in-any-e68-catalog-77'), E68PLB_CLASS.UNKNOWN)
})
