'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68BGUClassify, E68BGU_CLASS, E68BGU_BLOCK, E68BGU_WARN, E68BGU_ALLOW } = require('./e68bigu32uppercatalogguard.js')

test('E68BGU block classification', () => {
  for (const v of E68BGU_BLOCK) assert.equal(E68BGUClassify(v), E68BGU_CLASS.BLOCK, v)
})

test('E68BGU warn classification', () => {
  for (const v of E68BGU_WARN) assert.equal(E68BGUClassify(v), E68BGU_CLASS.WARN, v)
})

test('E68BGU allow classification', () => {
  for (const v of E68BGU_ALLOW) assert.equal(E68BGUClassify(v), E68BGU_CLASS.ALLOW, v)
})

test('E68BGU unknown classification', () => {
  assert.equal(E68BGUClassify('zzz-not-in-any-e68-catalog-77'), E68BGU_CLASS.UNKNOWN)
})
