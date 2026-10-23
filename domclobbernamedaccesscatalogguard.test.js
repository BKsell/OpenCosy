'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { DBCClassify, DBC_CLASS, DBC_BLOCK, DBC_WARN, DBC_ALLOW } = require('./domclobbernamedaccesscatalogguard.js')

test('DBC block classification', () => {
  for (const v of DBC_BLOCK) assert.equal(DBCClassify(v), DBC_CLASS.BLOCK, v)
})

test('DBC warn classification', () => {
  for (const v of DBC_WARN) assert.equal(DBCClassify(v), DBC_CLASS.WARN, v)
})

test('DBC allow classification', () => {
  for (const v of DBC_ALLOW) assert.equal(DBCClassify(v), DBC_CLASS.ALLOW, v)
})

test('DBC unknown classification', () => {
  assert.equal(DBCClassify('zzz-not-in-catalog-7'), DBC_CLASS.UNKNOWN)
})
