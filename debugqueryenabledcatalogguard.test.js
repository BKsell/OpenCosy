'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { DBGClassify, DBG_CLASS, DBG_BLOCK, DBG_WARN, DBG_ALLOW } = require('./debugqueryenabledcatalogguard.js')

test('DBG block classification', () => {
  for (const v of DBG_BLOCK) assert.equal(DBGClassify(v), DBG_CLASS.BLOCK, v)
})

test('DBG warn classification', () => {
  for (const v of DBG_WARN) assert.equal(DBGClassify(v), DBG_CLASS.WARN, v)
})

test('DBG allow classification', () => {
  for (const v of DBG_ALLOW) assert.equal(DBGClassify(v), DBG_CLASS.ALLOW, v)
})

test('DBG unknown classification', () => {
  assert.equal(DBGClassify('zzz-not-in-catalog-7'), DBG_CLASS.UNKNOWN)
})
