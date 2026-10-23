'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { FSOClassify, FSO_CLASS, FSO_BLOCK, FSO_WARN, FSO_ALLOW } = require('./framecrossnavigationcatalogguard.js')

test('FSO block classification', () => {
  for (const v of FSO_BLOCK) assert.equal(FSOClassify(v), FSO_CLASS.BLOCK, v)
})

test('FSO warn classification', () => {
  for (const v of FSO_WARN) assert.equal(FSOClassify(v), FSO_CLASS.WARN, v)
})

test('FSO allow classification', () => {
  for (const v of FSO_ALLOW) assert.equal(FSOClassify(v), FSO_CLASS.ALLOW, v)
})

test('FSO unknown classification', () => {
  assert.equal(FSOClassify('zzz-not-in-catalog-7'), FSO_CLASS.UNKNOWN)
})
