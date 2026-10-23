'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CRAClassify, CRA_CLASS, CRA_BLOCK, CRA_WARN, CRA_ALLOW } = require('./credentialstoreplaintextcatalogguard.js')

test('CRA block classification', () => {
  for (const v of CRA_BLOCK) assert.equal(CRAClassify(v), CRA_CLASS.BLOCK, v)
})

test('CRA warn classification', () => {
  for (const v of CRA_WARN) assert.equal(CRAClassify(v), CRA_CLASS.WARN, v)
})

test('CRA allow classification', () => {
  for (const v of CRA_ALLOW) assert.equal(CRAClassify(v), CRA_CLASS.ALLOW, v)
})

test('CRA unknown classification', () => {
  assert.equal(CRAClassify('zzz-not-in-catalog-7'), CRA_CLASS.UNKNOWN)
})
