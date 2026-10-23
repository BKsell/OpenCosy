'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CSDClassify, CSD_CLASS, CSD_BLOCK, CSD_WARN, CSD_ALLOW } = require('./cspdirectivecatalogguard.js')

test('CSD block classification', () => {
  for (const v of CSD_BLOCK) assert.equal(CSDClassify(v), CSD_CLASS.BLOCK, v)
})

test('CSD warn classification', () => {
  for (const v of CSD_WARN) assert.equal(CSDClassify(v), CSD_CLASS.WARN, v)
})

test('CSD allow classification', () => {
  for (const v of CSD_ALLOW) assert.equal(CSDClassify(v), CSD_CLASS.ALLOW, v)
})

test('CSD unknown classification', () => {
  assert.equal(CSDClassify('zzz-not-in-catalog-7'), CSD_CLASS.UNKNOWN)
})
