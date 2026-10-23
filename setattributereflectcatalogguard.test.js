'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { SASClassify, SAS_CLASS, SAS_BLOCK, SAS_WARN, SAS_ALLOW } = require('./setattributereflectcatalogguard.js')

test('SAS block classification', () => {
  for (const v of SAS_BLOCK) assert.equal(SASClassify(v), SAS_CLASS.BLOCK, v)
})

test('SAS warn classification', () => {
  for (const v of SAS_WARN) assert.equal(SASClassify(v), SAS_CLASS.WARN, v)
})

test('SAS allow classification', () => {
  for (const v of SAS_ALLOW) assert.equal(SASClassify(v), SAS_CLASS.ALLOW, v)
})

test('SAS unknown classification', () => {
  assert.equal(SASClassify('zzz-not-in-catalog-7'), SAS_CLASS.UNKNOWN)
})
