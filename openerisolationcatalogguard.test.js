'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { OPIClassify, OPI_CLASS, OPI_BLOCK, OPI_WARN, OPI_ALLOW } = require('./openerisolationcatalogguard.js')

test('OPI block classification', () => {
  for (const v of OPI_BLOCK) assert.equal(OPIClassify(v), OPI_CLASS.BLOCK, v)
})

test('OPI warn classification', () => {
  for (const v of OPI_WARN) assert.equal(OPIClassify(v), OPI_CLASS.WARN, v)
})

test('OPI allow classification', () => {
  for (const v of OPI_ALLOW) assert.equal(OPIClassify(v), OPI_CLASS.ALLOW, v)
})

test('OPI unknown classification', () => {
  assert.equal(OPIClassify('zzz-not-in-catalog-7'), OPI_CLASS.UNKNOWN)
})
