'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68PSCClassify, E68PSC_CLASS, E68PSC_BLOCK, E68PSC_WARN, E68PSC_ALLOW } = require('./e68pscharcatalogguard.js')

test('E68PSC block classification', () => {
  for (const v of E68PSC_BLOCK) assert.equal(E68PSCClassify(v), E68PSC_CLASS.BLOCK, v)
})

test('E68PSC warn classification', () => {
  for (const v of E68PSC_WARN) assert.equal(E68PSCClassify(v), E68PSC_CLASS.WARN, v)
})

test('E68PSC allow classification', () => {
  for (const v of E68PSC_ALLOW) assert.equal(E68PSCClassify(v), E68PSC_CLASS.ALLOW, v)
})

test('E68PSC unknown classification', () => {
  assert.equal(E68PSCClassify('zzz-not-in-any-e68-catalog-77'), E68PSC_CLASS.UNKNOWN)
})
