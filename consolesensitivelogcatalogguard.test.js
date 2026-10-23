'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CSLClassify, CSL_CLASS, CSL_BLOCK, CSL_WARN, CSL_ALLOW } = require('./consolesensitivelogcatalogguard.js')

test('CSL block classification', () => {
  for (const v of CSL_BLOCK) assert.equal(CSLClassify(v), CSL_CLASS.BLOCK, v)
})

test('CSL warn classification', () => {
  for (const v of CSL_WARN) assert.equal(CSLClassify(v), CSL_CLASS.WARN, v)
})

test('CSL allow classification', () => {
  for (const v of CSL_ALLOW) assert.equal(CSLClassify(v), CSL_CLASS.ALLOW, v)
})

test('CSL unknown classification', () => {
  assert.equal(CSLClassify('zzz-not-in-catalog-7'), CSL_CLASS.UNKNOWN)
})
