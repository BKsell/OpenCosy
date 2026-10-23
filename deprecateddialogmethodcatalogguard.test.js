'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { ODGClassify, ODG_CLASS, ODG_BLOCK, ODG_WARN, ODG_ALLOW } = require('./deprecateddialogmethodcatalogguard.js')

test('ODG block classification', () => {
  for (const v of ODG_BLOCK) assert.equal(ODGClassify(v), ODG_CLASS.BLOCK, v)
})

test('ODG warn classification', () => {
  for (const v of ODG_WARN) assert.equal(ODGClassify(v), ODG_CLASS.WARN, v)
})

test('ODG allow classification', () => {
  for (const v of ODG_ALLOW) assert.equal(ODGClassify(v), ODG_CLASS.ALLOW, v)
})

test('ODG unknown classification', () => {
  assert.equal(ODGClassify('zzz-not-in-catalog-7'), ODG_CLASS.UNKNOWN)
})
