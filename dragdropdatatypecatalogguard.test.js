'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { DDTClassify, DDT_CLASS, DDT_BLOCK, DDT_WARN, DDT_ALLOW } = require('./dragdropdatatypecatalogguard.js')

test('DDT block classification', () => {
  for (const v of DDT_BLOCK) assert.equal(DDTClassify(v), DDT_CLASS.BLOCK, v)
})

test('DDT warn classification', () => {
  for (const v of DDT_WARN) assert.equal(DDTClassify(v), DDT_CLASS.WARN, v)
})

test('DDT allow classification', () => {
  for (const v of DDT_ALLOW) assert.equal(DDTClassify(v), DDT_CLASS.ALLOW, v)
})

test('DDT unknown classification', () => {
  assert.equal(DDTClassify('zzz-not-in-catalog-7'), DDT_CLASS.UNKNOWN)
})
