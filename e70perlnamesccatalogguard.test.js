'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70PNSClassify, E70PNS_CLASS, E70PNS_BLOCK, E70PNS_WARN, E70PNS_ALLOW } = require('./e70perlnamesccatalogguard.js')

test('E70PNS block classification', () => {
  for (const v of E70PNS_BLOCK) assert.equal(E70PNSClassify(v), E70PNS_CLASS.BLOCK, v)
})

test('E70PNS warn classification', () => {
  for (const v of E70PNS_WARN) assert.equal(E70PNSClassify(v), E70PNS_CLASS.WARN, v)
})

test('E70PNS allow classification', () => {
  for (const v of E70PNS_ALLOW) assert.equal(E70PNSClassify(v), E70PNS_CLASS.ALLOW, v)
})

test('E70PNS unknown classification', () => {
  assert.equal(E70PNSClassify('zzz-not-in-any-e70-catalog-99'), E70PNS_CLASS.UNKNOWN)
})
