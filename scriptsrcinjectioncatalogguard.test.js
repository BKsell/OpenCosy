'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { SRSClassify, SRS_CLASS, SRS_BLOCK, SRS_WARN, SRS_ALLOW } = require('./scriptsrcinjectioncatalogguard.js')

test('SRS block classification', () => {
  for (const v of SRS_BLOCK) assert.equal(SRSClassify(v), SRS_CLASS.BLOCK, v)
})

test('SRS warn classification', () => {
  for (const v of SRS_WARN) assert.equal(SRSClassify(v), SRS_CLASS.WARN, v)
})

test('SRS allow classification', () => {
  for (const v of SRS_ALLOW) assert.equal(SRSClassify(v), SRS_CLASS.ALLOW, v)
})

test('SRS unknown classification', () => {
  assert.equal(SRSClassify('zzz-not-in-catalog-7'), SRS_CLASS.UNKNOWN)
})
