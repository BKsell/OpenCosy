'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { AFPClassify, AFP_CLASS, AFP_BLOCK, AFP_WARN, AFP_ALLOW } = require('./audiosignalfingerprintcatalogguard.js')

test('AFP block classification', () => {
  for (const v of AFP_BLOCK) assert.equal(AFPClassify(v), AFP_CLASS.BLOCK, v)
})

test('AFP warn classification', () => {
  for (const v of AFP_WARN) assert.equal(AFPClassify(v), AFP_CLASS.WARN, v)
})

test('AFP allow classification', () => {
  for (const v of AFP_ALLOW) assert.equal(AFPClassify(v), AFP_CLASS.ALLOW, v)
})

test('AFP unknown classification', () => {
  assert.equal(AFPClassify('zzz-not-in-catalog-7'), AFP_CLASS.UNKNOWN)
})
