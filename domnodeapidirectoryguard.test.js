'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { DNAClassify, DNA_CLASS, DNA_BLOCK, DNA_WARN, DNA_ALLOW } = require('./domnodeapidirectoryguard.js')

test('DNA block classification', () => {
  for (const v of DNA_BLOCK) assert.equal(DNAClassify(v), DNA_CLASS.BLOCK, v)
})

test('DNA warn classification', () => {
  for (const v of DNA_WARN) assert.equal(DNAClassify(v), DNA_CLASS.WARN, v)
})

test('DNA allow classification', () => {
  for (const v of DNA_ALLOW) assert.equal(DNAClassify(v), DNA_CLASS.ALLOW, v)
})

test('DNA unknown classification', () => {
  assert.equal(DNAClassify('zzz-not-in-catalog-7'), DNA_CLASS.UNKNOWN)
})
