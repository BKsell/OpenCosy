'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E68SQCClassify, E68SQC_CLASS, E68SQC_BLOCK, E68SQC_WARN, E68SQC_ALLOW } = require('./e68sqlcharcatalogguard.js')

test('E68SQC block classification', () => {
  for (const v of E68SQC_BLOCK) assert.equal(E68SQCClassify(v), E68SQC_CLASS.BLOCK, v)
})

test('E68SQC warn classification', () => {
  for (const v of E68SQC_WARN) assert.equal(E68SQCClassify(v), E68SQC_CLASS.WARN, v)
})

test('E68SQC allow classification', () => {
  for (const v of E68SQC_ALLOW) assert.equal(E68SQCClassify(v), E68SQC_CLASS.ALLOW, v)
})

test('E68SQC unknown classification', () => {
  assert.equal(E68SQCClassify('zzz-not-in-any-e68-catalog-77'), E68SQC_CLASS.UNKNOWN)
})
